// Syntax-checks every KQL query in the repo with Microsoft's official Kusto parser.
// Usage: dotnet run --project tools/KqlValidator -- <repo-root>
// Exit code 1 if any query has a syntax error.

using System.Text;
using Kusto.Language;

var root = args.Length > 0 ? args[0] : ".";
var queries = new List<(string File, string Query)>();

foreach (var path in Directory.GetFiles(Path.Combine(root, "detections"), "*.yaml").OrderBy(p => p))
{
    queries.Add((Path.GetFileName(path), ExtractYamlBlock(File.ReadAllLines(path), "query")));
}
foreach (var path in Directory.GetFiles(Path.Combine(root, "hunting"), "*.kql").OrderBy(p => p))
{
    queries.Add((Path.GetFileName(path), File.ReadAllText(path)));
}

var failures = 0;
foreach (var (file, query) in queries)
{
    if (string.IsNullOrWhiteSpace(query))
    {
        Console.WriteLine($"[ERR] {file}: no query found");
        failures++;
        continue;
    }
    var code = KustoCode.Parse(query);
    var errors = code.GetDiagnostics().Where(d => d.Severity == "Error").ToList();
    if (errors.Count == 0)
    {
        Console.WriteLine($"[ok ] {file}");
        continue;
    }
    failures++;
    Console.WriteLine($"[ERR] {file}");
    foreach (var d in errors)
    {
        var (line, col) = Position(query, d.Start);
        Console.WriteLine($"       line {line}, col {col}: {d.Message}");
    }
}

Console.WriteLine($"{queries.Count - failures}/{queries.Count} queries parsed cleanly");
return failures == 0 ? 0 : 1;

// Reads a YAML literal block scalar such as "query: |" followed by indented lines.
static string ExtractYamlBlock(string[] lines, string key)
{
    var sb = new StringBuilder();
    var inBlock = false;
    var indent = -1;
    foreach (var raw in lines)
    {
        if (!inBlock)
        {
            if (raw.TrimEnd() == $"{key}: |" || raw.TrimEnd() == $"{key}: |-") inBlock = true;
            continue;
        }
        if (raw.Trim().Length == 0) { sb.AppendLine(); continue; }
        var lead = raw.Length - raw.TrimStart().Length;
        if (indent < 0) indent = lead;
        if (lead < indent || lead == 0) break;
        sb.AppendLine(raw[indent..]);
    }
    return sb.ToString();
}

static (int Line, int Col) Position(string text, int offset)
{
    var line = 1;
    var col = 1;
    for (var i = 0; i < Math.Min(offset, text.Length); i++)
    {
        if (text[i] == '\n') { line++; col = 1; } else { col++; }
    }
    return (line, col);
}
