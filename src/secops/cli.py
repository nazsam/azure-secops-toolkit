"""Command line entry point: ``secops <command>``."""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from . import ioc, mitre, rules, vuln


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="secops", description="Azure SecOps toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="validate Sentinel analytics rules")
    v.add_argument("--rules", default="detections")

    b = sub.add_parser("build-arm", help="compile rules to an ARM template")
    b.add_argument("--rules", default="detections")
    b.add_argument("--out", default="build/analytics-rules.json")

    c = sub.add_parser("coverage", help="MITRE ATT&CK coverage report (markdown)")
    c.add_argument("--rules", default="detections")
    c.add_argument("--hunting", default="hunting")
    c.add_argument("--out", default="docs/mitre-coverage.md")

    i = sub.add_parser("ioc", help="extract IOCs from text into a Sentinel watchlist CSV")
    i.add_argument("file", help="text file, or - for stdin")
    i.add_argument("--source", default="manual")
    i.add_argument("--include-private", action="store_true")

    vu = sub.add_parser("vuln", help="prioritise a vulnerability export and assign SLAs")
    vu.add_argument("file")
    vu.add_argument("--out", default="build/prioritised-vulnerabilities.csv")
    vu.add_argument("--today", help="YYYY-MM-DD, defaults to today")

    a = p.parse_args(argv)

    if a.cmd == "validate":
        loaded = rules.load_rules(a.rules)
        bad = 0
        for r in loaded:
            status = "ok " if not r.errors else "ERR"
            print(f"[{status}] {r.path.name}: {r.name}")
            for e in r.errors:
                print(f"       - {e}")
            bad += bool(r.errors)
        print(f"{len(loaded) - bad}/{len(loaded)} rules valid")
        return 1 if bad or not loaded else 0

    if a.cmd == "build-arm":
        out = rules.write_arm(rules.load_rules(a.rules), a.out)
        print(f"wrote {out}")
        return 0

    if a.cmd == "coverage":
        md = mitre.markdown(mitre.coverage(a.rules, a.hunting))
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(md, encoding="utf-8")
        print(md.strip().splitlines()[-1])
        return 0

    if a.cmd == "ioc":
        text = sys.stdin.read() if a.file == "-" else Path(a.file).read_text(encoding="utf-8")
        sys.stdout.write(ioc.to_watchlist_csv(ioc.extract(text, a.include_private), a.source))
        return 0

    if a.cmd == "vuln":
        today = date.fromisoformat(a.today) if a.today else None
        findings = vuln.prioritise(vuln.load(a.file), today)
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        vuln.write_csv(findings, a.out)
        print(f"wrote {a.out}: {vuln.summary(findings)}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
