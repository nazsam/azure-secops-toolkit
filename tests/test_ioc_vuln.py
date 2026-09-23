from datetime import date
from pathlib import Path

from secops import ioc, vuln
from secops.cli import main

FIX = Path(__file__).parent / "fixtures"


def test_extracts_defanged_iocs():
    found = {(i.type, i.value) for i in ioc.extract((FIX / "report.txt").read_text())}
    assert ("url", "https://login-micros0ft.com/auth?id=42") in found
    assert ("domain", "cdn-update.net") in found
    assert ("ipv4", "185.220.101.45") in found
    assert ("ipv4", "10.0.0.5") not in found  # private skipped by default
    assert ("sha256", "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea") in found
    assert ("email", "billing@contoso-invoices.com") in found
    assert not any(v == "notes.txt" for _, v in found)  # file names are not domains
    assert not any(t == "domain" and v == "login-micros0ft.com" for t, v in found)  # part of the URL


def test_defang_and_watchlist():
    assert ioc.defang("https://evil.com") == "hxxps://evil[.]com"
    csv_text = ioc.to_watchlist_csv([ioc.Indicator("ipv4", "1.2.3.4")], source="TIP")
    assert csv_text.splitlines() == ["Indicator,Type,Source", "1.2.3.4,ipv4,TIP"]


def test_vulnerability_prioritisation():
    findings = vuln.prioritise(vuln.load(FIX / "vulns.csv"), today=date(2026, 9, 23))
    top = findings[0]
    assert top.cve in ("CVE-2024-3400", "CVE-2023-4966") and top.priority == "P1"
    by_cve = {f.cve: f for f in findings}
    assert by_cve["CVE-2024-3400"].overdue  # P1 found 1 Sep, 7 day SLA
    assert by_cve["CVE-2023-44487"].priority in ("P3", "P4")
    # internet exposed with no exploit ranks below exploited-and-exposed
    assert by_cve["CVE-2022-22965"].score < by_cve["CVE-2023-4966"].score
    s = vuln.summary(findings)
    assert sum(s[p] for p in ("P1", "P2", "P3", "P4")) == 5


def test_cli_ioc_and_vuln(tmp_path, capsys):
    assert main(["ioc", str(FIX / "report.txt"), "--source", "report"]) == 0
    assert "185.220.101.45,ipv4,report" in capsys.readouterr().out
    out = tmp_path / "v.csv"
    assert main(["vuln", str(FIX / "vulns.csv"), "--out", str(out), "--today", "2026-09-23"]) == 0
    assert out.read_text().splitlines()[1].startswith("P1")
