"""Risk-based vulnerability prioritisation for Defender for Cloud / Defender Vulnerability Management exports.

CVSS alone ranks thousands of findings as "critical". This scores each finding on what actually
drives risk (exploit available, internet exposure, asset criticality, age) and assigns a
remediation SLA, so teams fix the right things first.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

SLA_DAYS = {"P1": 7, "P2": 14, "P3": 30, "P4": 90}
CRITICALITY = {"high": 1.0, "medium": 0.6, "low": 0.3}


@dataclass
class Finding:
    cve: str
    asset: str
    cvss: float
    exploit_available: bool
    internet_exposed: bool
    asset_criticality: str
    first_seen: date
    score: float = 0.0
    priority: str = "P4"
    due: date | None = None
    overdue: bool = False


def _bool(v: str) -> bool:
    return str(v).strip().lower() in ("true", "yes", "1", "y")


def _date(v: str) -> date:
    return datetime.fromisoformat(str(v).strip()[:10]).date()


def score(f: Finding) -> float:
    """0-100 risk score."""
    s = f.cvss * 5  # up to 50
    s += 25 if f.exploit_available else 0
    s += 15 if f.internet_exposed else 0
    s *= 0.5 + 0.5 * CRITICALITY.get(f.asset_criticality.lower(), 0.6)
    s += 10 if f.exploit_available and f.internet_exposed else 0
    return round(min(s, 100.0), 1)


def priority(s: float) -> str:
    return "P1" if s >= 75 else "P2" if s >= 55 else "P3" if s >= 35 else "P4"


def load(path: str | Path) -> list[Finding]:
    rows = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for r in csv.DictReader(fh):
            rows.append(
                Finding(
                    cve=r["cveId"].strip(),
                    asset=r["assetName"].strip(),
                    cvss=float(r.get("cvssScore") or 0),
                    exploit_available=_bool(r.get("exploitAvailable", "")),
                    internet_exposed=_bool(r.get("internetExposed", "")),
                    asset_criticality=(r.get("assetCriticality") or "medium").strip(),
                    first_seen=_date(r["firstSeen"]),
                )
            )
    return rows


def prioritise(findings: list[Finding], today: date | None = None) -> list[Finding]:
    today = today or date.today()
    for f in findings:
        f.score = score(f)
        f.priority = priority(f.score)
        f.due = date.fromordinal(f.first_seen.toordinal() + SLA_DAYS[f.priority])
        f.overdue = today > f.due
    return sorted(findings, key=lambda f: (-f.score, f.first_seen))


def summary(findings: list[Finding]) -> dict[str, int]:
    out = {p: 0 for p in SLA_DAYS}
    for f in findings:
        out[f.priority] += 1
    out["overdue"] = sum(f.overdue for f in findings)
    return out


def write_csv(findings: list[Finding], path: str | Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "priority",
                "score",
                "cve",
                "asset",
                "cvss",
                "exploitAvailable",
                "internetExposed",
                "assetCriticality",
                "firstSeen",
                "due",
                "overdue",
            ]
        )
        for f in findings:
            w.writerow(
                [
                    f.priority,
                    f.score,
                    f.cve,
                    f.asset,
                    f.cvss,
                    f.exploit_available,
                    f.internet_exposed,
                    f.asset_criticality,
                    f.first_seen,
                    f.due,
                    f.overdue,
                ]
            )
