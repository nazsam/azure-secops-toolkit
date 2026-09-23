import json
from pathlib import Path

import pytest

from secops import rules
from secops.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_all_repo_rules_are_valid():
    loaded = rules.load_rules(ROOT / "detections")
    assert len(loaded) >= 10
    assert {r.path.name: r.errors for r in loaded if r.errors} == {}


def test_arm_template_shape(tmp_path):
    out = rules.write_arm(rules.load_rules(ROOT / "detections"), tmp_path / "rules.json")
    arm = json.loads(out.read_text())
    res = arm["resources"][0]
    assert res["type"] == "Microsoft.SecurityInsights/alertRules"
    assert "workspaces" in res["scope"]
    assert res["kind"] == "Scheduled"
    p = res["properties"]
    assert p["queryFrequency"].startswith("P") and p["triggerOperator"] == "GreaterThan"
    assert all("." not in t for t in p["techniques"])
    assert "subTechniques" not in p  # not in the stable 2024-03-01 API


@pytest.mark.parametrize("value,iso", [("5m", "PT5M"), ("1h", "PT1H"), ("1d", "P1D"), ("14d", "P14D")])
def test_durations(value, iso):
    assert rules.to_iso_duration(value) == iso


def test_validation_catches_mistakes(tmp_path):
    (tmp_path / "bad.yaml").write_text(
        "id: not-a-guid\nname: x\ndescription: x\nseverity: Critical\nkind: Scheduled\n"
        "queryFrequency: 1h\nqueryPeriod: 30m\ntriggerOperator: gt\ntriggerThreshold: 0\n"
        "tactics: [Hacking]\nrelevantTechniques: [T99]\nquery: 'SigninLogs | where (x'\nversion: 1.0.0\n"
        "entityMappings:\n  - entityType: Account\n    fieldMappings:\n      - identifier: Email\n        columnName: Missing\n"
    )
    errs = rules.load_rules(tmp_path)[0].errors
    joined = " ".join(errs)
    for expected in [
        "GUID",
        "severity",
        "queryPeriod",
        "unknown tactic",
        "technique",
        "parentheses",
        "Email",
        "Missing",
    ]:
        assert expected in joined, expected


def test_cli_validate_and_coverage(tmp_path, capsys):
    assert main(["validate", "--rules", str(ROOT / "detections")]) == 0
    out = tmp_path / "cov.md"
    assert (
        main(["coverage", "--rules", str(ROOT / "detections"), "--hunting", str(ROOT / "hunting"), "--out", str(out)])
        == 0
    )
    md = out.read_text()
    assert "T1110.003" in md and "hunt: legacy-auth-signins" in md
