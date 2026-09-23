"""Detection-as-code for Microsoft Sentinel.

Rules live as YAML in ``detections/`` (the same shape as the public Azure-Sentinel repo).
This module validates them and compiles them to an ARM template that deploys every rule
as a Scheduled analytics rule.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SEVERITIES = {"Informational", "Low", "Medium", "High"}
OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}
TACTICS = {
    "Reconnaissance",
    "ResourceDevelopment",
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Collection",
    "CommandAndControl",
    "Exfiltration",
    "Impact",
    "ImpairProcessControl",
    "InhibitResponseFunction",
}
ENTITY_TYPES = {
    "Account": {"FullName", "Name", "NTDomain", "UPNSuffix", "Sid", "AadTenantId", "AadUserId", "ObjectGuid"},
    "Host": {"FullName", "HostName", "DnsDomain", "NetBiosName", "AzureID", "OMSAgentID"},
    "IP": {"Address"},
    "URL": {"Url"},
    "FileHash": {"Algorithm", "Value"},
    "AzureResource": {"ResourceId"},
    "CloudApplication": {"AppId", "Name", "InstanceName"},
    "DNS": {"DomainName"},
    "File": {"Directory", "Name"},
    "Process": {"ProcessId", "CommandLine"},
    "MailMessage": {"Recipient", "Sender", "NetworkMessageId"},
}
REQUIRED = [
    "id",
    "name",
    "description",
    "severity",
    "kind",
    "queryFrequency",
    "queryPeriod",
    "triggerOperator",
    "triggerThreshold",
    "tactics",
    "relevantTechniques",
    "query",
    "version",
]
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
DURATION = re.compile(r"^(\d+)([mhd])$")


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    path: Path
    data: dict[str, Any]
    errors: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return str(self.data.get("name", self.path.stem))


def to_iso_duration(value: str) -> str:
    """Convert '30m', '1h', '1d' to ISO 8601 ('PT30M', 'PT1H', 'P1D')."""
    m = DURATION.match(str(value).strip())
    if not m:
        raise RuleError(f"bad duration {value!r}, use forms like 30m, 1h, 1d")
    n, unit = int(m.group(1)), m.group(2)
    return f"P{n}D" if unit == "d" else f"PT{n}{unit.upper()}"


def minutes(value: str) -> int:
    m = DURATION.match(str(value).strip())
    if not m:
        raise RuleError(f"bad duration {value!r}")
    n, unit = int(m.group(1)), m.group(2)
    return n * {"m": 1, "h": 60, "d": 1440}[unit]


def validate(rule: Rule) -> list[str]:
    d, errs = rule.data, []
    for key in REQUIRED:
        if key not in d or d[key] in (None, "", []):
            errs.append(f"missing '{key}'")
    if errs:
        return errs
    try:
        uuid.UUID(str(d["id"]))
    except ValueError:
        errs.append("id must be a GUID")
    if d["severity"] not in SEVERITIES:
        errs.append(f"severity must be one of {sorted(SEVERITIES)}")
    if d["kind"] != "Scheduled":
        errs.append("only kind: Scheduled is supported")
    if d["triggerOperator"] not in OPERATORS:
        errs.append(f"triggerOperator must be one of {sorted(OPERATORS)}")
    try:
        freq, period = minutes(d["queryFrequency"]), minutes(d["queryPeriod"])
        if period < freq:
            errs.append("queryPeriod must be >= queryFrequency or events will be missed")
        if not 5 <= freq <= 20160 or period > 20160:
            errs.append("Sentinel allows queryFrequency 5m..14d and queryPeriod up to 14d")
    except RuleError as e:
        errs.append(str(e))
    for t in d["tactics"]:
        if t not in TACTICS:
            errs.append(f"unknown tactic '{t}'")
    for t in d["relevantTechniques"]:
        if not TECHNIQUE.match(str(t)):
            errs.append(f"bad technique id '{t}'")
    q = str(d["query"])
    if q.count("(") != q.count(")"):
        errs.append("query has unbalanced parentheses")
    if q.count("[") != q.count("]"):
        errs.append("query has unbalanced brackets")
    if len(q) > 10000:
        errs.append("query longer than the 10,000 character Sentinel limit")
    for m in d.get("entityMappings") or []:
        et = m.get("entityType")
        if et not in ENTITY_TYPES:
            errs.append(f"unknown entityType '{et}'")
            continue
        for fm in m.get("fieldMappings") or []:
            if fm.get("identifier") not in ENTITY_TYPES[et]:
                errs.append(f"{et} has no identifier '{fm.get('identifier')}'")
            col = fm.get("columnName", "")
            if col and not re.search(rf"\b{re.escape(col)}\b", q):
                errs.append(f"entity column '{col}' does not appear in the query")
    if len(d.get("entityMappings") or []) > 10:
        errs.append("Sentinel allows at most 10 entity mappings")
    return errs


def load_rules(directory: str | Path) -> list[Rule]:
    rules = []
    for path in sorted(Path(directory).glob("*.y*ml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            rules.append(Rule(path, {}, [f"invalid YAML: {e}"]))
            continue
        rule = Rule(path, data)
        rule.errors = validate(rule)
        rules.append(rule)
    ids = [r.data.get("id") for r in rules]
    for r in rules:
        if r.data.get("id") and ids.count(r.data["id"]) > 1:
            r.errors.append("duplicate id")
    return rules


def to_arm_resource(d: dict[str, Any]) -> dict[str, Any]:
    techniques = sorted({t.split(".")[0] for t in d["relevantTechniques"]})
    props: dict[str, Any] = {
        "displayName": d["name"],
        "description": str(d["description"]).strip(),
        "severity": d["severity"],
        "enabled": bool(d.get("enabled", True)),
        "query": str(d["query"]).strip(),
        "queryFrequency": to_iso_duration(d["queryFrequency"]),
        "queryPeriod": to_iso_duration(d["queryPeriod"]),
        "triggerOperator": OPERATORS[d["triggerOperator"]],
        "triggerThreshold": int(d["triggerThreshold"]),
        "suppressionDuration": "PT1H",
        "suppressionEnabled": False,
        "tactics": d["tactics"],
        "techniques": techniques,
        "templateVersion": str(d["version"]),
        "incidentConfiguration": {
            "createIncident": True,
            "groupingConfiguration": {
                "enabled": True,
                "reopenClosedIncident": False,
                "lookbackDuration": "PT5H",
                "matchingMethod": "AllEntities",
            },
        },
        "eventGroupingSettings": {"aggregationKind": "SingleAlert"},
    }
    if d.get("entityMappings"):
        props["entityMappings"] = d["entityMappings"]
    return {
        "type": "Microsoft.SecurityInsights/alertRules",
        "apiVersion": "2024-03-01",
        "scope": "[format('Microsoft.OperationalInsights/workspaces/{0}', parameters('workspaceName'))]",
        "name": str(d["id"]),
        "kind": "Scheduled",
        "properties": props,
    }


def build_arm(rules: list[Rule]) -> dict[str, Any]:
    bad = [r for r in rules if r.errors]
    if bad:
        raise RuleError("; ".join(f"{r.path.name}: {', '.join(r.errors)}" for r in bad))
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {"workspaceName": {"type": "string", "metadata": {"description": "Sentinel workspace name"}}},
        "resources": [to_arm_resource(r.data) for r in rules],
    }


def write_arm(rules: list[Rule], out: str | Path) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(build_arm(rules), indent=2), encoding="utf-8")
    return out
