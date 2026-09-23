"""Extract, defang and refang indicators of compromise, and export them as a Sentinel watchlist."""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from dataclasses import dataclass

REFANG = [
    (re.compile(r"hxxps", re.I), "https"),
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\[at\]", re.I), "@"),
    (re.compile(r"\[://\]"), "://"),
]
PATTERNS = {
    "url": re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.I),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,24})\b"),
}
COMMON_FILE_EXT = {
    "exe",
    "dll",
    "ps1",
    "txt",
    "log",
    "json",
    "yaml",
    "yml",
    "csv",
    "zip",
    "png",
    "jpg",
    "pdf",
    "docx",
    "xlsx",
    "kql",
    "md",
    "py",
    "js",
    "sh",
    "bat",
    "vbs",
    "lnk",
    "iso",
    "msi",
}


@dataclass(frozen=True)
class Indicator:
    type: str
    value: str


def refang(text: str) -> str:
    for pattern, repl in REFANG:
        text = pattern.sub(repl, text)
    return text


def defang(value: str) -> str:
    value = re.sub(r"^http", "hxxp", value, flags=re.I)
    return value.replace(".", "[.]").replace("@", "[@]")


def extract(text: str, include_private: bool = False) -> list[Indicator]:
    """Extract unique indicators from free text (reports, emails, tickets). Handles defanged input."""
    clean = refang(text)
    found: dict[tuple[str, str], Indicator] = {}
    taken_spans: list[tuple[int, int]] = []

    def overlaps(span: tuple[int, int]) -> bool:
        return any(s <= span[0] < e or s < span[1] <= e for s, e in taken_spans)

    for kind in ("url", "email", "ipv4", "sha256", "sha1", "md5", "domain"):
        for m in PATTERNS[kind].finditer(clean):
            if overlaps(m.span()):
                continue
            value = m.group(0).rstrip(".,;")
            if kind == "ipv4":
                ip = ipaddress.ip_address(value)
                if not include_private and (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local):
                    continue
            if kind == "domain":
                if value.rsplit(".", 1)[-1].lower() in COMMON_FILE_EXT:
                    continue
                value = value.lower()
            if kind in ("sha256", "sha1", "md5"):
                value = value.lower()
            taken_spans.append(m.span())
            found.setdefault((kind, value), Indicator(kind, value))
    return list(found.values())


def to_watchlist_csv(indicators: list[Indicator], source: str = "manual") -> str:
    """CSV ready to upload as a Microsoft Sentinel watchlist (SearchKey = Indicator)."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["Indicator", "Type", "Source"])
    for i in sorted(indicators, key=lambda x: (x.type, x.value)):
        w.writerow([i.value, i.type, source])
    return buf.getvalue()
