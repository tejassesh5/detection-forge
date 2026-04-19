from __future__ import annotations
import re
import uuid
from ..models import CTIItem, SourceType

_IOC_PATTERNS: list[str] = [
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    r"\b[a-fA-F0-9]{64}\b",
    r"\b[a-fA-F0-9]{40}\b",
    r"\b[a-fA-F0-9]{32}\b",
    r"(?:https?://|ftp://)[^\s<>\"]+",
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:ru|cn|io|biz|info|xyz|top|tk)\b",
]

_BENIGN = {
    "google.com", "microsoft.com", "apple.com", "github.com",
    "cloudflare.com", "amazon.com", "windows.com",
}


def extract_iocs(text: str) -> list[str]:
    found: set[str] = set()
    for pattern in _IOC_PATTERNS:
        for match in re.findall(pattern, text, re.IGNORECASE):
            if match.lower() not in _BENIGN:
                found.add(match)
    return list(found)


def parse_text(text: str, title: str | None = None) -> CTIItem:
    return CTIItem(
        id=str(uuid.uuid4()),
        title=title or text[:80].strip(),
        text=text,
        source_type=SourceType.TEXT,
        raw_iocs=extract_iocs(text),
    )
