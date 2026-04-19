from __future__ import annotations

import re

_TECHNIQUE_RE = re.compile(r"^[Tt](\d{4})(?:\.(\d{3}))?$")


def normalize_technique_id(raw: str) -> str:
    m = _TECHNIQUE_RE.match(raw.strip())
    if not m:
        raise ValueError(f"Not a valid ATT&CK technique ID: {raw!r}")
    base = f"T{m.group(1)}"
    return f"{base}.{m.group(2)}" if m.group(2) else base


def extract_technique_ids(candidates: list[str]) -> list[str]:
    result = []
    for c in candidates:
        try:
            result.append(normalize_technique_id(c))
        except ValueError:
            continue
    return result
