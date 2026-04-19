from __future__ import annotations

import json
import uuid
from pathlib import Path

from ..models import CTIItem, SourceType


def parse_stix_bundle(bundle_path: Path | str) -> list[CTIItem]:
    with open(bundle_path) as f:
        bundle = json.load(f)

    items = []
    for obj in bundle.get("objects", []):
        if obj.get("type") not in ("indicator", "malware", "attack-pattern", "campaign"):
            continue
        text_parts = [obj.get("name", ""), obj.get("description", "")]
        if obj.get("type") == "indicator" and "pattern" in obj:
            text_parts.append(f"IOC pattern: {obj['pattern']}")

        text = "\n".join(p for p in text_parts if p)
        if not text.strip():
            continue

        items.append(
            CTIItem(
                id=str(uuid.uuid4()),
                title=obj.get("name", f"STIX {obj.get('type', 'object')}"),
                text=text,
                source_type=SourceType.STIX,
                metadata={"stix_type": obj.get("type"), "stix_id": obj.get("id")},
            )
        )
    return items
