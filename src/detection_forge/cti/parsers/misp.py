from __future__ import annotations

import uuid

from ..models import CTIItem, SourceType


def parse_misp_event(event: dict) -> CTIItem:
    """Parse a single MISP event dict into a CTIItem."""
    info = event.get("info", "Unknown MISP Event")
    attributes = event.get("Attribute", [])
    attr_text = "\n".join(
        f"{a.get('type', '')}: {a.get('value', '')}"
        for a in attributes
        if a.get("value")
    )
    text = f"{info}\n{attr_text}".strip()
    iocs = [a["value"] for a in attributes if a.get("value") and a.get("to_ids")]
    return CTIItem(
        id=str(uuid.uuid4()),
        title=info,
        text=text,
        source_type=SourceType.MISP,
        raw_iocs=iocs,
        metadata={"misp_event_id": event.get("id")},
    )
