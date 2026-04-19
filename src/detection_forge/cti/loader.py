from __future__ import annotations

from pathlib import Path

from .models import CTIItem, SourceType
from .parsers.text import parse_text


def load(
    source: str | Path,
    source_type: SourceType = SourceType.TEXT,
    **kwargs,
) -> list[CTIItem]:
    """Unified CTI loader. Returns one or more CTIItems."""
    if source_type == SourceType.TEXT:
        return [parse_text(str(source), title=kwargs.get("title"))]
    if source_type == SourceType.PDF:
        from .parsers.pdf import parse_pdf
        return [parse_pdf(Path(source))]
    if source_type == SourceType.STIX:
        from .parsers.stix import parse_stix_bundle
        return parse_stix_bundle(Path(source))
    if source_type == SourceType.TAXII:
        from .parsers.taxii import fetch_taxii
        return fetch_taxii(
            server_url=str(source),
            collection_id=kwargs["collection_id"],
            username=kwargs.get("username", ""),
            password=kwargs.get("password", ""),
        )
    if source_type == SourceType.MISP:
        from .parsers.misp import parse_misp_event
        return [parse_misp_event(kwargs["event"])]
    raise ValueError(f"Unsupported source_type: {source_type}")
