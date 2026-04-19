from __future__ import annotations

import uuid
from pathlib import Path

from ..models import CTIItem, SourceType
from .text import extract_iocs


def parse_pdf(path: Path | str) -> CTIItem:
    import pdfplumber

    path = Path(path)
    with pdfplumber.open(path) as pdf:
        pages = [page.extract_text() or "" for page in pdf.pages]
    text = "\n".join(pages).strip()
    return CTIItem(
        id=str(uuid.uuid4()),
        title=path.stem,
        text=text,
        source_type=SourceType.PDF,
        raw_iocs=extract_iocs(text),
        metadata={"filename": path.name, "pages": len(pages)},
    )
