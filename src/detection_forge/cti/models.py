from __future__ import annotations
import uuid
from enum import Enum
from pydantic import BaseModel, Field


class SourceType(str, Enum):
    TEXT = "text"
    PDF = "pdf"
    STIX = "stix"
    TAXII = "taxii"
    MISP = "misp"


class CTIItem(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    text: str
    source_type: SourceType
    raw_iocs: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
