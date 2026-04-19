from pydantic import BaseModel, Field


class ExtractedCTI(BaseModel):
    ttps: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    behaviors: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    detection_hints: list[str] = Field(default_factory=list)


class ClassifyResult(BaseModel):
    rule_type: str
    log_source: str
    rationale: str
