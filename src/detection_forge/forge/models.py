from __future__ import annotations
import uuid
from enum import Enum
from pydantic import BaseModel, Field


class RuleType(str, Enum):
    SIGMA = "sigma"
    YARA = "yara"


class ValidationError(BaseModel):
    stage: str
    message: str


class RuleDraft(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    rule_type: RuleType
    content: str
    description: str = ""
    level: str = "medium"
    confidence: float = 0.5
    attack_techniques: list[str] = Field(default_factory=list)
    validation_errors: list[ValidationError] = Field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return len(self.validation_errors) == 0
