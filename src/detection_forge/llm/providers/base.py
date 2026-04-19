from __future__ import annotations
from typing import Protocol, runtime_checkable
from pydantic import BaseModel


class LLMResponse(BaseModel):
    content: str | dict
    provider: str
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0


@runtime_checkable
class LLMProvider(Protocol):
    name: str
    cost_per_1k_in: float

    async def generate(self, prompt: str, schema: dict | None = None) -> LLMResponse: ...
