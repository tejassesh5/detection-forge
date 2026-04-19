from __future__ import annotations
import asyncio
import structlog
from .providers.base import LLMProvider, LLMResponse

log = structlog.get_logger()


class LLMGateway:
    def __init__(self, providers: list[LLMProvider], max_retries: int = 2) -> None:
        self._providers = providers
        self._max_retries = max_retries

    async def generate(self, prompt: str, schema: dict | None = None) -> LLMResponse:
        last_exc: Exception | None = None
        for provider in self._providers:
            for attempt in range(self._max_retries + 1):
                try:
                    result = await provider.generate(prompt, schema)
                    log.info("llm.success", provider=provider.name, attempt=attempt)
                    return result
                except Exception as exc:
                    log.warning(
                        "llm.error", provider=provider.name, attempt=attempt, error=str(exc)
                    )
                    last_exc = exc
                    if attempt < self._max_retries:
                        await asyncio.sleep(2**attempt)
        raise RuntimeError(f"All LLM providers failed. Last: {last_exc}") from last_exc
