from __future__ import annotations

import json

from groq import AsyncGroq

from .base import LLMProvider, LLMResponse


class GroqLlamaProvider:
    name = "groq"
    cost_per_1k_in = 0.0

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile") -> None:
        self._client = AsyncGroq(api_key=api_key)
        self._model = model

    async def generate(self, prompt: str, schema: dict | None = None) -> LLMResponse:
        kwargs: dict = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
        }
        if schema:
            kwargs["response_format"] = {"type": "json_object"}

        response = await self._client.chat.completions.create(**kwargs)
        raw = response.choices[0].message.content or ""
        content: str | dict = raw
        if schema:
            try:
                content = json.loads(raw)
            except json.JSONDecodeError:
                content = raw

        usage = response.usage
        return LLMResponse(
            content=content,
            provider=self.name,
            tokens_in=usage.prompt_tokens if usage else 0,
            tokens_out=usage.completion_tokens if usage else 0,
        )


assert isinstance(GroqLlamaProvider("x"), LLMProvider)
