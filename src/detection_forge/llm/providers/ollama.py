from __future__ import annotations

import json

import httpx

from .base import LLMProvider, LLMResponse


class OllamaProvider:
    name = "ollama"
    cost_per_1k_in = 0.0

    def __init__(self, host: str = "http://localhost:11434", model: str = "qwen2.5:7b") -> None:
        self._host = host.rstrip("/")
        self._model = model

    async def generate(self, prompt: str, schema: dict | None = None) -> LLMResponse:
        payload: dict = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
        }
        if schema:
            payload["format"] = "json"

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(f"{self._host}/api/generate", json=payload)
            response.raise_for_status()
            data = response.json()

        raw = data.get("response", "")
        content: str | dict = raw
        if schema:
            try:
                content = json.loads(raw)
            except json.JSONDecodeError:
                content = raw

        return LLMResponse(
            content=content,
            provider=self.name,
            tokens_in=data.get("prompt_eval_count", 0),
            tokens_out=data.get("eval_count", 0),
        )


assert isinstance(OllamaProvider(), LLMProvider)
