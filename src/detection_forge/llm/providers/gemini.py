from __future__ import annotations
import asyncio
import json
import google.generativeai as genai
from .base import LLMProvider, LLMResponse


class GeminiFlashProvider:
    name = "gemini"
    cost_per_1k_in = 0.0

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash") -> None:
        genai.configure(api_key=api_key)
        self._model_name = model

    async def generate(self, prompt: str, schema: dict | None = None) -> LLMResponse:
        model = genai.GenerativeModel(self._model_name)
        config = None
        if schema:
            config = genai.GenerationConfig(response_mime_type="application/json")

        response = await asyncio.to_thread(
            model.generate_content, prompt, generation_config=config
        )
        raw = response.text
        content: str | dict = raw
        if schema:
            try:
                content = json.loads(raw)
            except json.JSONDecodeError:
                content = raw

        meta = response.usage_metadata
        return LLMResponse(
            content=content,
            provider=self.name,
            tokens_in=meta.prompt_token_count if meta else 0,
            tokens_out=meta.candidates_token_count if meta else 0,
        )


assert isinstance(GeminiFlashProvider("x"), LLMProvider)
