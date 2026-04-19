import pytest
from unittest.mock import AsyncMock, MagicMock
from detection_forge.llm.gateway import LLMGateway
from detection_forge.llm.providers.base import LLMResponse


def _make_provider(name: str, *, fail: bool = False, content: str = "ok") -> MagicMock:
    p = MagicMock()
    p.name = name
    p.cost_per_1k_in = 0.0
    if fail:
        p.generate = AsyncMock(side_effect=RuntimeError("api error"))
    else:
        p.generate = AsyncMock(return_value=LLMResponse(content=content, provider=name))
    return p


@pytest.mark.asyncio
async def test_uses_primary():
    gw = LLMGateway([_make_provider("gemini", content="result")], max_retries=0)
    r = await gw.generate("prompt")
    assert r.provider == "gemini"
    assert r.content == "result"


@pytest.mark.asyncio
async def test_falls_back_on_failure():
    gw = LLMGateway(
        [_make_provider("gemini", fail=True), _make_provider("groq", content="fallback")],
        max_retries=0,
    )
    r = await gw.generate("prompt")
    assert r.provider == "groq"


@pytest.mark.asyncio
async def test_raises_when_all_fail():
    gw = LLMGateway(
        [_make_provider("gemini", fail=True), _make_provider("groq", fail=True)],
        max_retries=0,
    )
    with pytest.raises(RuntimeError, match="All LLM providers failed"):
        await gw.generate("prompt")


@pytest.mark.asyncio
async def test_retries_before_fallback():
    p = _make_provider("gemini", fail=True)
    gw = LLMGateway([p, _make_provider("groq")], max_retries=2)
    await gw.generate("prompt")
    assert p.generate.call_count == 3
