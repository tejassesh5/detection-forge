import pytest
from unittest.mock import AsyncMock, MagicMock
from detection_forge.forge.pipeline import ForgePipeline
from detection_forge.cti.models import CTIItem, SourceType
from detection_forge.llm.providers.base import LLMResponse

EXTRACT_RESPONSE = {
    "ttps": ["spearphishing", "command and scripting interpreter"],
    "iocs": ["evil.ru"],
    "behaviors": ["powershell executes encoded command"],
    "attack_techniques": ["T1566.001", "T1059.001"],
    "detection_hints": ["powershell.exe with -EncodedCommand flag"],
}

CLASSIFY_RESPONSE = {
    "rule_type": "sigma",
    "log_source": "sysmon",
    "rationale": "Log-based detection of powershell execution",
}

VALID_SIGMA_CONTENT = """title: Suspicious Encoded PowerShell
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\powershell.exe'
        CommandLine|contains: '-EncodedCommand'
    condition: selection
level: high
"""

DRAFT_RESPONSE = {
    "title": "Suspicious Encoded PowerShell",
    "content": VALID_SIGMA_CONTENT,
    "description": "Detects encoded PowerShell execution",
    "level": "high",
    "confidence": 0.85,
}


def _make_gateway(responses: list[dict]) -> MagicMock:
    calls = iter(responses)
    gateway = MagicMock()
    gateway.generate = AsyncMock(
        side_effect=lambda prompt, schema=None: LLMResponse(
            content=next(calls), provider="mock"
        )
    )
    return gateway


@pytest.mark.asyncio
async def test_forge_produces_valid_sigma():
    gw = _make_gateway([EXTRACT_RESPONSE, CLASSIFY_RESPONSE, DRAFT_RESPONSE])
    pipeline = ForgePipeline(gw)
    cti = CTIItem(
        title="APT29 phishing report",
        text="APT29 used spearphishing to deliver encoded PowerShell",
        source_type=SourceType.TEXT,
    )
    rule = await pipeline.forge(cti)
    assert rule.rule_type.value == "sigma"
    assert "EncodedCommand" in rule.content
    assert rule.is_valid
    assert "T1059.001" in rule.attack_techniques


@pytest.mark.asyncio
async def test_forge_retries_on_invalid_sigma():
    bad_content = "title: Bad\ndetection:\n  selection:\n    Image: ps\n"
    bad_draft = {**DRAFT_RESPONSE, "content": bad_content}
    good_refine = {**DRAFT_RESPONSE}
    gw = _make_gateway([EXTRACT_RESPONSE, CLASSIFY_RESPONSE, bad_draft, good_refine])
    pipeline = ForgePipeline(gw)
    cti = CTIItem(title="test", text="test threat intel", source_type=SourceType.TEXT)
    rule = await pipeline.forge(cti)
    assert rule.is_valid
    assert gw.generate.call_count == 4  # extract + classify + draft + 1 refine
