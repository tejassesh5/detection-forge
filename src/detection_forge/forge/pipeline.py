from __future__ import annotations

import json
from pathlib import Path

import yaml

from jinja2 import Environment, FileSystemLoader

from ..cti.models import CTIItem
from ..llm.gateway import LLMGateway
from ..llm.models import ClassifyResult, ExtractedCTI
from .models import RuleDraft, RuleType, ValidationError
from .validator import validate_sigma, validate_yara

_PROMPTS_DIR = Path(__file__).parent.parent / "llm" / "prompts"
_env = Environment(loader=FileSystemLoader(str(_PROMPTS_DIR)))

MAX_REFINE_ATTEMPTS = 2


def _render(template_name: str, **kwargs) -> str:
    return _env.get_template(template_name).render(**kwargs)


def _parse_json_response(content: str | dict) -> dict:
    if isinstance(content, dict):
        return content
    # Strip markdown code fences (```json ... ``` or ``` ... ```)
    stripped = content.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        # Drop first line (```json or ```) and last line (```)
        inner = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        stripped = inner.strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM returned non-JSON: {e}\nContent: {content[:200]}") from e


class ForgePipeline:
    def __init__(self, gateway: LLMGateway) -> None:
        self._gw = gateway

    async def forge(self, cti: CTIItem, examples: list[str] | None = None) -> RuleDraft:
        # Stage A: Extract
        extract_prompt = _render("extract.j2", text=cti.text)
        extract_resp = await self._gw.generate(extract_prompt)
        extracted = ExtractedCTI(**_parse_json_response(extract_resp.content))

        # Stage B: Classify
        classify_prompt = _render(
            "classify.j2",
            ttps=extracted.ttps,
            behaviors=extracted.behaviors,
        )
        classify_resp = await self._gw.generate(classify_prompt)
        classified = ClassifyResult(**_parse_json_response(classify_resp.content))

        # Stage C: Draft
        rule_type = RuleType.SIGMA if classified.rule_type in ("sigma", "both") else RuleType.YARA
        template = "draft_sigma.j2" if rule_type == RuleType.SIGMA else "draft_yara.j2"
        draft_prompt = _render(
            template,
            ttps=extracted.ttps,
            behaviors=extracted.behaviors,
            attack_techniques=extracted.attack_techniques,
            detection_hints=extracted.detection_hints,
            iocs=cti.raw_iocs,
            log_source=classified.log_source,
            examples=examples or [],
        )
        draft_resp = await self._gw.generate(draft_prompt)
        raw = _parse_json_response(draft_resp.content)

        content: str = raw.get("content", "")
        # LLMs sometimes return rule as a dict under "rule" key instead of YAML string under "content"
        if not content and "rule" in raw and isinstance(raw["rule"], dict):
            content = yaml.dump(raw["rule"], default_flow_style=False, allow_unicode=True)
            raw["title"] = raw["rule"].get("title", raw.get("title", cti.title))
            raw["level"] = raw["rule"].get("level", raw.get("level", "medium"))

        # Stage D: Validate + Refine
        validator = validate_sigma if rule_type == RuleType.SIGMA else validate_yara
        errors = validator(content)

        for _ in range(MAX_REFINE_ATTEMPTS):
            if not errors:
                break
            refine_prompt = _render(
                "refine.j2", original_content=content, errors=errors
            )
            refine_resp = await self._gw.generate(refine_prompt)
            refined = _parse_json_response(refine_resp.content)
            content = refined.get("content", content)
            raw.update(refined)
            errors = validator(content)

        # Inject missing title into YAML content if validator flagged it
        final_title = raw.get("title", cti.title)
        if errors and any("title" in e.lower() for e in errors):
            if not content.strip().startswith("title:"):
                content = f"title: {final_title}\n" + content

        return RuleDraft(
            title=final_title,
            rule_type=rule_type,
            content=content,
            description=raw.get("description", ""),
            level=raw.get("level", "medium"),
            confidence=float(raw.get("confidence", 0.5)),
            attack_techniques=extracted.attack_techniques,
            validation_errors=[
                ValidationError(stage="validate", message=e) for e in errors
            ],
        )
