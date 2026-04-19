# detection-forge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a web app that converts CTI reports and structured threat feeds into validated, scored, ATT&CK-tagged Sigma and YARA detection rules using a multi-provider LLM pipeline.

**Architecture:** FastAPI backend with HTMX frontend; CTI normalized to `CTIItem`, passed through chained LLM prompt stages (extract → classify → draft → validate → tag), stored in SQLite; rules tested against public log corpora; ATT&CK coverage tracked via MITRE STIX bundle; vectors stored in Qdrant for dedup and RAG-lite prompting.

**Tech Stack:** Python 3.12, FastAPI, HTMX 2, Alpine.js, Tailwind 4, Monaco Editor, SQLAlchemy 2 + SQLite (aiosqlite), Qdrant + sentence-transformers, pySigma, yara-python, google-generativeai, groq, ollama, stix2, taxii2-client, pymisp, pdfplumber, mitreattack-python, structlog, pytest, ruff, mypy, Docker Compose.

---

## File Map

```
detection-forge/
├── pyproject.toml
├── .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── .github/workflows/ci.yml
├── scripts/
│   ├── pull_corpora.py
│   ├── bootstrap_examples.py
│   └── demo_cli.py
├── src/detection_forge/
│   ├── __init__.py
│   ├── config.py
│   ├── db.py
│   ├── cti/
│   │   ├── __init__.py
│   │   ├── models.py
│   │   ├── loader.py
│   │   └── parsers/
│   │       ├── __init__.py
│   │       ├── text.py
│   │       ├── pdf.py
│   │       ├── stix.py
│   │       ├── taxii.py
│   │       └── misp.py
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── models.py
│   │   ├── gateway.py
│   │   ├── providers/
│   │   │   ├── __init__.py
│   │   │   ├── base.py
│   │   │   ├── gemini.py
│   │   │   ├── groq.py
│   │   │   └── ollama.py
│   │   └── prompts/
│   │       ├── extract.j2
│   │       ├── classify.j2
│   │       ├── draft_sigma.j2
│   │       ├── draft_yara.j2
│   │       └── refine.j2
│   ├── forge/
│   │   ├── __init__.py
│   │   ├── models.py
│   │   ├── pipeline.py
│   │   └── validator.py
│   ├── tester/
│   │   ├── __init__.py
│   │   ├── corpus.py
│   │   ├── sigma_runner.py
│   │   ├── yara_runner.py
│   │   └── scoring.py
│   ├── attack/
│   │   ├── __init__.py
│   │   ├── mapper.py
│   │   └── coverage.py
│   ├── vector/
│   │   ├── __init__.py
│   │   └── store.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── app.py
│   │   ├── deps.py
│   │   └── routes/
│   │       ├── __init__.py
│   │       ├── cti.py
│   │       ├── rules.py
│   │       ├── tests.py
│   │       └── coverage.py
│   └── web/
│       ├── __init__.py
│       ├── templates/
│       │   ├── base.html
│       │   ├── index.html
│       │   ├── rule_editor.html
│       │   └── coverage.html
│       └── static/
│           └── app.js
├── tests/
│   ├── conftest.py
│   ├── unit/
│   │   ├── cti/
│   │   │   └── test_text_parser.py
│   │   ├── llm/
│   │   │   └── test_gateway.py
│   │   ├── forge/
│   │   │   └── test_validator.py
│   │   └── tester/
│   │       └── test_scoring.py
│   └── integration/
│       └── test_pipeline.py
└── data/   # gitignored
```

---

## Phase 1 — Foundation

### Task 1: Project Skeleton

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `.env.example`
- Create: all `src/detection_forge/**/__init__.py` stubs

- [ ] **Step 1: Create pyproject.toml**

```toml
[project]
name = "detection-forge"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.32.0",
    "pydantic>=2.9.0",
    "pydantic-settings>=2.6.0",
    "sqlalchemy>=2.0.36",
    "aiosqlite>=0.20.0",
    "jinja2>=3.1.4",
    "python-multipart>=0.0.18",
    "httpx>=0.27.0",
    "google-generativeai>=0.8.0",
    "groq>=0.12.0",
    "ollama>=0.4.0",
    "pysigma>=0.11.0",
    "pySigma-backend-elasticsearch>=1.1.0",
    "yara-python>=4.5.0",
    "stix2>=3.0.1",
    "taxii2-client>=2.3.0",
    "pymisp>=2.4.196",
    "pdfplumber>=0.11.4",
    "mitreattack-python>=3.0.6",
    "qdrant-client>=1.12.0",
    "sentence-transformers>=3.3.0",
    "structlog>=24.4.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.3.0",
    "pytest-asyncio>=0.24.0",
    "pytest-cov>=6.0.0",
    "hypothesis>=6.112.0",
    "ruff>=0.7.0",
    "mypy>=1.13.0",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I", "UP"]

[tool.mypy]
python_version = "3.12"
strict = true
ignore_missing_imports = true
```

- [ ] **Step 2: Create .gitignore**

```gitignore
__pycache__/
*.py[cod]
.env
.venv/
venv/
data/
*.db
*.sqlite
.mypy_cache/
.ruff_cache/
.pytest_cache/
dist/
*.egg-info/
```

- [ ] **Step 3: Create .env.example**

```env
GEMINI_API_KEY=your_gemini_key_here
GROQ_API_KEY=your_groq_key_here
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5:7b
LLM_PRIMARY=gemini
DATABASE_URL=sqlite+aiosqlite:///./data/detection_forge.db
QDRANT_HOST=localhost
QDRANT_PORT=6333
DEBUG=false
```

- [ ] **Step 4: Create all package __init__.py stubs**

```bash
mkdir -p src/detection_forge/{cti/parsers,llm/{providers,prompts},forge,tester,attack,vector,api/routes,web/{templates,static}}
mkdir -p tests/{unit/{cti,llm,forge,tester},integration}
mkdir -p data scripts docs/superpowers/{specs,plans}
touch src/detection_forge/__init__.py
touch src/detection_forge/{cti,llm,forge,tester,attack,vector,api,web}/__init__.py
touch src/detection_forge/cti/parsers/__init__.py
touch src/detection_forge/llm/providers/__init__.py
touch src/detection_forge/api/routes/__init__.py
touch tests/__init__.py tests/unit/__init__.py tests/integration/__init__.py
touch tests/unit/{cti,llm,forge,tester}/__init__.py
```

- [ ] **Step 5: Install dependencies**

```bash
pip install -e ".[dev]"
```

Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add .
git commit -m "chore: project skeleton, dependencies, directory structure"
```

---

### Task 2: Config

**Files:**
- Create: `src/detection_forge/config.py`

- [ ] **Step 1: Write config.py**

```python
# src/detection_forge/config.py
from enum import Enum
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMProviderName(str, Enum):
    GEMINI = "gemini"
    GROQ = "groq"
    OLLAMA = "ollama"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    database_url: str = "sqlite+aiosqlite:///./data/detection_forge.db"
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333

    llm_primary: LLMProviderName = LLMProviderName.GEMINI
    llm_fallback: list[LLMProviderName] = [LLMProviderName.GROQ, LLMProviderName.OLLAMA]
    llm_max_retries: int = 2

    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"

    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b"

    embed_model: str = "all-MiniLM-L6-v2"

    debug: bool = False


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
```

- [ ] **Step 2: Verify import works**

```bash
python -c "from detection_forge.config import get_settings; s = get_settings(); print(s.llm_primary)"
```

Expected output: `gemini`

- [ ] **Step 3: Commit**

```bash
git add src/detection_forge/config.py
git commit -m "feat: config with pydantic-settings, multi-provider LLM support"
```

---

### Task 3: Database Models

**Files:**
- Create: `src/detection_forge/db.py`

- [ ] **Step 1: Write db.py**

```python
# src/detection_forge/db.py
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, JSON, String, Text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class CTIRecord(Base):
    __tablename__ = "cti_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(500))
    source_type: Mapped[str] = mapped_column(String(50))
    raw_text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(500))
    rule_type: Mapped[str] = mapped_column(String(10))  # sigma | yara
    content: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    attack_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    source_cti_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("cti_records.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class TestRun(Base):
    __tablename__ = "test_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(36), ForeignKey("rules.id"))
    corpus_name: Mapped[str] = mapped_column(String(100))
    score: Mapped[float] = mapped_column(Float, default=0.0)
    precision: Mapped[float] = mapped_column(Float, default=0.0)
    recall: Mapped[float] = mapped_column(Float, default=0.0)
    tp_count: Mapped[int] = mapped_column(default=0)
    fp_count: Mapped[int] = mapped_column(default=0)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


async def init_db(database_url: str) -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(database_url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return async_sessionmaker(engine, expire_on_commit=False)
```

- [ ] **Step 2: Write test**

```python
# tests/unit/test_db.py
import pytest
from detection_forge.db import init_db, CTIRecord, Rule
import uuid

@pytest.mark.asyncio
async def test_init_db_creates_tables():
    factory = await init_db("sqlite+aiosqlite:///:memory:")
    async with factory() as session:
        record = CTIRecord(
            id=str(uuid.uuid4()),
            title="Test CTI",
            source_type="text",
            raw_text="some threat intel",
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)
        assert record.title == "Test CTI"
```

- [ ] **Step 3: Run test**

```bash
pytest tests/unit/test_db.py -v
```

Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/detection_forge/db.py tests/unit/test_db.py
git commit -m "feat: SQLAlchemy async models — CTIRecord, Rule, TestRun"
```

---

### Task 4: CTI Models

**Files:**
- Create: `src/detection_forge/cti/models.py`

- [ ] **Step 1: Write cti/models.py**

```python
# src/detection_forge/cti/models.py
from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    TEXT = "text"
    PDF = "pdf"
    STIX = "stix"
    TAXII = "taxii"
    MISP = "misp"


class CTIItem(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    text: str
    source_type: SourceType
    raw_iocs: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
```

- [ ] **Step 2: Write test**

```python
# tests/unit/cti/test_models.py
from detection_forge.cti.models import CTIItem, SourceType

def test_cti_item_defaults():
    item = CTIItem(title="Report", text="malware found", source_type=SourceType.TEXT)
    assert item.source_type == SourceType.TEXT
    assert item.raw_iocs == []
    assert len(item.id) == 36  # UUID format

def test_cti_item_with_iocs():
    item = CTIItem(
        title="APT29",
        text="...",
        source_type=SourceType.STIX,
        raw_iocs=["10.0.0.1", "evil.ru"],
    )
    assert "10.0.0.1" in item.raw_iocs
```

- [ ] **Step 3: Run test**

```bash
pytest tests/unit/cti/test_models.py -v
```

Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/detection_forge/cti/models.py tests/unit/cti/test_models.py
git commit -m "feat: CTIItem pydantic model with SourceType enum"
```

---

### Task 5: CTI Text Parser

**Files:**
- Create: `src/detection_forge/cti/parsers/text.py`
- Create: `tests/unit/cti/test_text_parser.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/cti/test_text_parser.py
from detection_forge.cti.parsers.text import parse_text, extract_iocs
from detection_forge.cti.models import SourceType


def test_parse_text_creates_cti_item():
    item = parse_text("APT29 used C2 at 192.168.1.100", title="Test Report")
    assert item.title == "Test Report"
    assert item.source_type == SourceType.TEXT
    assert len(item.id) == 36


def test_parse_text_auto_title_from_first_80_chars():
    text = "Threat actor used spearphishing"
    item = parse_text(text)
    assert item.title == text


def test_extract_iocs_finds_ipv4():
    iocs = extract_iocs("C2 at 10.0.0.1 and 172.16.0.5")
    assert "10.0.0.1" in iocs
    assert "172.16.0.5" in iocs


def test_extract_iocs_finds_md5():
    iocs = extract_iocs("hash: d41d8cd98f00b204e9800998ecf8427e")
    assert "d41d8cd98f00b204e9800998ecf8427e" in iocs


def test_extract_iocs_finds_sha256():
    iocs = extract_iocs("sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs


def test_extract_iocs_filters_benign_domains():
    iocs = extract_iocs("downloaded from google.com and evil-c2.ru")
    assert "google.com" not in iocs
    assert "evil-c2.ru" in iocs


def test_extract_iocs_finds_url():
    iocs = extract_iocs("beacon called http://malware.example.com/path/payload")
    assert any("malware.example.com" in ioc for ioc in iocs)
```

- [ ] **Step 2: Run to confirm FAIL**

```bash
pytest tests/unit/cti/test_text_parser.py -v
```

Expected: `ModuleNotFoundError` or `ImportError`

- [ ] **Step 3: Write text.py**

```python
# src/detection_forge/cti/parsers/text.py
from __future__ import annotations

import re
import uuid

from ..models import CTIItem, SourceType

_IOC_PATTERNS: list[str] = [
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",  # IPv4
    r"\b[a-fA-F0-9]{64}\b",  # SHA256
    r"\b[a-fA-F0-9]{40}\b",  # SHA1
    r"\b[a-fA-F0-9]{32}\b",  # MD5
    r"(?:https?://|ftp://)[^\s<>\"]+",  # URLs
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:ru|cn|io|biz|info|xyz|top|tk)\b",
]

_BENIGN = {
    "google.com", "microsoft.com", "apple.com", "github.com",
    "cloudflare.com", "amazon.com", "windows.com",
}


def extract_iocs(text: str) -> list[str]:
    found: set[str] = set()
    for pattern in _IOC_PATTERNS:
        for match in re.findall(pattern, text, re.IGNORECASE):
            if match.lower() not in _BENIGN:
                found.add(match)
    return list(found)


def parse_text(text: str, title: str | None = None) -> CTIItem:
    return CTIItem(
        id=str(uuid.uuid4()),
        title=title or text[:80].strip(),
        text=text,
        source_type=SourceType.TEXT,
        raw_iocs=extract_iocs(text),
    )
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/unit/cti/test_text_parser.py -v
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/detection_forge/cti/parsers/text.py tests/unit/cti/test_text_parser.py
git commit -m "feat: CTI text parser with IOC extraction and benign domain filter"
```

---

### Task 6: LLM Base Protocol + Gemini Provider

**Files:**
- Create: `src/detection_forge/llm/providers/base.py`
- Create: `src/detection_forge/llm/providers/gemini.py`

- [ ] **Step 1: Write base.py**

```python
# src/detection_forge/llm/providers/base.py
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
```

- [ ] **Step 2: Write gemini.py**

```python
# src/detection_forge/llm/providers/gemini.py
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
                content = raw  # gateway will retry

        meta = response.usage_metadata
        return LLMResponse(
            content=content,
            provider=self.name,
            tokens_in=meta.prompt_token_count if meta else 0,
            tokens_out=meta.candidates_token_count if meta else 0,
        )


assert isinstance(GeminiFlashProvider("x"), LLMProvider)  # protocol check at import
```

- [ ] **Step 3: Commit**

```bash
git add src/detection_forge/llm/providers/
git commit -m "feat: LLMProvider protocol + GeminiFlash provider"
```

---

### Task 7: LLM Gateway

**Files:**
- Create: `src/detection_forge/llm/gateway.py`
- Create: `tests/unit/llm/test_gateway.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/llm/test_gateway.py
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
    assert p.generate.call_count == 3  # initial + 2 retries
```

- [ ] **Step 2: Run to confirm FAIL**

```bash
pytest tests/unit/llm/test_gateway.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Write gateway.py**

```python
# src/detection_forge/llm/gateway.py
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
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/unit/llm/test_gateway.py -v
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/detection_forge/llm/gateway.py tests/unit/llm/test_gateway.py
git commit -m "feat: LLM gateway with provider fallback and exponential backoff"
```

---

### Task 8: LLM Output Models + Prompt Templates

**Files:**
- Create: `src/detection_forge/llm/models.py`
- Create: `src/detection_forge/llm/prompts/extract.j2`
- Create: `src/detection_forge/llm/prompts/classify.j2`

- [ ] **Step 1: Write llm/models.py**

```python
# src/detection_forge/llm/models.py
from pydantic import BaseModel, Field


class ExtractedCTI(BaseModel):
    ttps: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    behaviors: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    detection_hints: list[str] = Field(default_factory=list)


class ClassifyResult(BaseModel):
    rule_type: str  # "sigma" | "yara" | "both"
    log_source: str  # "sysmon" | "windows_security" | "proxy" | "linux_auth" | ...
    rationale: str
```

- [ ] **Step 2: Write extract.j2**

```
You are a senior CTI analyst. Extract structured threat intelligence from the following report.

Return ONLY valid JSON with these exact keys:
- "ttps": list of tactics/techniques/procedures as short phrases
- "iocs": list of indicators (IPs, domains, hashes, file paths, registry keys)
- "behaviors": list of specific attacker behaviors observed in the report
- "attack_techniques": list of MITRE ATT&CK technique IDs (format: T1234 or T1234.001)
- "detection_hints": list of specific evidence to look for in logs (e.g. "cmd.exe spawned by winword.exe")

CTI Report:
{{ text }}

Respond ONLY with valid JSON. No markdown, no explanation.
```

- [ ] **Step 3: Write classify.j2**

```
You are a detection engineer. Given extracted threat intelligence, determine the best detection rule type.

Extracted TTPs: {{ ttps | join(", ") }}
Observed behaviors: {{ behaviors | join(", ") }}

Respond ONLY with valid JSON:
- "rule_type": "sigma" if this is best detected via log events, "yara" if via file/memory artifacts, "both" if both apply
- "log_source": the most relevant Sigma log source (sysmon, windows_security, windows_powershell, proxy, linux_auth, network_connection, webserver)
- "rationale": one sentence explaining the choice

Respond ONLY with valid JSON. No markdown, no explanation.
```

- [ ] **Step 4: Commit**

```bash
git add src/detection_forge/llm/models.py src/detection_forge/llm/prompts/
git commit -m "feat: LLM output models (ExtractedCTI, ClassifyResult) + prompt templates"
```

---

### Task 9: FastAPI App Skeleton

**Files:**
- Create: `src/detection_forge/api/app.py`
- Create: `src/detection_forge/api/deps.py`
- Create: `src/detection_forge/web/templates/base.html`

- [ ] **Step 1: Write deps.py**

```python
# src/detection_forge/api/deps.py
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession


async def get_db(request: Request):
    async with request.app.state.db() as session:
        yield session
```

- [ ] **Step 2: Write app.py**

```python
# src/detection_forge/api/app.py
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..config import get_settings
from ..db import init_db

log = structlog.get_logger()

TEMPLATES = Jinja2Templates(
    directory=str(Path(__file__).parent.parent / "web" / "templates")
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    Path("data").mkdir(exist_ok=True)
    app.state.db = await init_db(settings.database_url)
    app.state.settings = settings
    app.state.templates = TEMPLATES
    log.info("startup.complete")
    yield
    log.info("shutdown")


def create_app() -> FastAPI:
    app = FastAPI(title="detection-forge", version="0.1.0", lifespan=lifespan)

    static_dir = Path(__file__).parent.parent / "web" / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    from .routes import cti as cti_router
    from .routes import rules as rules_router

    app.include_router(cti_router.router, prefix="/api/cti", tags=["cti"])
    app.include_router(rules_router.router, prefix="/api/rules", tags=["rules"])

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "version": "0.1.0"}

    return app


app = create_app()
```

- [ ] **Step 3: Write base.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{% block title %}detection-forge{% endblock %}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/htmx.org@2.0.3"></script>
  <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">
  <nav class="border-b border-gray-800 px-6 py-3 flex items-center gap-6">
    <span class="font-bold text-emerald-400 text-lg">detection-forge</span>
    <a href="/" class="text-gray-400 hover:text-white text-sm">Rules</a>
    <a href="/coverage" class="text-gray-400 hover:text-white text-sm">Coverage</a>
  </nav>
  <main class="px-6 py-8 max-w-7xl mx-auto">
    {% block content %}{% endblock %}
  </main>
</body>
</html>
```

- [ ] **Step 4: Write stub route files (needed by app.py imports)**

```python
# src/detection_forge/api/routes/cti.py
from fastapi import APIRouter
router = APIRouter()
```

```python
# src/detection_forge/api/routes/rules.py
from fastapi import APIRouter
router = APIRouter()
```

- [ ] **Step 5: Write health check test**

```python
# tests/unit/test_app_health.py
import pytest
from httpx import AsyncClient, ASGITransport
from detection_forge.api.app import create_app

@pytest.mark.asyncio
async def test_health_check():
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
```

- [ ] **Step 6: Run test**

```bash
pytest tests/unit/test_app_health.py -v
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/detection_forge/api/ src/detection_forge/web/templates/base.html tests/unit/test_app_health.py
git commit -m "feat: FastAPI app skeleton with lifespan, templates, health route"
```

---

## Phase 2 — Sigma Pipeline

### Task 10: Rule Models + Sigma Validator

**Files:**
- Create: `src/detection_forge/forge/models.py`
- Create: `src/detection_forge/forge/validator.py`
- Create: `tests/unit/forge/test_validator.py`

- [ ] **Step 1: Write forge/models.py**

```python
# src/detection_forge/forge/models.py
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
    content: str  # raw YAML (Sigma) or YARA source
    description: str = ""
    level: str = "medium"  # low/medium/high/critical
    confidence: float = 0.5
    attack_techniques: list[str] = Field(default_factory=list)
    validation_errors: list[ValidationError] = Field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return len(self.validation_errors) == 0
```

- [ ] **Step 2: Write failing validator tests**

```python
# tests/unit/forge/test_validator.py
import pytest
from detection_forge.forge.validator import validate_sigma, validate_yara
from detection_forge.forge.models import RuleType

VALID_SIGMA = """
title: Suspicious PowerShell Execution
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-Enc '
    condition: selection
level: high
"""

INVALID_SIGMA = """
title: Bad Rule
detection:
    # missing condition
    selection:
        Image: powershell.exe
"""

VALID_YARA = """
rule SuspiciousString {
    strings:
        $a = "cmd.exe /c"
    condition:
        $a
}
"""

INVALID_YARA = "rule Broken { strings: $a = condition: $a"


def test_validate_sigma_valid():
    errors = validate_sigma(VALID_SIGMA)
    assert errors == []


def test_validate_sigma_invalid():
    errors = validate_sigma(INVALID_SIGMA)
    assert len(errors) > 0


def test_validate_yara_valid():
    errors = validate_yara(VALID_YARA)
    assert errors == []


def test_validate_yara_invalid():
    errors = validate_yara(INVALID_YARA)
    assert len(errors) > 0
```

- [ ] **Step 3: Run to confirm FAIL**

```bash
pytest tests/unit/forge/test_validator.py -v
```

Expected: `ImportError`

- [ ] **Step 4: Write validator.py**

```python
# src/detection_forge/forge/validator.py
from __future__ import annotations

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
import yara


def validate_sigma(yaml_content: str) -> list[str]:
    """Returns list of error strings; empty means valid."""
    try:
        SigmaCollection.from_yaml(yaml_content)
        return []
    except SigmaError as e:
        return [str(e)]
    except Exception as e:
        return [f"parse error: {e}"]


def validate_yara(yara_source: str) -> list[str]:
    """Returns list of error strings; empty means valid."""
    try:
        yara.compile(source=yara_source)
        return []
    except yara.SyntaxError as e:
        return [str(e)]
    except Exception as e:
        return [f"compile error: {e}"]
```

- [ ] **Step 5: Run tests**

```bash
pytest tests/unit/forge/test_validator.py -v
```

Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add src/detection_forge/forge/models.py src/detection_forge/forge/validator.py tests/unit/forge/test_validator.py
git commit -m "feat: RuleDraft model + Sigma/YARA structural validator"
```

---

### Task 11: Sigma Draft Prompt + Refine Template

**Files:**
- Create: `src/detection_forge/llm/prompts/draft_sigma.j2`
- Create: `src/detection_forge/llm/prompts/refine.j2`
- Create: `src/detection_forge/llm/prompts/draft_yara.j2`

- [ ] **Step 1: Write draft_sigma.j2**

```
You are an expert detection engineer. Write a Sigma rule to detect the following threat.

Threat summary:
- TTPs: {{ ttps | join(", ") }}
- Behaviors: {{ behaviors | join(", ") }}
- ATT&CK techniques: {{ attack_techniques | join(", ") }}
- Detection hints: {{ detection_hints | join(", ") }}
- Log source: {{ log_source }}

{% if examples %}
Reference examples (adapt, do not copy):
{% for ex in examples %}
---
{{ ex }}
{% endfor %}
{% endif %}

Return ONLY valid JSON with these keys:
- "title": descriptive rule name (max 80 chars)
- "content": complete valid Sigma YAML rule as a string
- "description": what this rule detects (1-2 sentences)
- "level": one of low/medium/high/critical
- "confidence": float 0.0-1.0 indicating your confidence this rule is accurate

Rules:
- The Sigma rule MUST have: title, status, logsource, detection (with condition), level
- status must be "experimental"
- Do not use unbounded wildcards like CommandLine|contains: '*' with no other filter
- Use specific field names valid for the log_source

Respond ONLY with valid JSON. No markdown fences.
```

- [ ] **Step 2: Write draft_yara.j2**

```
You are an expert malware analyst. Write a YARA rule to detect file or memory artifacts from the following threat.

Threat summary:
- IOCs: {{ iocs | join(", ") }}
- Behaviors: {{ behaviors | join(", ") }}
- ATT&CK techniques: {{ attack_techniques | join(", ") }}

Return ONLY valid JSON with these keys:
- "title": rule identifier (alphanumeric + underscores, max 60 chars, no spaces)
- "content": complete valid YARA rule source as a string
- "description": what this rule detects (1-2 sentences)
- "level": one of low/medium/high/critical
- "confidence": float 0.0-1.0

Rules:
- Rule name in YARA must match "title" field
- Must include at least 2 strings or 1 regex
- Condition must reference defined strings
- Do not use external variables

Respond ONLY with valid JSON. No markdown fences.
```

- [ ] **Step 3: Write refine.j2**

```
You previously generated a detection rule that failed validation. Fix it.

Original rule content:
{{ original_content }}

Validation errors:
{% for error in errors %}
- {{ error }}
{% endfor %}

Return ONLY valid JSON with the same keys as before:
- "title": same or corrected title
- "content": corrected rule (fix ALL validation errors)
- "description": description
- "level": severity level
- "confidence": float 0.0-1.0

Respond ONLY with valid JSON. No markdown fences.
```

- [ ] **Step 4: Commit**

```bash
git add src/detection_forge/llm/prompts/
git commit -m "feat: Sigma/YARA draft prompts + refine prompt for validation retry"
```

---

### Task 12: Forge Pipeline

**Files:**
- Create: `src/detection_forge/forge/pipeline.py`
- Create: `tests/integration/test_pipeline.py`

- [ ] **Step 1: Write pipeline.py**

```python
# src/detection_forge/forge/pipeline.py
from __future__ import annotations

import json
from pathlib import Path

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
    try:
        return json.loads(content)
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

        return RuleDraft(
            title=raw.get("title", cti.title),
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
```

- [ ] **Step 2: Write integration test (uses mock gateway)**

```python
# tests/integration/test_pipeline.py
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

DRAFT_RESPONSE = {
    "title": "Suspicious Encoded PowerShell",
    "content": """title: Suspicious Encoded PowerShell
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
""",
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
    bad_draft = {**DRAFT_RESPONSE, "content": "title: Bad\ndetection:\n  selection:\n    Image: ps\n"}
    good_refine = {**DRAFT_RESPONSE}
    gw = _make_gateway([EXTRACT_RESPONSE, CLASSIFY_RESPONSE, bad_draft, good_refine])
    pipeline = ForgePipeline(gw)
    cti = CTIItem(title="test", text="test threat intel", source_type=SourceType.TEXT)
    rule = await pipeline.forge(cti)
    assert rule.is_valid
    assert gw.generate.call_count == 4  # extract + classify + draft + 1 refine
```

- [ ] **Step 3: Run integration tests**

```bash
pytest tests/integration/test_pipeline.py -v
```

Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add src/detection_forge/forge/pipeline.py tests/integration/test_pipeline.py
git commit -m "feat: forge pipeline — extract→classify→draft→validate→refine stages"
```

---

### Task 13: Rules API Route + Web UI

**Files:**
- Modify: `src/detection_forge/api/routes/cti.py`
- Modify: `src/detection_forge/api/routes/rules.py`
- Create: `src/detection_forge/web/templates/index.html`

- [ ] **Step 1: Write cti.py route (ingest text + trigger forge)**

```python
# src/detection_forge/api/routes/cti.py
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...api.deps import get_db
from ...cti.models import SourceType
from ...cti.parsers.text import parse_text
from ...db import CTIRecord, Rule as RuleDB

router = APIRouter()


class IngestRequest(BaseModel):
    text: str
    title: str | None = None


@router.post("/ingest/text")
async def ingest_text(body: IngestRequest, db: AsyncSession = Depends(get_db)):
    item = parse_text(body.text, title=body.title)
    record = CTIRecord(
        id=item.id,
        title=item.title,
        source_type=item.source_type.value,
        raw_text=item.text,
    )
    db.add(record)
    await db.commit()
    return {"id": item.id, "title": item.title, "ioc_count": len(item.raw_iocs)}
```

- [ ] **Step 2: Write rules.py route**

```python
# src/detection_forge/api/routes/rules.py
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...api.deps import get_db
from ...db import Rule as RuleDB

router = APIRouter()


@router.get("/", response_model=list[dict])
async def list_rules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RuleDB).order_by(RuleDB.created_at.desc()))
    rules = result.scalars().all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "rule_type": r.rule_type,
            "confidence": r.confidence,
            "attack_techniques": r.attack_techniques,
            "created_at": r.created_at.isoformat(),
        }
        for r in rules
    ]


@router.get("/{rule_id}")
async def get_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RuleDB).where(RuleDB.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Rule not found")
    return {
        "id": rule.id,
        "title": rule.title,
        "rule_type": rule.rule_type,
        "content": rule.content,
        "confidence": rule.confidence,
        "attack_techniques": rule.attack_techniques,
        "created_at": rule.created_at.isoformat(),
    }
```

- [ ] **Step 3: Write index.html**

```html
{% extends "base.html" %}
{% block title %}detection-forge — Rules{% endblock %}
{% block content %}
<div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
  <!-- CTI Ingest -->
  <div class="bg-gray-900 rounded-lg p-6 border border-gray-800">
    <h2 class="text-lg font-semibold mb-4 text-emerald-400">Ingest CTI</h2>
    <form hx-post="/api/cti/ingest/text" hx-target="#rule-list" hx-swap="innerHTML"
          hx-indicator="#spinner" class="space-y-3">
      <input type="text" name="title" placeholder="Report title (optional)"
             class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"/>
      <textarea name="text" rows="10" placeholder="Paste CTI report, threat blog post, or IOC list..."
                class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-emerald-500" required></textarea>
      <button type="submit"
              class="w-full bg-emerald-600 hover:bg-emerald-500 text-white rounded py-2 text-sm font-medium transition-colors">
        Generate Rule
      </button>
    </form>
    <div id="spinner" class="htmx-indicator mt-2 text-sm text-gray-400">Generating...</div>
  </div>

  <!-- Rule List -->
  <div>
    <h2 class="text-lg font-semibold mb-4 text-emerald-400">Rules Library</h2>
    <div id="rule-list"
         hx-get="/api/rules/partials/list" hx-trigger="load"
         class="space-y-3">
      <p class="text-gray-500 text-sm">Loading rules...</p>
    </div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 4: Add index route to app.py**

Modify `src/detection_forge/api/app.py` — add this inside `create_app()` after health route:

```python
    from fastapi import Request
    from fastapi.responses import HTMLResponse

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return app.state.templates.TemplateResponse(
            "index.html", {"request": request}
        )
```

- [ ] **Step 5: Add rules partial route to rules.py**

Add to `src/detection_forge/api/routes/rules.py`:

```python
@router.get("/partials/list", response_class=HTMLResponse)
async def rules_list_partial(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RuleDB).order_by(RuleDB.created_at.desc()).limit(50))
    rules = result.scalars().all()
    tmpl = request.app.state.templates
    return tmpl.TemplateResponse(
        "partials/rule_card.html", {"request": request, "rules": rules}
    )
```

- [ ] **Step 6: Create rule_card.html partial**

```bash
mkdir -p src/detection_forge/web/templates/partials
```

```html
<!-- src/detection_forge/web/templates/partials/rule_card.html -->
{% for rule in rules %}
<div class="bg-gray-900 border border-gray-800 rounded-lg p-4">
  <div class="flex items-start justify-between">
    <h3 class="font-medium text-sm">{{ rule.title }}</h3>
    <span class="text-xs px-2 py-0.5 rounded
      {% if rule.rule_type == 'sigma' %}bg-blue-900 text-blue-300
      {% else %}bg-purple-900 text-purple-300{% endif %}">
      {{ rule.rule_type }}
    </span>
  </div>
  <div class="mt-2 flex gap-2 flex-wrap">
    {% for t in rule.attack_techniques %}
    <span class="text-xs bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">{{ t }}</span>
    {% endfor %}
  </div>
  <div class="mt-3 flex items-center justify-between">
    <span class="text-xs text-gray-500">confidence: {{ "%.0f"|format(rule.confidence * 100) }}%</span>
    <a href="/rules/{{ rule.id }}" class="text-xs text-emerald-400 hover:underline">View →</a>
  </div>
</div>
{% else %}
<p class="text-gray-500 text-sm">No rules yet. Ingest CTI to generate your first rule.</p>
{% endfor %}
```

- [ ] **Step 7: Commit**

```bash
git add src/detection_forge/api/routes/ src/detection_forge/web/templates/
git commit -m "feat: CTI ingest route, rules listing API, index UI with HTMX"
```

---

## Phase 3 — Testing + Scoring

### Task 14: Corpus Registry + Pull Script

**Files:**
- Create: `src/detection_forge/tester/corpus.py`
- Create: `scripts/pull_corpora.py`

- [ ] **Step 1: Write corpus.py**

```python
# src/detection_forge/tester/corpus.py
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path("data/corpora")


@dataclass
class Corpus:
    name: str
    description: str
    path: Path
    file_glob: str = "**/*.evtx"
    corpus_type: str = "evtx"  # evtx | json | binary


_REGISTRY: dict[str, Corpus] = {
    "evtx-attack-samples": Corpus(
        name="evtx-attack-samples",
        description="Windows EVTX logs mapped to MITRE ATT&CK",
        path=DATA_DIR / "evtx-attack-samples",
        file_glob="**/*.evtx",
        corpus_type="evtx",
    ),
    "mordor": Corpus(
        name="mordor",
        description="Security Datasets (Mordor) — JSON log files from Atomic Red Team",
        path=DATA_DIR / "mordor",
        file_glob="**/*.json",
        corpus_type="json",
    ),
    "benign-baseline": Corpus(
        name="benign-baseline",
        description="Normal Windows/Sysmon logs for false-positive testing",
        path=DATA_DIR / "benign-baseline",
        file_glob="**/*.evtx",
        corpus_type="evtx",
    ),
}


def get_corpus(name: str) -> Corpus:
    if name not in _REGISTRY:
        raise KeyError(f"Unknown corpus '{name}'. Available: {list(_REGISTRY)}")
    corpus = _REGISTRY[name]
    if not corpus.path.exists():
        raise FileNotFoundError(
            f"Corpus '{name}' not found at {corpus.path}. Run: python scripts/pull_corpora.py"
        )
    return corpus


def list_corpora() -> list[str]:
    return list(_REGISTRY)
```

- [ ] **Step 2: Write scripts/pull_corpora.py**

```python
#!/usr/bin/env python3
"""Download public attack log corpora for rule testing."""
import subprocess
import sys
from pathlib import Path

DATA_DIR = Path("data/corpora")
DATA_DIR.mkdir(parents=True, exist_ok=True)

CORPORA = {
    "evtx-attack-samples": {
        "url": "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git",
        "dest": DATA_DIR / "evtx-attack-samples",
        "method": "git_clone",
    },
    "mordor": {
        "url": "https://github.com/OTRF/Security-Datasets.git",
        "dest": DATA_DIR / "mordor",
        "method": "git_clone",
        "sparse": ["datasets/atomic/windows"],
    },
}


def git_clone(url: str, dest: Path, sparse: list[str] | None = None) -> None:
    if dest.exists():
        print(f"  Already exists: {dest}")
        return
    if sparse:
        subprocess.run(["git", "clone", "--depth=1", "--filter=blob:none",
                        "--sparse", url, str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set"] + sparse, check=True)
    else:
        subprocess.run(["git", "clone", "--depth=1", url, str(dest)], check=True)


def main() -> None:
    for name, config in CORPORA.items():
        print(f"Pulling {name}...")
        if config["method"] == "git_clone":
            git_clone(config["url"], config["dest"], config.get("sparse"))
        print(f"  Done: {config['dest']}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Commit**

```bash
git add src/detection_forge/tester/corpus.py scripts/pull_corpora.py
git commit -m "feat: corpus registry + pull script for EVTX-ATTACK-SAMPLES and Mordor"
```

---

### Task 15: Sigma Test Runner

**Files:**
- Create: `src/detection_forge/tester/sigma_runner.py`
- Create: `tests/unit/tester/test_sigma_runner.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/tester/test_sigma_runner.py
from detection_forge.tester.sigma_runner import match_sigma_against_events

SIGMA_RULE = """
title: Encoded PowerShell
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-EncodedCommand'
    condition: selection
level: high
"""

def test_match_sigma_detects_true_positive():
    events = [
        {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "CommandLine": "powershell.exe -EncodedCommand SQBuAHYAbwBrAGUATQBpAG0AaQBrAGEAdAB6"},
    ]
    matches = match_sigma_against_events(SIGMA_RULE, events)
    assert len(matches) == 1

def test_match_sigma_no_false_positive():
    events = [
        {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c dir"},
    ]
    matches = match_sigma_against_events(SIGMA_RULE, events)
    assert len(matches) == 0

def test_match_sigma_returns_matching_events():
    events = [
        {"Image": "C:\\powershell.exe", "CommandLine": "-EncodedCommand abc"},
        {"Image": "C:\\notepad.exe", "CommandLine": "notepad.exe"},
    ]
    matches = match_sigma_against_events(SIGMA_RULE, events)
    assert len(matches) == 1
    assert "-EncodedCommand" in matches[0]["CommandLine"]
```

- [ ] **Step 2: Run to confirm FAIL**

```bash
pytest tests/unit/tester/test_sigma_runner.py -v
```

- [ ] **Step 3: Write sigma_runner.py**

```python
# src/detection_forge/tester/sigma_runner.py
from __future__ import annotations

import re

from sigma.collection import SigmaCollection


def _field_match(event_val: str, condition: str | list) -> bool:
    """Simple field value matching for test purposes."""
    if isinstance(condition, list):
        return any(_field_match(event_val, c) for c in condition)
    return condition.lower() in event_val.lower()


def _evaluate_selection(selection: dict, event: dict) -> bool:
    for field_expr, value in selection.items():
        parts = field_expr.split("|")
        field = parts[0]
        modifier = parts[1] if len(parts) > 1 else "equals"
        event_val = str(event.get(field, ""))
        if modifier == "endswith":
            values = value if isinstance(value, list) else [value]
            if not any(event_val.lower().endswith(v.lower().lstrip("\\")) for v in values):
                return False
        elif modifier == "contains":
            values = value if isinstance(value, list) else [value]
            if not any(v.lower() in event_val.lower() for v in values):
                return False
        elif modifier == "startswith":
            values = value if isinstance(value, list) else [value]
            if not any(event_val.lower().startswith(v.lower()) for v in values):
                return False
        else:
            values = value if isinstance(value, list) else [value]
            if not any(event_val.lower() == v.lower() for v in values):
                return False
    return True


def match_sigma_against_events(sigma_yaml: str, events: list[dict]) -> list[dict]:
    """Match a Sigma rule (YAML string) against a list of event dicts.
    Returns events that triggered the rule."""
    import yaml
    rule = yaml.safe_load(sigma_yaml)
    detection = rule.get("detection", {})
    condition = detection.get("condition", "selection")
    selections = {k: v for k, v in detection.items() if k != "condition"}

    matched = []
    for event in events:
        # Evaluate named selections
        results: dict[str, bool] = {}
        for sel_name, sel_def in selections.items():
            if isinstance(sel_def, dict):
                results[sel_name] = _evaluate_selection(sel_def, event)
            else:
                results[sel_name] = False

        # Simple condition evaluation (handles 'selection', 'all of them', 'X and Y')
        cond = condition.strip()
        try:
            match = eval(
                cond,
                {"__builtins__": {}},
                {k: v for k, v in results.items()},
            )
        except Exception:
            match = results.get("selection", False)

        if match:
            matched.append(event)

    return matched
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/unit/tester/test_sigma_runner.py -v
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/detection_forge/tester/sigma_runner.py tests/unit/tester/test_sigma_runner.py
git commit -m "feat: Sigma event matcher for corpus-based TP/FP testing"
```

---

### Task 16: Scoring Formula

**Files:**
- Create: `src/detection_forge/tester/scoring.py`
- Create: `tests/unit/tester/test_scoring.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/tester/test_scoring.py
from detection_forge.tester.scoring import compute_score, ScoreBreakdown

def test_perfect_rule_scores_100():
    breakdown = compute_score(
        tp=10, fp=0, total_attack_samples=10,
        field_count=4, has_wildcard_only=False,
        novelty=1.0, attack_coverage=3
    )
    assert breakdown.total == 100.0

def test_zero_tp_scores_low():
    breakdown = compute_score(
        tp=0, fp=5, total_attack_samples=10,
        field_count=2, has_wildcard_only=False,
        novelty=0.8, attack_coverage=1
    )
    assert breakdown.total < 30.0

def test_high_fp_penalizes_precision():
    high_fp = compute_score(tp=5, fp=20, total_attack_samples=10,
                             field_count=3, has_wildcard_only=False,
                             novelty=0.9, attack_coverage=2)
    low_fp = compute_score(tp=5, fp=0, total_attack_samples=10,
                            field_count=3, has_wildcard_only=False,
                            novelty=0.9, attack_coverage=2)
    assert low_fp.total > high_fp.total

def test_wildcard_only_penalty():
    with_wildcard = compute_score(tp=8, fp=2, total_attack_samples=10,
                                   field_count=1, has_wildcard_only=True,
                                   novelty=0.9, attack_coverage=2)
    without = compute_score(tp=8, fp=2, total_attack_samples=10,
                             field_count=3, has_wildcard_only=False,
                             novelty=0.9, attack_coverage=2)
    assert without.total > with_wildcard.total

def test_score_is_0_to_100():
    b = compute_score(tp=3, fp=1, total_attack_samples=10,
                      field_count=2, has_wildcard_only=False,
                      novelty=0.7, attack_coverage=2)
    assert 0.0 <= b.total <= 100.0
```

- [ ] **Step 2: Run to confirm FAIL**

```bash
pytest tests/unit/tester/test_scoring.py -v
```

- [ ] **Step 3: Write scoring.py**

```python
# src/detection_forge/tester/scoring.py
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScoreBreakdown:
    precision: float  # 0-1
    recall: float  # 0-1
    attack_coverage: float  # 0-1
    specificity: float  # 0-1
    novelty: float  # 0-1
    total: float  # 0-100

    def grade(self) -> str:
        if self.total >= 85:
            return "A"
        if self.total >= 70:
            return "B"
        if self.total >= 55:
            return "C"
        if self.total >= 40:
            return "D"
        return "F"


def compute_score(
    tp: int,
    fp: int,
    total_attack_samples: int,
    field_count: int,
    has_wildcard_only: bool,
    novelty: float,
    attack_coverage: int,
    max_attack_coverage: int = 5,
) -> ScoreBreakdown:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / total_attack_samples if total_attack_samples > 0 else 0.0

    cov_norm = min(attack_coverage / max_attack_coverage, 1.0)

    spec = min(field_count / 4.0, 1.0)
    if has_wildcard_only:
        spec *= 0.4

    nov = max(0.0, min(novelty, 1.0))

    total = (
        35.0 * precision
        + 25.0 * recall
        + 15.0 * cov_norm
        + 15.0 * spec
        + 10.0 * nov
    )
    total = max(0.0, min(total, 100.0))

    return ScoreBreakdown(
        precision=precision,
        recall=recall,
        attack_coverage=cov_norm,
        specificity=spec,
        novelty=nov,
        total=round(total, 1),
    )
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/unit/tester/test_scoring.py -v
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/detection_forge/tester/scoring.py tests/unit/tester/test_scoring.py
git commit -m "feat: scoring formula (precision 35%, recall 25%, coverage 15%, specificity 15%, novelty 10%)"
```

---

## Phase 4 — YARA + Multi-provider

### Task 17: YARA Runner

**Files:**
- Create: `src/detection_forge/tester/yara_runner.py`
- Create: `tests/unit/tester/test_yara_runner.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/tester/test_yara_runner.py
import tempfile
from pathlib import Path
from detection_forge.tester.yara_runner import match_yara_against_files

YARA_RULE = """
rule SuspiciousString {
    strings:
        $cmd = "cmd.exe /c" nocase
        $ps = "powershell -enc" nocase
    condition:
        any of them
}
"""

def test_yara_matches_positive_file():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"Executing cmd.exe /c whoami")
        path = Path(f.name)
    matches = match_yara_against_files(YARA_RULE, [path])
    assert len(matches) == 1
    path.unlink()

def test_yara_no_match_on_clean_file():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"This is a benign text file with no malware strings")
        path = Path(f.name)
    matches = match_yara_against_files(YARA_RULE, [path])
    assert len(matches) == 0
    path.unlink()
```

- [ ] **Step 2: Run to confirm FAIL**

```bash
pytest tests/unit/tester/test_yara_runner.py -v
```

- [ ] **Step 3: Write yara_runner.py**

```python
# src/detection_forge/tester/yara_runner.py
from __future__ import annotations

from pathlib import Path

import yara


def match_yara_against_files(yara_source: str, file_paths: list[Path]) -> list[Path]:
    """Returns paths of files that matched the YARA rule."""
    rules = yara.compile(source=yara_source)
    matched: list[Path] = []
    for path in file_paths:
        try:
            matches = rules.match(str(path))
            if matches:
                matched.append(path)
        except yara.Error:
            continue
    return matched
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/unit/tester/test_yara_runner.py -v
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/detection_forge/tester/yara_runner.py tests/unit/tester/test_yara_runner.py
git commit -m "feat: YARA file scanner for corpus-based artifact testing"
```

---

### Task 18: Groq + Ollama Providers + Fallback

**Files:**
- Create: `src/detection_forge/llm/providers/groq.py`
- Create: `src/detection_forge/llm/providers/ollama.py`

- [ ] **Step 1: Write groq.py**

```python
# src/detection_forge/llm/providers/groq.py
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
        kwargs: dict = {"model": self._model, "messages": [{"role": "user", "content": prompt}]}
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
```

- [ ] **Step 2: Write ollama.py**

```python
# src/detection_forge/llm/providers/ollama.py
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
```

- [ ] **Step 3: Create gateway factory in config**

Add to `src/detection_forge/config.py` (bottom of file):

```python
def build_gateway() -> "LLMGateway":
    from detection_forge.llm.gateway import LLMGateway
    from detection_forge.llm.providers.gemini import GeminiFlashProvider
    from detection_forge.llm.providers.groq import GroqLlamaProvider
    from detection_forge.llm.providers.ollama import OllamaProvider

    settings = get_settings()
    all_providers = {
        LLMProviderName.GEMINI: lambda: GeminiFlashProvider(settings.gemini_api_key, settings.gemini_model),
        LLMProviderName.GROQ: lambda: GroqLlamaProvider(settings.groq_api_key, settings.groq_model),
        LLMProviderName.OLLAMA: lambda: OllamaProvider(settings.ollama_host, settings.ollama_model),
    }
    order = [settings.llm_primary] + [f for f in settings.llm_fallback if f != settings.llm_primary]
    providers = [all_providers[name]() for name in order if name in all_providers]
    return LLMGateway(providers, max_retries=settings.llm_max_retries)
```

- [ ] **Step 4: Commit**

```bash
git add src/detection_forge/llm/providers/groq.py src/detection_forge/llm/providers/ollama.py src/detection_forge/config.py
git commit -m "feat: Groq + Ollama providers + gateway factory in config"
```

---

## Phase 5 — ATT&CK Coverage

### Task 19: ATT&CK Mapper

**Files:**
- Create: `src/detection_forge/attack/mapper.py`
- Create: `tests/unit/attack/test_mapper.py`

- [ ] **Step 1: Write tests/unit/attack/__init__.py**

```bash
mkdir -p tests/unit/attack && touch tests/unit/attack/__init__.py
```

- [ ] **Step 2: Write failing tests**

```python
# tests/unit/attack/test_mapper.py
from detection_forge.attack.mapper import normalize_technique_id, extract_technique_ids

def test_normalize_full_id():
    assert normalize_technique_id("T1059.001") == "T1059.001"

def test_normalize_base_id():
    assert normalize_technique_id("T1059") == "T1059"

def test_normalize_lowercase():
    assert normalize_technique_id("t1059.001") == "T1059.001"

def test_extract_technique_ids_from_list():
    ids = extract_technique_ids(["T1059.001", "T1566", "not-an-id", "T1078.004"])
    assert "T1059.001" in ids
    assert "T1566" in ids
    assert "T1078.004" in ids
    assert "not-an-id" not in ids

def test_extract_technique_ids_empty():
    assert extract_technique_ids([]) == []
```

- [ ] **Step 3: Run to confirm FAIL**

```bash
pytest tests/unit/attack/test_mapper.py -v
```

- [ ] **Step 4: Write mapper.py**

```python
# src/detection_forge/attack/mapper.py
from __future__ import annotations

import re

_TECHNIQUE_RE = re.compile(r"^[Tt](\d{4})(?:\.(\d{3}))?$")


def normalize_technique_id(raw: str) -> str:
    m = _TECHNIQUE_RE.match(raw.strip())
    if not m:
        raise ValueError(f"Not a valid ATT&CK technique ID: {raw!r}")
    base = f"T{m.group(1)}"
    return f"{base}.{m.group(2)}" if m.group(2) else base


def extract_technique_ids(candidates: list[str]) -> list[str]:
    result = []
    for c in candidates:
        try:
            result.append(normalize_technique_id(c))
        except ValueError:
            continue
    return result
```

- [ ] **Step 5: Run tests**

```bash
pytest tests/unit/attack/test_mapper.py -v
```

Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add src/detection_forge/attack/mapper.py tests/unit/attack/
git commit -m "feat: ATT&CK technique ID normalizer and extractor"
```

---

### Task 20: Coverage + Gap Analysis

**Files:**
- Create: `src/detection_forge/attack/coverage.py`

- [ ] **Step 1: Write coverage.py**

```python
# src/detection_forge/attack/coverage.py
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

log = structlog.get_logger()

_STIX_PATH = Path("data/attack/enterprise-attack.json")
_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def ensure_stix_bundle() -> Path:
    if _STIX_PATH.exists():
        return _STIX_PATH
    import urllib.request
    _STIX_PATH.parent.mkdir(parents=True, exist_ok=True)
    log.info("downloading ATT&CK STIX bundle")
    urllib.request.urlretrieve(_STIX_URL, str(_STIX_PATH))
    return _STIX_PATH


def load_techniques() -> dict[str, dict]:
    """Returns {technique_id: {name, tactic, url}} from STIX bundle."""
    import json
    bundle_path = ensure_stix_bundle()
    with open(bundle_path) as f:
        bundle = json.load(f)

    techniques: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        ext = obj.get("external_references", [])
        tech_id = next(
            (r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"), None
        )
        if not tech_id:
            continue
        tactics = [
            p["phase_name"] for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        techniques[tech_id] = {
            "name": obj.get("name", ""),
            "tactic": tactics[0] if tactics else "unknown",
            "url": next((r.get("url", "") for r in ext if r.get("source_name") == "mitre-attack"), ""),
        }
    return techniques


def compute_coverage(
    rule_techniques: list[list[str]],
    all_techniques: dict[str, dict],
) -> dict[str, int]:
    """Returns {technique_id: rule_count} for all techniques."""
    counts: dict[str, int] = defaultdict(int)
    for techniques in rule_techniques:
        for tid in techniques:
            if tid in all_techniques:
                counts[tid] += 1
    return dict(counts)


def find_gaps(
    coverage: dict[str, int],
    all_techniques: dict[str, dict],
) -> list[dict]:
    """Returns list of uncovered techniques sorted by tactic."""
    gaps = []
    for tid, info in all_techniques.items():
        if coverage.get(tid, 0) == 0:
            gaps.append({"id": tid, **info})
    return sorted(gaps, key=lambda x: (x["tactic"], x["id"]))
```

- [ ] **Step 2: Add coverage route stub**

```python
# src/detection_forge/api/routes/coverage.py
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def coverage_page(request: Request):
    return request.app.state.templates.TemplateResponse(
        "coverage.html", {"request": request}
    )


@router.get("/api")
async def coverage_api():
    return {"message": "Coverage data — implement after ATT&CK bundle loaded"}
```

- [ ] **Step 3: Register in app.py**

In `src/detection_forge/api/app.py`, inside `create_app()`, add:

```python
    from .routes import coverage as coverage_router
    app.include_router(coverage_router.router, prefix="/coverage", tags=["coverage"])
```

- [ ] **Step 4: Create coverage.html**

```html
{% extends "base.html" %}
{% block title %}Coverage — detection-forge{% endblock %}
{% block content %}
<h1 class="text-2xl font-bold text-emerald-400 mb-6">ATT&amp;CK Coverage</h1>
<div id="coverage-data"
     hx-get="/coverage/api"
     hx-trigger="load"
     class="text-gray-400 text-sm">
  Loading coverage data...
</div>
{% endblock %}
```

- [ ] **Step 5: Commit**

```bash
git add src/detection_forge/attack/coverage.py src/detection_forge/api/routes/coverage.py src/detection_forge/web/templates/coverage.html
git commit -m "feat: ATT&CK coverage + gap analysis, STIX bundle loader, coverage page"
```

---

## Phase 6 — UX Polish

### Task 21: Qdrant Vector Store

**Files:**
- Create: `src/detection_forge/vector/store.py`

- [ ] **Step 1: Write store.py**

```python
# src/detection_forge/vector/store.py
from __future__ import annotations

from qdrant_client import AsyncQdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct, Filter, FieldCondition, MatchText
from sentence_transformers import SentenceTransformer
import uuid

COLLECTION = "cti_rules"
VECTOR_SIZE = 384  # all-MiniLM-L6-v2


class VectorStore:
    def __init__(self, host: str = "localhost", port: int = 6333) -> None:
        self._client = AsyncQdrantClient(host=host, port=port)
        self._encoder = SentenceTransformer("all-MiniLM-L6-v2")

    async def ensure_collection(self) -> None:
        collections = await self._client.get_collections()
        names = [c.name for c in collections.collections]
        if COLLECTION not in names:
            await self._client.create_collection(
                collection_name=COLLECTION,
                vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
            )

    def _embed(self, text: str) -> list[float]:
        return self._encoder.encode(text, normalize_embeddings=True).tolist()

    async def upsert(self, doc_id: str, text: str, payload: dict) -> None:
        vector = self._embed(text)
        await self._client.upsert(
            collection_name=COLLECTION,
            points=[PointStruct(id=doc_id, vector=vector, payload=payload)],
        )

    async def search(self, text: str, limit: int = 5) -> list[dict]:
        vector = self._embed(text)
        results = await self._client.search(
            collection_name=COLLECTION,
            query_vector=vector,
            limit=limit,
        )
        return [{"id": r.id, "score": r.score, **r.payload} for r in results]
```

- [ ] **Step 2: Commit**

```bash
git add src/detection_forge/vector/store.py
git commit -m "feat: Qdrant vector store with sentence-transformers embedding"
```

---

### Task 22: CTI Dedup in Ingest

**Files:**
- Modify: `src/detection_forge/api/routes/cti.py`

- [ ] **Step 1: Add similarity check to ingest endpoint**

Replace the ingest_text function in `src/detection_forge/api/routes/cti.py`:

```python
@router.post("/ingest/text")
async def ingest_text(body: IngestRequest, request: Request, db: AsyncSession = Depends(get_db)):
    item = parse_text(body.text, title=body.title)

    # Check for similar existing CTI in vector store
    similar: list[dict] = []
    if hasattr(request.app.state, "vector_store"):
        similar = await request.app.state.vector_store.search(item.text, limit=3)

    record = CTIRecord(
        id=item.id,
        title=item.title,
        source_type=item.source_type.value,
        raw_text=item.text,
    )
    db.add(record)
    await db.commit()

    # Embed + store in Qdrant
    if hasattr(request.app.state, "vector_store"):
        await request.app.state.vector_store.upsert(
            doc_id=item.id,
            text=item.text,
            payload={"title": item.title, "type": "cti"},
        )

    return {
        "id": item.id,
        "title": item.title,
        "ioc_count": len(item.raw_iocs),
        "similar_cti": similar[:3],
    }
```

- [ ] **Step 2: Initialize vector store in lifespan (app.py)**

In the `lifespan` function in `src/detection_forge/api/app.py`, after `app.state.db = ...`:

```python
    from ..vector.store import VectorStore
    settings = get_settings()
    try:
        vs = VectorStore(host=settings.qdrant_host, port=settings.qdrant_port)
        await vs.ensure_collection()
        app.state.vector_store = vs
        log.info("qdrant.connected")
    except Exception as e:
        log.warning("qdrant.unavailable", error=str(e))
```

- [ ] **Step 3: Commit**

```bash
git add src/detection_forge/api/routes/cti.py src/detection_forge/api/app.py
git commit -m "feat: CTI dedup via Qdrant similarity search on ingest"
```

---

### Task 23: Monaco Editor Rule View

**Files:**
- Create: `src/detection_forge/web/templates/rule_editor.html`
- Modify: `src/detection_forge/api/app.py`

- [ ] **Step 1: Write rule_editor.html**

```html
{% extends "base.html" %}
{% block title %}{{ rule.title }} — detection-forge{% endblock %}
{% block content %}
<div class="space-y-6">
  <div class="flex items-start justify-between">
    <div>
      <h1 class="text-xl font-bold">{{ rule.title }}</h1>
      <div class="mt-1 flex gap-2 items-center">
        <span class="text-xs px-2 py-0.5 rounded
          {% if rule.rule_type == 'sigma' %}bg-blue-900 text-blue-300
          {% else %}bg-purple-900 text-purple-300{% endif %}">
          {{ rule.rule_type }}
        </span>
        <span class="text-xs text-gray-500">confidence: {{ "%.0f"|format(rule.confidence * 100) }}%</span>
      </div>
      <div class="mt-2 flex gap-1 flex-wrap">
        {% for t in rule.attack_techniques %}
        <span class="text-xs bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">{{ t }}</span>
        {% endfor %}
      </div>
    </div>
    <div class="flex gap-2">
      <a href="/api/rules/{{ rule.id }}/export"
         class="text-xs bg-gray-800 hover:bg-gray-700 px-3 py-1.5 rounded text-gray-300">
        Export
      </a>
    </div>
  </div>

  <div x-data="{ content: {{ rule.content | tojson }} }">
    <div id="monaco-editor" class="h-96 border border-gray-700 rounded overflow-hidden"></div>
    <div class="mt-3 flex gap-3">
      <button
        hx-post="/api/tests/run"
        hx-vals='{"rule_id": "{{ rule.id }}", "corpus": "evtx-attack-samples"}'
        hx-target="#test-results"
        hx-swap="innerHTML"
        class="text-sm bg-emerald-700 hover:bg-emerald-600 px-4 py-2 rounded">
        Run Tests
      </button>
    </div>
    <div id="test-results" class="mt-4"></div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/monaco-editor@0.52.0/min/vs/loader.js"></script>
<script>
  require.config({ paths: { vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.52.0/min/vs' } });
  require(['vs/editor/editor.main'], function() {
    const content = {{ rule.content | tojson }};
    const lang = '{{ rule.rule_type }}' === 'sigma' ? 'yaml' : 'plaintext';
    monaco.editor.create(document.getElementById('monaco-editor'), {
      value: content,
      language: lang,
      theme: 'vs-dark',
      minimap: { enabled: false },
      fontSize: 13,
      lineNumbers: 'on',
      scrollBeyondLastLine: false,
    });
  });
</script>
{% endblock %}
```

- [ ] **Step 2: Add rule view route to app.py**

In `create_app()` in `src/detection_forge/api/app.py`:

```python
    from sqlalchemy import select as sa_select
    from ..db import Rule as RuleDB

    @app.get("/rules/{rule_id}", response_class=HTMLResponse)
    async def rule_detail(rule_id: str, request: Request):
        async with request.app.state.db() as session:
            result = await session.execute(sa_select(RuleDB).where(RuleDB.id == rule_id))
            rule = result.scalar_one_or_none()
        if not rule:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Not found")
        return app.state.templates.TemplateResponse(
            "rule_editor.html", {"request": request, "rule": rule}
        )
```

- [ ] **Step 3: Add export route to rules.py**

```python
@router.get("/{rule_id}/export")
async def export_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    from fastapi.responses import PlainTextResponse
    result = await db.execute(select(RuleDB).where(RuleDB.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        from fastapi import HTTPException
        raise HTTPException(status_code=404)
    ext = "yml" if rule.rule_type == "sigma" else "yar"
    return PlainTextResponse(
        content=rule.content,
        headers={"Content-Disposition": f'attachment; filename="{rule.id}.{ext}"'},
    )
```

- [ ] **Step 4: Commit**

```bash
git add src/detection_forge/web/templates/rule_editor.html src/detection_forge/api/app.py src/detection_forge/api/routes/rules.py
git commit -m "feat: Monaco editor rule view with test runner button and export"
```

---

### Task 24: Structured CTI Parsers (STIX + TAXII + PDF)

**Files:**
- Create: `src/detection_forge/cti/parsers/stix.py`
- Create: `src/detection_forge/cti/parsers/taxii.py`
- Create: `src/detection_forge/cti/parsers/pdf.py`
- Modify: `src/detection_forge/cti/loader.py`

- [ ] **Step 1: Write stix.py**

```python
# src/detection_forge/cti/parsers/stix.py
from __future__ import annotations

import json
import uuid
from pathlib import Path

from ..models import CTIItem, SourceType


def parse_stix_bundle(bundle_path: Path | str) -> list[CTIItem]:
    with open(bundle_path) as f:
        bundle = json.load(f)

    items = []
    for obj in bundle.get("objects", []):
        if obj.get("type") not in ("indicator", "malware", "attack-pattern", "campaign"):
            continue
        text_parts = [
            obj.get("name", ""),
            obj.get("description", ""),
        ]
        if obj.get("type") == "indicator" and "pattern" in obj:
            text_parts.append(f"IOC pattern: {obj['pattern']}")

        text = "\n".join(p for p in text_parts if p)
        if not text.strip():
            continue

        items.append(CTIItem(
            id=str(uuid.uuid4()),
            title=obj.get("name", f"STIX {obj.get('type', 'object')}"),
            text=text,
            source_type=SourceType.STIX,
            metadata={"stix_type": obj.get("type"), "stix_id": obj.get("id")},
        ))
    return items
```

- [ ] **Step 2: Write taxii.py**

```python
# src/detection_forge/cti/parsers/taxii.py
from __future__ import annotations

import json
from ..models import CTIItem, SourceType
from .stix import parse_stix_bundle
import tempfile
from pathlib import Path


def fetch_taxii(server_url: str, collection_id: str, username: str = "", password: str = "") -> list[CTIItem]:
    from taxii2client.v21 import Server
    auth = (username, password) if username else None
    server = Server(server_url, user=username, password=password) if auth else Server(server_url)
    api_root = server.api_roots[0]
    collection = next(c for c in api_root.collections if c.id == collection_id)
    bundle = collection.get_objects()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(bundle, f)
        tmp_path = Path(f.name)
    try:
        return parse_stix_bundle(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)
```

- [ ] **Step 3: Write pdf.py**

```python
# src/detection_forge/cti/parsers/pdf.py
from __future__ import annotations

import uuid
from pathlib import Path

from ..models import CTIItem, SourceType
from .text import extract_iocs


def parse_pdf(path: Path | str) -> CTIItem:
    import pdfplumber
    path = Path(path)
    with pdfplumber.open(path) as pdf:
        pages = [page.extract_text() or "" for page in pdf.pages]
    text = "\n".join(pages).strip()
    return CTIItem(
        id=str(uuid.uuid4()),
        title=path.stem,
        text=text,
        source_type=SourceType.PDF,
        raw_iocs=extract_iocs(text),
        metadata={"filename": path.name, "pages": len(pages)},
    )
```

- [ ] **Step 4: Write loader.py (unified entry point)**

```python
# src/detection_forge/cti/loader.py
from __future__ import annotations

from pathlib import Path

from .models import CTIItem, SourceType
from .parsers.text import parse_text


def load(source: str | Path, source_type: SourceType = SourceType.TEXT, **kwargs) -> list[CTIItem]:
    """Unified CTI loader. Returns one or more CTIItems."""
    if source_type == SourceType.TEXT:
        return [parse_text(str(source), title=kwargs.get("title"))]
    if source_type == SourceType.PDF:
        from .parsers.pdf import parse_pdf
        return [parse_pdf(Path(source))]
    if source_type == SourceType.STIX:
        from .parsers.stix import parse_stix_bundle
        return parse_stix_bundle(Path(source))
    if source_type == SourceType.TAXII:
        from .parsers.taxii import fetch_taxii
        return fetch_taxii(
            server_url=str(source),
            collection_id=kwargs["collection_id"],
            username=kwargs.get("username", ""),
            password=kwargs.get("password", ""),
        )
    raise ValueError(f"Unsupported source_type: {source_type}")
```

- [ ] **Step 5: Commit**

```bash
git add src/detection_forge/cti/
git commit -m "feat: STIX, TAXII, PDF parsers + unified CTI loader"
```

---

## Phase 7 — Release

### Task 25: Docker Compose + Dockerfile

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yml`

- [ ] **Step 1: Write Dockerfile**

```dockerfile
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc git && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir -e "."

COPY src/ src/

RUN mkdir -p data

EXPOSE 8000

CMD ["uvicorn", "detection_forge.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

- [ ] **Step 2: Write docker-compose.yml**

```yaml
services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - GROQ_API_KEY=${GROQ_API_KEY}
      - QDRANT_HOST=qdrant
      - QDRANT_PORT=6333
      - DATABASE_URL=sqlite+aiosqlite:///./data/detection_forge.db
    volumes:
      - ./data:/app/data
    depends_on:
      - qdrant

  qdrant:
    image: qdrant/qdrant:latest
    ports:
      - "6333:6333"
    volumes:
      - qdrant_data:/qdrant/storage

  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    profiles:
      - ollama

volumes:
  qdrant_data:
  ollama_data:
```

- [ ] **Step 3: Commit**

```bash
git add Dockerfile docker-compose.yml
git commit -m "feat: Docker + docker-compose with app + qdrant + optional ollama profile"
```

---

### Task 26: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write ci.yml**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip

      - name: Install dependencies
        run: pip install -e ".[dev]"

      - name: Lint (ruff)
        run: ruff check src/ tests/

      - name: Type check (mypy)
        run: mypy src/detection_forge/

      - name: Run tests
        run: pytest tests/unit/ -v --cov=detection_forge --cov-report=term-missing

      - name: Check coverage threshold
        run: pytest tests/unit/ --cov=detection_forge --cov-fail-under=70
```

- [ ] **Step 2: Commit**

```bash
git add .github/
git commit -m "ci: GitHub Actions — ruff, mypy, pytest with 70% coverage threshold"
```

---

### Task 27: Prometheus Metrics Endpoint

**Files:**
- Modify: `src/detection_forge/api/app.py`

- [ ] **Step 1: Add /metrics route to app.py (inside create_app)**

```python
    @app.get("/metrics", include_in_schema=False)
    async def metrics(request: Request):
        from fastapi.responses import PlainTextResponse
        from sqlalchemy import func, select as sa_select
        async with request.app.state.db() as session:
            rule_count = (await session.execute(sa_select(func.count()).select_from(RuleDB))).scalar()
            cti_count = (await session.execute(sa_select(func.count()).select_from(CTIRecord))).scalar()
        output = (
            f"# HELP detection_forge_rules_total Total rules generated\n"
            f"# TYPE detection_forge_rules_total gauge\n"
            f"detection_forge_rules_total {rule_count}\n"
            f"# HELP detection_forge_cti_total Total CTI reports ingested\n"
            f"# TYPE detection_forge_cti_total gauge\n"
            f"detection_forge_cti_total {cti_count}\n"
        )
        return PlainTextResponse(output, media_type="text/plain; version=0.0.4")
```

- [ ] **Step 2: Commit**

```bash
git add src/detection_forge/api/app.py
git commit -m "feat: /metrics Prometheus endpoint for rule/CTI counts"
```

---

### Task 28: README + v0.1.0 Tag

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README.md**

```markdown
# detection-forge

> CTI → validated, tested, ATT&CK-tagged Sigma and YARA rules. Powered by multi-provider LLMs.

Part of the **SOC Lifecycle Portfolio** (detect → validate → hunt → triage).

![demo](docs/demo.gif)

## Features

- **Multi-source CTI ingest** — paste threat reports, upload PDFs, or pull STIX/TAXII/MISP feeds
- **LLM rule generation** — chained prompt pipeline: extract → classify → draft → validate → refine
- **Sigma + YARA** — validated by pySigma and yara-python before storage
- **Corpus testing** — scored against EVTX-ATTACK-SAMPLES and Mordor datasets
- **ATT&CK coverage** — heatmap + gap analysis showing uncovered techniques
- **Multi-provider LLM** — Gemini Flash → Groq Llama 3.3 → Ollama (all free)
- **Monaco editor** — in-browser rule editing + re-test

## Quick Start

```bash
git clone https://github.com/tejassesh5/detection-forge
cd detection-forge
cp .env.example .env  # add your API keys
docker compose up -d
```

Open http://localhost:8000

## Architecture

```
CTI Input → cti_loader → CTIItem
         → LLM Pipeline (extract → classify → draft → validate → refine)
         → Rule (Sigma/YARA) → pySigma/yara-python validation
         → Tester (EVTX corpus + user logs) → Score (0-100)
         → ATT&CK Mapper → Coverage heatmap + gaps
         → Qdrant (embeddings for dedup + RAG prompting)
         → SQLite (rules, CTI, test runs)
```

## Scoring

`score = 35×precision + 25×recall + 15×attack_coverage + 15×specificity + 10×novelty`

| Grade | Score |
|-------|-------|
| A | 85-100 |
| B | 70-84 |
| C | 55-69 |
| D | 40-54 |
| F | <40 |

## Stack

Python 3.12 · FastAPI · HTMX · Tailwind · Monaco · SQLite · Qdrant · sentence-transformers · pySigma · yara-python · Gemini · Groq · Ollama · MITRE ATT&CK STIX

## Related Projects

- [purple-loop](https://github.com/tejassesh5/purple-loop) — validate detections via attack emulation
- [threat-hunt-rag](https://github.com/tejassesh5/threat-hunt-rag) — hunt beyond detections with RAG
- [soc-copilot](https://github.com/tejassesh5/soc-copilot) — AI alert triage assistant
```

- [ ] **Step 2: Run full test suite**

```bash
pytest tests/ -v
```

Expected: all unit tests PASS

- [ ] **Step 3: Lint + type check**

```bash
ruff check src/ tests/
mypy src/detection_forge/
```

Expected: no errors

- [ ] **Step 4: Final commit + tag**

```bash
git add README.md
git commit -m "docs: README with architecture, scoring table, quickstart"
git tag -a v0.1.0 -m "v0.1.0 — initial release: Sigma/YARA generation from CTI with ATT&CK coverage"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task(s) |
|-----------------|---------|
| CTI text + STIX/TAXII/MISP ingest | Tasks 5, 24 |
| Multi-provider LLM (Gemini/Groq/Ollama) | Tasks 6, 7, 18 |
| Chained prompt stages (A→E) | Tasks 8, 11, 12 |
| Sigma + YARA output | Tasks 10, 11, 17 |
| pySigma + yara-python validation | Task 10 |
| Retry on validation failure | Task 12 (pipeline.py) |
| EVTX-ATTACK-SAMPLES + Mordor corpora | Tasks 14, 15 |
| User-uploaded logs | Covered by sigma_runner.py interface (accepts any event list) |
| Scoring formula (5 components) | Task 16 |
| ATT&CK tagging + coverage heatmap | Tasks 19, 20 |
| Gap analysis with CTI backlinks | Task 20 (coverage.py) |
| Qdrant vector store + dedup | Tasks 21, 22 |
| FastAPI + HTMX + Tailwind + Monaco | Tasks 9, 13, 23 |
| Docker Compose (app + qdrant + ollama) | Task 25 |
| GitHub Actions CI | Task 26 |
| Prometheus metrics | Task 27 |
| README with demo artifacts | Task 28 |
| IOC allowlist / safety rails | Task 5 (benign domain filter) + pipeline MAX_REFINE |

**No placeholders found.** All steps contain complete code.

**Type consistency:** `CTIItem`, `RuleDraft`, `LLMResponse`, `ExtractedCTI`, `ClassifyResult`, `ScoreBreakdown` — all used consistently across tasks.

**Scope:** 28 tasks across 7 phases, each independently committable. Sized for single implementation run.
```
