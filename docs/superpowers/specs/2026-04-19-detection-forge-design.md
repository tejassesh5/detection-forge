# detection-forge — Design Spec

**Date:** 2026-04-19
**Status:** Draft → pending user review
**Owner:** tejas (`tejassesh5`)
**Related projects:** part of 4-project SOC Lifecycle portfolio arc

---

## 1. Context: SOC Lifecycle Portfolio Arc

Four linked repos telling a full SOC story: **detect → validate → hunt → triage**.

| # | Project | Role | Key Tech |
|---|---------|------|----------|
| 1 | **detection-forge** *(this spec)* | Build detections from CTI → Sigma/YARA | FastAPI + HTMX + Qdrant + multi-LLM |
| 2 | **purple-loop** | Validate detections (attack sim + coverage) | Atomic Red Team + Caldera + Elastic |
| 3 | **threat-hunt-rag** | Hunt beyond detections (RAG over logs + CTI) | LangGraph/LlamaIndex + Qdrant + Gemini |
| 4 | **soc-copilot** | Triage + respond (AI analyst on alerts) | MCP server + Claude API + Elastic webhook |

Build order: 1 → 2 → 3 → 4. After #2, extract shared code (`llm`, `attack`, `vector`) into `soc-core` package.

---

## 2. Goal

Turn raw threat intelligence (CTI reports, STIX/TAXII feeds, MISP events) into validated, scored, ATT&CK-tagged Sigma and YARA detection rules — via an LLM pipeline with provider fallback, structural validation, corpus-based testing, and a coverage/gap dashboard.

**Target user:** SOC analyst or detection engineer who reads a threat report and wants a tested rule ready to ship, with a view of current coverage gaps.

**Not in scope:** live log streaming, SIEM deployment, alert triage, attack emulation (all owned by sibling projects).

---

## 3. Design Decisions (locked during brainstorming)

| Decision | Choice | Reason |
|----------|--------|--------|
| Input sources | Raw CTI text + structured feeds (STIX/TAXII, MISP) | Covers both manual (blog) and automated (feed) ingestion |
| Rule formats | Sigma + YARA | SIEM logs + file/memory artifact coverage; industry standard 2026 |
| Testing | Public corpora (EVTX-ATTACK-SAMPLES, Mordor) + user-uploaded logs | Reproducible benchmark + practical workflow; live emulation deferred to purple-loop |
| LLM | Multi-provider (Gemini 2.5 Flash → Groq Llama 3.3 → Ollama Qwen 2.5) | All free; provider-agnostic design; recruiter demo works without API key |
| Interface | Web UI primary (FastAPI + HTMX + Alpine + Tailwind + Monaco) | Screenshot/GIF-worthy demo; no node build pipeline; CLI via API routes |
| Storage | SQLite (structured) + Qdrant (embeddings, docker) | Zero-ops + vector similarity for dedup + reusable in project #3 |
| Deployment | Local-first `docker compose up` + polished README artifacts (GIF, diagrams) | Free-tier hosting unreliable in 2026; app too heavy for free tier anyway |
| ATT&CK depth | Tag + coverage heatmap + gap analysis (with CTI backlinks) | SOC managers care about coverage gaps, not rule counts |

---

## 4. Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  detection-forge (web)                   │
│  FastAPI + HTMX + Alpine + Tailwind + Monaco editor      │
└──────────────────────────────────────────────────────────┘
           │
   ┌───────┼────────┬─────────┬──────────┬──────────┐
   ▼       ▼        ▼         ▼          ▼          ▼
┌──────┐ ┌─────┐ ┌──────┐ ┌────────┐ ┌────────┐ ┌──────┐
│ CTI  │ │ LLM │ │ Rule │ │ Tester │ │ATT&CK  │ │Vector│
│Loader│ │Gate │ │Forge │ │        │ │Mapper  │ │Store │
└──────┘ └─────┘ └──────┘ └────────┘ └────────┘ └──────┘
   │       │        │         │          │          │
   ▼       ▼        ▼         ▼          ▼          ▼
 STIX/   Gemini/  Sigma/    EVTX+    MITRE       Qdrant
 TAXII/  Groq/    YARA      Mordor   STIX        (embeddings)
 MISP/   Ollama             +user    bundle
 text                       logs
                      │
                      ▼
                   SQLite (rules, runs, scores, CTI cache)
```

### Modules (clear boundaries)

| Module | Responsibility | Public interface |
|--------|----------------|------------------|
| `cti_loader` | Parse raw text / STIX / TAXII / MISP → normalized `CTIItem` | `load(source) → CTIItem` |
| `llm_gateway` | Provider abstraction + retry + fallback + cost/token log | `generate(prompt, schema) → dict` |
| `rule_forge` | Orchestrate CTI → LLM stages → validated rule | `forge(cti) → Rule` |
| `tester` | Run rule against corpus; capture tp/fp + scoring | `test(rule, corpus) → TestResult` |
| `attack_mapper` | Tag rule with ATT&CK; compute coverage + gaps | `tag(rule)`, `coverage()`, `gaps()` |
| `vector_store` | Qdrant client; embed CTI + rules; dedup/similarity | `upsert/search(text) → [match]` |
| `api` | FastAPI routes + HTMX partials | REST + HTML |
| `web` | Templates, static, Monaco embed | Jinja2 |

Each module is independently testable. Consumers depend on interfaces, not internals.

---

## 5. Data Flow

### 5.1 Ingest

```
User pastes blog/report OR uploads PDF OR pulls TAXII feed
    → cti_loader → CTIItem { id, title, text, source, raw_iocs[] }
    → embed (sentence-transformers MiniLM-L6-v2) → Qdrant upsert
    → vector_store.search(new CTI) → "3 similar CTI items already processed"
      (shown in UI as context)
```

### 5.2 Forge

```
rule_forge.forge(CTIItem):
  Stage A — EXTRACT:  LLM → { ttps[], iocs[], attack_techniques[], detection_hints }
  Stage B — CLASSIFY: LLM → { rule_type: sigma|yara|both, log_source: sysmon|... }
  Stage C — DRAFT:    LLM → { rule_yaml_or_yar, title, description, level, confidence }
                      (few-shot examples retrieved via Qdrant similarity to TTPs)
  Stage D — VALIDATE: pySigma.parse() or yara.compile()
                      if fail: REFINE stage (max 2 retries, error injected into prompt)
  Stage E — TAG:      attack_mapper.tag() via LLM + STIX bundle for canonical IDs
  → Rule persisted to SQLite
```

### 5.3 Test

```
tester.test(rule, corpus="evtx-attack-samples"):
  Sigma path: pySigma.convert(backend="elasticsearch_lucene") → match against corpus events
              → also run against benign-baseline for FP
  YARA path:  yara.compile() → scan file samples
  → TestResult { tp_count, fp_count, matched_samples[], precision, recall, coverage_score }
  → SQLite
```

### 5.4 Score + Surface

```
score = 35*precision + 25*recall + 15*attack_coverage + 15*specificity + 10*novelty

attack_mapper.coverage() → ATT&CK matrix heatmap (tactics × techniques)
attack_mapper.gaps()     → uncovered techniques + "CTI mentioning them"
```

UI: rule list sortable by score; radar chart per rule; coverage heatmap; gap dashboard with CTI backlinks.

### 5.5 Secondary flows

- User uploads own logs → `tester.test(rule, user_logs)` → ad-hoc result
- Monaco editor rule edit → re-test button → re-score
- Export: single rule YAML/YAR, or bundle zip with ATT&CK manifest

---

## 6. LLM Pipeline

### 6.1 Provider abstraction

```python
class LLMProvider(Protocol):
    name: str
    cost_per_1k_in: float
    def generate(self, prompt: str, schema: dict | None) -> dict | str: ...

providers = [GeminiFlash(), GroqLlama33(), OllamaLocal()]
# Config-driven primary; auto-fallback on 429 / 5xx / timeout
```

### 6.2 Structured output

- Gemini: native `response_schema`
- Groq: `response_format={"type": "json_object"}` + schema-in-prompt
- Ollama: `format="json"` + schema-in-prompt + Pydantic validator retry
- All paths converge on a Pydantic `RuleDraft` model. Invalid output → retry with error injected (max 2).

### 6.3 Chained stages (not one mega-prompt)

| Stage | Input | Output | Rationale |
|-------|-------|--------|-----------|
| Extract | raw CTI text | `{ttps, iocs, behaviors, targets, attack_techniques}` | Small, cheap, reusable in project #3 |
| Classify | extracted | `{rule_type, log_source}` | Picks right template + scope |
| Draft | extracted + classification + few-shot | `{rule, title, description, level, confidence}` | Main generation |
| Refine | draft + validator errors | corrected rule | Conditional (only if validation fails) |

### 6.4 Few-shot library

- 20–30 curated Sigma+YARA pairs in `prompts/examples/*.yml`
- Retrieved via Qdrant similarity to extracted TTPs (RAG-lite for prompting)
- Bounds prompt size; best examples per CTI

### 6.5 Prompt caching

- System prompt + few-shot template = cached (Gemini explicit cache / Anthropic ephemeral / Ollama KV-cache)
- Per-CTI portion = uncached
- Cost/latency logged to SQLite for README metrics

### 6.6 Safety rails

- IOC allowlist strip (google.com, microsoft.com, internal corp domains) → prevent rules firing on benign infra
- Validator rejects rules with unbounded wildcards on `CommandLine` (overly broad)
- Max output tokens capped per stage

---

## 7. Testing + Scoring

### 7.1 Corpora

| Corpus | Content | Size | Use |
|--------|---------|------|-----|
| EVTX-ATTACK-SAMPLES | Windows event logs (ATT&CK-mapped) | ~300 .evtx | Sigma TP test |
| Security-Datasets (Mordor) | JSON logs, Atomic Red Team runs | ~50 datasets | Sigma multi-source |
| theZoo / MalwareBazaar | Malware samples (hash-pull, not committed) | on-demand | YARA TP test |
| benign-baseline | Normal Windows/sysmon logs (self-generated) | ~10k events | FP test |

Repo ships **pull scripts only**, not corpus data (license + size).

### 7.2 Scoring formula

```
score (0–100) = 35*precision
              + 25*recall
              + 15*attack_coverage   (distinct techniques matched)
              + 15*specificity       (field count; wildcard penalty)
              + 10*novelty           (1 - max_similarity_to_existing_rule)
```

Displayed as radar chart + overall grade (A/B/C/D/F).

### 7.3 Coverage + gaps

- MITRE ATT&CK STIX bundle (v14+) loaded at startup
- Matrix mapping `technique_id → [rule_id...]`
- **Heatmap:** tactics columns × techniques rows; cell color by rule count
- **Gap analysis:** for each uncovered technique, match against ingested CTI via embedding similarity → surfaces "CTI `APT29 SolarWinds` mentions T1078.004 but you have 0 rules"

### 7.4 CI

- GitHub Actions on every push: ruff, mypy, pytest, full test-suite against corpora
- Benchmarks tracked over commits: avg generation time, avg score, total coverage

---

## 8. Tech Stack

| Layer | Tech | Reason |
|-------|------|--------|
| Backend | Python 3.12, FastAPI, Uvicorn | Async, auto OpenAPI |
| Frontend | Jinja2 + HTMX 2.x + Alpine 3 + Tailwind 4 + Monaco | No node build; pro UX |
| ORM | SQLAlchemy 2 + SQLite (aiosqlite) | Simple, typed, async |
| Vector | Qdrant (docker) + sentence-transformers MiniLM-L6-v2 | Local, free, fast |
| LLM | Gemini 2.5 Flash + Groq Llama 3.3 + Ollama Qwen 2.5 | Multi-provider, all free |
| Rule libs | pySigma, pySigma-backend-elasticsearch, yara-python | Canonical |
| CTI parse | stix2, taxii2-client, pymisp, pdfplumber | Battle-tested |
| ATT&CK | mitreattack-python | Official STIX loader |
| Testing | pytest, pytest-asyncio, hypothesis | Standard |
| Infra | Docker Compose (app + qdrant + optional ollama profile) | Matches siem-lab pattern |
| CI | GitHub Actions: ruff, mypy, pytest, build-image | Portfolio polish |
| Observability | structlog → stdout, SQLite cost/latency table, `/metrics` Prometheus endpoint | Dashboard-able |

---

## 9. Repo Layout

```
detection-forge/
├── README.md                  # hero GIF, arch diagram, quickstart, scoring explained
├── docker-compose.yml         # app + qdrant + ollama (profile)
├── Dockerfile
├── pyproject.toml             # uv/pip
├── .github/workflows/ci.yml
├── docs/
│   ├── architecture.md
│   ├── scoring.md
│   └── adr/                   # decision records
├── src/detection_forge/
│   ├── __init__.py
│   ├── config.py              # pydantic-settings
│   ├── db.py                  # SQLAlchemy models + session
│   ├── cti/
│   │   ├── loader.py
│   │   ├── parsers/           # text.py, pdf.py, stix.py, taxii.py, misp.py
│   │   └── models.py
│   ├── llm/
│   │   ├── gateway.py
│   │   ├── providers/         # gemini.py, groq.py, ollama.py
│   │   ├── prompts/           # extract.j2, classify.j2, draft.j2, refine.j2
│   │   └── examples/          # few-shot YAML library
│   ├── forge/
│   │   ├── pipeline.py
│   │   └── validator.py
│   ├── tester/
│   │   ├── sigma_runner.py
│   │   ├── yara_runner.py
│   │   ├── corpus.py
│   │   └── scoring.py
│   ├── attack/
│   │   ├── mapper.py
│   │   └── coverage.py
│   ├── vector/
│   │   └── store.py
│   ├── api/
│   │   ├── app.py
│   │   ├── routes/            # cti.py, rules.py, tests.py, coverage.py
│   │   └── partials/          # HTMX HTML responses
│   └── web/
│       ├── templates/
│       └── static/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   └── conftest.py
├── scripts/
│   ├── pull_corpora.py
│   ├── bootstrap_examples.py
│   └── demo_cli.py
└── data/                      # gitignored: corpora/, db.sqlite, qdrant/
```

---

## 10. Milestones

1. **Skeleton** — FastAPI app, SQLite schema, CTI text loader, Gemini provider, extract-stage prompt → "generates any output end-to-end"
2. **Sigma path** — classify + draft + pySigma validation + retry loop → "generates valid Sigma from pasted text"
3. **Test loop** — EVTX corpus pull script + Sigma runner + scoring → "scores rules end-to-end"
4. **YARA path + multi-provider** — YARA runner, Groq + Ollama providers with fallback
5. **ATT&CK** — mapper, coverage heatmap, gap analysis UI
6. **UX polish** — Monaco editor, rule refinement loop, export bundle
7. **Release** — CI green, docs, demo GIF, README polish, v0.1.0 tag

---

## 11. Risks + Mitigations

| Risk | Mitigation |
|------|------------|
| LLM generates plausible-but-wrong rules | Multi-stage validation (pySigma parse, yara compile, corpus test) before surfacing |
| Gemini free tier quota hits (history: user had quota=0) | Multi-provider fallback; Ollama as zero-API floor |
| False positives on benign logs | Dedicated benign-baseline corpus in FP scoring; IOC allowlist |
| Corpus size blows up repo | Pull scripts only; `.gitignore` data dir |
| pySigma backend conversion edge cases | Start with elasticsearch_lucene; add backends incrementally |
| Prompt drift over model versions | Pin model IDs in config; CI benchmark detects regressions |

---

## 12. Open Questions (not blocking; decide during implementation)

- Rate-limit strategy when pulling TAXII feeds (per-feed backoff)
- Whether to store full CTI text or summary+hash (size vs fidelity)
- Authentication — single-user local for v1; multi-user deferred
- Whether to run Qdrant embedded vs docker (currently docker; embedded via fastembed is an option for simplicity)

---

## 13. Review Notes

Spec self-review completed:
- No TBD / TODO / placeholders
- Internal consistency: architecture matches modules matches data flow
- Scope: sized for single implementation plan with 7 milestones
- Ambiguity: each decision has a single explicit value; alternatives noted only in open questions

**Next step:** user reviews this spec. On approval, invoke `superpowers:writing-plans` to produce phased implementation plan.
