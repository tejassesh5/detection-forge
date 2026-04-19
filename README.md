# detection-forge

> CTI → validated, tested, ATT&CK-tagged Sigma and YARA rules. Powered by multi-provider LLMs.

Part of the **SOC Lifecycle Portfolio** (detect → validate → hunt → triage).

## Features

- **Multi-source CTI ingest** — paste threat reports, upload PDFs, or pull STIX/TAXII/MISP feeds
- **LLM rule generation** — chained prompt pipeline: extract → classify → draft → validate → refine
- **Sigma + YARA** — validated by pySigma and yara-python before storage
- **Corpus testing** — scored against EVTX-ATTACK-SAMPLES and Mordor datasets
- **ATT&CK coverage** — heatmap + gap analysis showing uncovered techniques
- **Multi-provider LLM** — Gemini Flash → Groq Llama 3.3 → Ollama (all free, auto-fallback)
- **Monaco editor** — in-browser rule editing with syntax highlighting

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
| A | 85–100 |
| B | 70–84 |
| C | 55–69 |
| D | 40–54 |
| F | <40 |

## Stack

Python 3.11 · FastAPI · HTMX · Tailwind · Monaco · SQLite · Qdrant · sentence-transformers · pySigma · yara-python · Gemini · Groq · Ollama · MITRE ATT&CK STIX

## Related Projects

- [purple-loop](https://github.com/tejassesh5/purple-loop) — validate detections via attack emulation
- [threat-hunt-rag](https://github.com/tejassesh5/threat-hunt-rag) — hunt beyond detections with RAG
- [soc-copilot](https://github.com/tejassesh5/soc-copilot) — AI alert triage assistant
