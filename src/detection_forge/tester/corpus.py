from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path("data/corpora")


@dataclass
class Corpus:
    name: str
    description: str
    path: Path
    file_glob: str = "**/*.evtx"
    corpus_type: str = "evtx"


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
