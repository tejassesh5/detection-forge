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
        subprocess.run(
            ["git", "clone", "--depth=1", "--filter=blob:none", "--sparse", url, str(dest)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "sparse-checkout", "set"] + sparse, check=True
        )
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
