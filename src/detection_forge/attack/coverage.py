from __future__ import annotations

import json
import urllib.request
from collections import defaultdict
from pathlib import Path

import structlog

log = structlog.get_logger()

_STIX_PATH = Path("data/attack/enterprise-attack.json")
_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def ensure_stix_bundle() -> Path:
    if _STIX_PATH.exists():
        return _STIX_PATH
    _STIX_PATH.parent.mkdir(parents=True, exist_ok=True)
    log.info("downloading ATT&CK STIX bundle")
    urllib.request.urlretrieve(_STIX_URL, str(_STIX_PATH))
    return _STIX_PATH


def load_techniques() -> dict[str, dict]:
    """Returns {technique_id: {name, tactic, url}} from STIX bundle."""
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
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        techniques[tech_id] = {
            "name": obj.get("name", ""),
            "tactic": tactics[0] if tactics else "unknown",
            "url": next(
                (r.get("url", "") for r in ext if r.get("source_name") == "mitre-attack"), ""
            ),
        }
    return techniques


def compute_coverage(
    rule_techniques: list[list[str]],
    all_techniques: dict[str, dict],
) -> dict[str, int]:
    """Returns {technique_id: rule_count} for covered techniques."""
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
