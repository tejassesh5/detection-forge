from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScoreBreakdown:
    precision: float
    recall: float
    attack_coverage: float
    specificity: float
    novelty: float
    total: float

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
