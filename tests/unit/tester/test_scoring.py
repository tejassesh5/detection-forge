from detection_forge.tester.scoring import compute_score, ScoreBreakdown


def test_perfect_rule_scores_100():
    b = compute_score(
        tp=10, fp=0, total_attack_samples=10,
        field_count=4, has_wildcard_only=False,
        novelty=1.0, attack_coverage=5,
    )
    assert b.total == 100.0


def test_zero_tp_scores_low():
    b = compute_score(
        tp=0, fp=5, total_attack_samples=10,
        field_count=2, has_wildcard_only=False,
        novelty=0.8, attack_coverage=1,
    )
    assert b.total < 30.0


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


def test_grade_a():
    b = compute_score(tp=10, fp=0, total_attack_samples=10,
                      field_count=4, has_wildcard_only=False,
                      novelty=1.0, attack_coverage=5)
    assert b.grade() == "A"


def test_grade_f():
    b = compute_score(tp=0, fp=10, total_attack_samples=10,
                      field_count=1, has_wildcard_only=True,
                      novelty=0.0, attack_coverage=0)
    assert b.grade() == "F"
