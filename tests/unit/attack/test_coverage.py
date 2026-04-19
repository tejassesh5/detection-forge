from detection_forge.attack.coverage import compute_coverage, find_gaps


MOCK_TECHNIQUES = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution", "url": ""},
    "T1566": {"name": "Phishing", "tactic": "initial-access", "url": ""},
    "T1078": {"name": "Valid Accounts", "tactic": "defense-evasion", "url": ""},
}


def test_compute_coverage_counts_correctly():
    rule_techniques = [["T1059", "T1566"], ["T1059"]]
    cov = compute_coverage(rule_techniques, MOCK_TECHNIQUES)
    assert cov["T1059"] == 2
    assert cov["T1566"] == 1
    assert "T1078" not in cov


def test_compute_coverage_ignores_unknown_techniques():
    rule_techniques = [["T9999"]]  # not in MOCK_TECHNIQUES
    cov = compute_coverage(rule_techniques, MOCK_TECHNIQUES)
    assert len(cov) == 0


def test_find_gaps_returns_uncovered():
    coverage = {"T1059": 2}
    gaps = find_gaps(coverage, MOCK_TECHNIQUES)
    gap_ids = [g["id"] for g in gaps]
    assert "T1566" in gap_ids
    assert "T1078" in gap_ids
    assert "T1059" not in gap_ids


def test_find_gaps_sorted_by_tactic():
    coverage = {}
    gaps = find_gaps(coverage, MOCK_TECHNIQUES)
    tactics = [g["tactic"] for g in gaps]
    assert tactics == sorted(tactics)
