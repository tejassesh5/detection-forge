import pytest
from detection_forge.attack.mapper import normalize_technique_id, extract_technique_ids


def test_normalize_full_id():
    assert normalize_technique_id("T1059.001") == "T1059.001"


def test_normalize_base_id():
    assert normalize_technique_id("T1059") == "T1059"


def test_normalize_lowercase():
    assert normalize_technique_id("t1059.001") == "T1059.001"


def test_normalize_invalid_raises():
    with pytest.raises(ValueError):
        normalize_technique_id("not-an-id")


def test_extract_technique_ids_from_list():
    ids = extract_technique_ids(["T1059.001", "T1566", "not-an-id", "T1078.004"])
    assert "T1059.001" in ids
    assert "T1566" in ids
    assert "T1078.004" in ids
    assert "not-an-id" not in ids


def test_extract_technique_ids_empty():
    assert extract_technique_ids([]) == []
