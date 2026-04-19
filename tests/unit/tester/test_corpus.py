from detection_forge.tester.corpus import list_corpora, get_corpus
import pytest

def test_list_corpora_returns_known_names():
    names = list_corpora()
    assert "evtx-attack-samples" in names
    assert "mordor" in names
    assert "benign-baseline" in names

def test_get_corpus_unknown_raises():
    with pytest.raises(KeyError, match="Unknown corpus"):
        get_corpus("nonexistent-corpus")

def test_get_corpus_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        get_corpus("evtx-attack-samples")  # data/corpora doesn't exist in test env
