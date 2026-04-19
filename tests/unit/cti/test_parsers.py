import json
import tempfile
from pathlib import Path
from detection_forge.cti.parsers.stix import parse_stix_bundle
from detection_forge.cti.parsers.misp import parse_misp_event
from detection_forge.cti.loader import load
from detection_forge.cti.models import SourceType

MOCK_STIX_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "malware",
            "id": "malware--1234",
            "name": "EvilRAT",
            "description": "A remote access trojan used by APT99",
        },
        {
            "type": "tool",  # not in allowed types, should be skipped
            "id": "tool--5678",
            "name": "PsExec",
        },
    ],
}

MOCK_MISP_EVENT = {
    "id": "42",
    "info": "APT99 Campaign Q1 2026",
    "Attribute": [
        {"type": "ip-dst", "value": "10.0.0.1", "to_ids": True},
        {"type": "domain", "value": "evil.ru", "to_ids": True},
        {"type": "comment", "value": "C2 server", "to_ids": False},
    ],
}


def test_parse_stix_bundle_extracts_malware():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(MOCK_STIX_BUNDLE, f)
        path = Path(f.name)
    try:
        items = parse_stix_bundle(path)
        assert len(items) == 1
        assert items[0].title == "EvilRAT"
        assert items[0].source_type.value == "stix"
    finally:
        path.unlink(missing_ok=True)


def test_parse_stix_skips_unsupported_types():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(MOCK_STIX_BUNDLE, f)
        path = Path(f.name)
    try:
        items = parse_stix_bundle(path)
        titles = [i.title for i in items]
        assert "PsExec" not in titles
    finally:
        path.unlink(missing_ok=True)


def test_parse_misp_event():
    item = parse_misp_event(MOCK_MISP_EVENT)
    assert item.title == "APT99 Campaign Q1 2026"
    assert item.source_type.value == "misp"
    assert "10.0.0.1" in item.raw_iocs
    assert "evil.ru" in item.raw_iocs
    assert "C2 server" not in item.raw_iocs  # to_ids=False


def test_loader_text_source():
    items = load("APT group used encoded powershell", SourceType.TEXT, title="Test")
    assert len(items) == 1
    assert items[0].title == "Test"


def test_loader_stix_source():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(MOCK_STIX_BUNDLE, f)
        path = Path(f.name)
    try:
        items = load(path, SourceType.STIX)
        assert len(items) == 1
    finally:
        path.unlink(missing_ok=True)
