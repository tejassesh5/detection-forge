from detection_forge.cti.parsers.text import parse_text, extract_iocs
from detection_forge.cti.models import SourceType


def test_parse_text_creates_cti_item():
    item = parse_text("APT29 used C2 at 192.168.1.100", title="Test Report")
    assert item.title == "Test Report"
    assert item.source_type == SourceType.TEXT
    assert len(item.id) == 36


def test_parse_text_auto_title_from_first_80_chars():
    text = "Threat actor used spearphishing"
    item = parse_text(text)
    assert item.title == text


def test_extract_iocs_finds_ipv4():
    iocs = extract_iocs("C2 at 10.0.0.1 and 172.16.0.5")
    assert "10.0.0.1" in iocs
    assert "172.16.0.5" in iocs


def test_extract_iocs_finds_md5():
    iocs = extract_iocs("hash: d41d8cd98f00b204e9800998ecf8427e")
    assert "d41d8cd98f00b204e9800998ecf8427e" in iocs


def test_extract_iocs_finds_sha256():
    iocs = extract_iocs("sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs


def test_extract_iocs_filters_benign_domains():
    iocs = extract_iocs("downloaded from google.com and evil-c2.ru")
    assert "google.com" not in iocs
    assert "evil-c2.ru" in iocs


def test_extract_iocs_finds_url():
    iocs = extract_iocs("beacon called http://malware.example.com/path/payload")
    assert any("malware.example.com" in ioc for ioc in iocs)
