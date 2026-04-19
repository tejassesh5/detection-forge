from detection_forge.cti.models import CTIItem, SourceType

def test_cti_item_defaults():
    item = CTIItem(title="Report", text="malware found", source_type=SourceType.TEXT)
    assert item.source_type == SourceType.TEXT
    assert item.raw_iocs == []
    assert len(item.id) == 36

def test_cti_item_with_iocs():
    item = CTIItem(title="APT29", text="...", source_type=SourceType.STIX, raw_iocs=["10.0.0.1"])
    assert "10.0.0.1" in item.raw_iocs
