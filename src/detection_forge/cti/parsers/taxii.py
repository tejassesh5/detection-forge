from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..models import CTIItem
from .stix import parse_stix_bundle


def fetch_taxii(
    server_url: str,
    collection_id: str,
    username: str = "",
    password: str = "",
) -> list[CTIItem]:
    from taxii2client.v21 import Server

    server = Server(server_url, user=username or None, password=password or None)
    api_root = server.api_roots[0]
    collection = next(c for c in api_root.collections if c.id == collection_id)
    bundle = collection.get_objects()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(bundle, f)
        tmp_path = Path(f.name)
    try:
        return parse_stix_bundle(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)
