from __future__ import annotations

from pathlib import Path

import yara


def match_yara_against_files(yara_source: str, file_paths: list[Path]) -> list[Path]:
    """Returns paths of files that matched the YARA rule."""
    rules = yara.compile(source=yara_source)
    matched: list[Path] = []
    for path in file_paths:
        try:
            matches = rules.match(str(path))
            if matches:
                matched.append(path)
        except yara.Error:
            continue
    return matched
