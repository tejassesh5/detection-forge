import tempfile
from pathlib import Path
import pytest
from detection_forge.tester.yara_runner import match_yara_against_files

YARA_RULE = """
rule SuspiciousString {
    strings:
        $cmd = "cmd.exe /c" nocase
        $ps = "powershell -enc" nocase
    condition:
        any of them
}
"""


def test_yara_matches_positive_file():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"Executing cmd.exe /c whoami")
        path = Path(f.name)
    try:
        matches = match_yara_against_files(YARA_RULE, [path])
        assert len(matches) == 1
    finally:
        path.unlink(missing_ok=True)


def test_yara_no_match_on_clean_file():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"This is a benign text file with no malware strings")
        path = Path(f.name)
    try:
        matches = match_yara_against_files(YARA_RULE, [path])
        assert len(matches) == 0
    finally:
        path.unlink(missing_ok=True)


def test_yara_returns_only_matching_paths():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f1:
        f1.write(b"powershell -enc SQBuAHYAbwBrAGU=")
        path1 = Path(f1.name)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f2:
        f2.write(b"nothing malicious here")
        path2 = Path(f2.name)
    try:
        matches = match_yara_against_files(YARA_RULE, [path1, path2])
        assert len(matches) == 1
        assert path1 in matches
        assert path2 not in matches
    finally:
        path1.unlink(missing_ok=True)
        path2.unlink(missing_ok=True)
