from detection_forge.forge.validator import validate_sigma, validate_yara

VALID_SIGMA = """
title: Suspicious PowerShell Execution
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-Enc '
    condition: selection
level: high
"""

INVALID_SIGMA = """
title: Bad Rule
detection:
    selection:
        Image: powershell.exe
"""

VALID_YARA = """
rule SuspiciousString {
    strings:
        $a = "cmd.exe /c"
    condition:
        $a
}
"""

INVALID_YARA = "rule Broken { strings: $a = condition: $a"


def test_validate_sigma_valid():
    errors = validate_sigma(VALID_SIGMA)
    assert errors == []

def test_validate_sigma_invalid():
    errors = validate_sigma(INVALID_SIGMA)
    assert len(errors) > 0

def test_validate_yara_valid():
    errors = validate_yara(VALID_YARA)
    assert errors == []

def test_validate_yara_invalid():
    errors = validate_yara(INVALID_YARA)
    assert len(errors) > 0
