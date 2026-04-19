from detection_forge.tester.sigma_runner import match_sigma_against_events

SIGMA_RULE = """
title: Encoded PowerShell
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-EncodedCommand'
    condition: selection
level: high
"""


def test_match_sigma_detects_true_positive():
    events = [
        {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand SQBuAHYAbwBrAGU=",
        }
    ]
    matches = match_sigma_against_events(SIGMA_RULE, events)
    assert len(matches) == 1


def test_match_sigma_no_false_positive():
    events = [{"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c dir"}]
    matches = match_sigma_against_events(SIGMA_RULE, events)
    assert len(matches) == 0


def test_match_sigma_returns_matching_events():
    events = [
        {"Image": "C:\\powershell.exe", "CommandLine": "-EncodedCommand abc"},
        {"Image": "C:\\notepad.exe", "CommandLine": "notepad.exe"},
    ]
    matches = match_sigma_against_events(SIGMA_RULE, events)
    assert len(matches) == 1
    assert "-EncodedCommand" in matches[0]["CommandLine"]
