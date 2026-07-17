from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-001-Suspicious-PowerShell-Encoded-Command.yml"
)


def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_rule_id():
    assert load_rule()["id"] == "DET-001"


def test_title():
    assert load_rule()["title"] == "Suspicious PowerShell Encoded Command"


def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"


def test_image_selection():
    images = load_rule()["detection"]["selection"]["Image|endswith"]

    assert "\\powershell.exe" in images
    assert "\\pwsh.exe" in images


def test_commandline_selection():
    commands = load_rule()["detection"]["selection"]["CommandLine|contains"]

    assert "-EncodedCommand" in commands
    assert "-enc" in commands


def test_condition():
    assert load_rule()["detection"]["condition"] == "selection"


def test_level():
    assert load_rule()["level"] == "high"