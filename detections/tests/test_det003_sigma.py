from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-003-PowerShell-Execution-Policy-Bypass.yml"
)

def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_id():
    assert load_rule()["id"] == "DET-003"

def test_title():
    assert load_rule()["title"] == "PowerShell Execution Policy Bypass"

def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"

def test_execution_policy():
    indicators = load_rule()["detection"]["execution_policy"]["CommandLine|contains"]

    assert "-ExecutionPolicy" in indicators
    assert "-executionpolicy" in indicators
    assert "-ep" in indicators

def test_bypass():
    indicators = load_rule()["detection"]["bypass"]["CommandLine|contains"]

    assert "Bypass" in indicators
    assert "bypass" in indicators

def test_level():
    assert load_rule()["level"] == "medium"