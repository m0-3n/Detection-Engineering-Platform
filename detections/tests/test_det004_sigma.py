from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-004-PowerShell-Hidden-Window.yml"
)

def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_id():
    assert load_rule()["id"] == "DET-004"

def test_title():
    assert load_rule()["title"] == "PowerShell Hidden Window"

def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"

def test_hidden_window():
    indicators = load_rule()["detection"]["hidden_window"]["CommandLine|contains"]

    assert "-WindowStyle Hidden" in indicators
    assert "-windowstyle hidden" in indicators
    assert "-w hidden" in indicators

def test_level():
    assert load_rule()["level"] == "medium"