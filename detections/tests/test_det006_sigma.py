from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-006-PowerShell-Network-Communication.yml"
)

def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_id():
    assert load_rule()["id"] == "DET-006"

def test_title():
    assert load_rule()["title"] == "PowerShell Network Communication"

def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"

def test_network_functions():
    indicators = load_rule()["detection"]["network_functions"]["CommandLine|contains"]

    assert "Invoke-WebRequest" in indicators
    assert "Invoke-RestMethod" in indicators
    assert "Net.WebClient" in indicators
    assert "System.Net.Http.HttpClient" in indicators
    assert "WebRequest.Create" in indicators

def test_level():
    assert load_rule()["level"] == "high"