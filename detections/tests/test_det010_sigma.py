from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-010-WMI-Remote-Process-Creation.yml"
)

def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_id():
    assert load_rule()["id"] == "DET-010"

def test_title():
    assert load_rule()["title"] == "WMI Remote Process Creation"

def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"

def test_wmi_process():
    image = load_rule()["detection"]["wmi_process"]["Image|endswith"]
    assert "\\wmic.exe" in image

def test_process_creation():
    indicators = load_rule()["detection"]["process_creation"]["CommandLine|contains"]

    assert "process" in indicators
    assert "call" in indicators
    assert "create" in indicators

def test_suspicious_process():
    processes = load_rule()["detection"]["suspicious_process"]["CommandLine|contains"]

    assert "powershell.exe" in processes
    assert "cmd.exe" in processes

def test_level():
    assert load_rule()["level"] == "high"