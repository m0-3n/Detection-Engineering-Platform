from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-005-Suspicious-PowerShell-Parent-Process.yml"
)

def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_id():
    assert load_rule()["id"] == "DET-005"

def test_title():
    assert load_rule()["title"] == "Suspicious Parent Process Launching PowerShell"

def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"

def test_parent_processes():
    parents = load_rule()["detection"]["suspicious_parent"]["ParentImage|endswith"]

    assert "\\WINWORD.EXE" in parents
    assert "\\EXCEL.EXE" in parents
    assert "\\POWERPNT.EXE" in parents
    assert "\\OUTLOOK.EXE" in parents
    assert "\\AcroRd32.exe" in parents

def test_level():
    assert load_rule()["level"] == "high"