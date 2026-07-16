from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-012-Suspicious-Scheduled-Task-Creation.yml"
)

def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_id():
    assert load_rule()["id"] == "DET-012"

def test_title():
    assert load_rule()["title"] == "Suspicious Scheduled Task Creation"

def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"

def test_schtasks():
    image = load_rule()["detection"]["schtasks_process"]["Image|endswith"]

    assert "\\schtasks.exe" in image

def test_create_task():
    create = load_rule()["detection"]["create_task"]["CommandLine|contains"]

    assert "/create" in create

def test_suspicious_process():
    process = load_rule()["detection"]["suspicious_process"]["CommandLine|contains"]

    assert "powershell.exe" in process
    assert "cmd.exe" in process

def test_level():
    assert load_rule()["level"] == "high"