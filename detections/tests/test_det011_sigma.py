from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-011-PsExec-Remote-Execution.yml"
)

def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_id():
    assert load_rule()["id"] == "DET-011"

def test_title():
    assert load_rule()["title"] == "PsExec Remote Execution"

def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"

def test_psexec():
    image = load_rule()["detection"]["psexec_process"]["Image|endswith"]

    assert "\\PsExec.exe" in image
    assert "\\PsExec64.exe" in image

def test_remote_host():
    remote = load_rule()["detection"]["remote_host"]["CommandLine|contains"]

    assert "\\\\" in remote

def test_suspicious_process():
    process = load_rule()["detection"]["suspicious_process"]["CommandLine|contains"]

    assert "powershell.exe" in process
    assert "cmd.exe" in process

def test_level():
    assert load_rule()["level"] == "high"