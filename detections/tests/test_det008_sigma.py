from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-008-Rundll32-Suspicious-DLL-Execution.yml"
)

def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_id():
    assert load_rule()["id"] == "DET-008"

def test_title():
    assert load_rule()["title"] == "Rundll32 Suspicious DLL Execution"

def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"

def test_rundll32():
    image = load_rule()["detection"]["rundll32_process"]["Image|endswith"]
    assert "\\rundll32.exe" in image

def test_suspicious_arguments():
    args = load_rule()["detection"]["suspicious_arguments"]["CommandLine|contains"]

    assert "javascript:" in args
    assert "mshtml" in args

def test_level():
    assert load_rule()["level"] == "high"