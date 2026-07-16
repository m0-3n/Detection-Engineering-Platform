from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-009-Regsvr32-Remote-Script-Execution.yml"
)

def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_id():
    assert load_rule()["id"] == "DET-009"

def test_title():
    assert load_rule()["title"] == "Regsvr32 Remote Script Execution"

def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"

def test_regsvr32():
    image = load_rule()["detection"]["regsvr32_process"]["Image|endswith"]
    assert "\\regsvr32.exe" in image

def test_remote_script():
    assert "/i:" in load_rule()["detection"]["remote_script"]["CommandLine|contains"]

def test_script_engine():
    assert "scrobj.dll" in load_rule()["detection"]["script_engine"]["CommandLine|contains"]

def test_remote_url():
    urls = load_rule()["detection"]["remote_url"]["CommandLine|contains"]
    assert "http://" in urls
    assert "https://" in urls

def test_level():
    assert load_rule()["level"] == "high"