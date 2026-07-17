from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-015-LSASS-Memory-Dump-Attempt.yml"
)

def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_id():
    assert load_rule()["id"] == "DET-015"

def test_title():
    assert load_rule()["title"] == "LSASS Memory Dump Attempt"

def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"

def test_procdump_detection():
    commands = load_rule()["detection"]["procdump"]["CommandLine|contains|all"]

    assert "procdump" in commands
    assert "-ma" in commands
    assert "lsass" in commands

def test_comsvcs_detection():
    commands = load_rule()["detection"]["comsvcs"]["CommandLine|contains|all"]

    assert "rundll32" in commands
    assert "comsvcs.dll" in commands
    assert "MiniDump" in commands
    assert "lsass" in commands

def test_mimikatz_detection():
    commands = load_rule()["detection"]["mimikatz"]["CommandLine|contains"]

    assert "sekurlsa::logonpasswords" in commands

def test_nanodump_detection():
    commands = load_rule()["detection"]["nanodump"]["CommandLine|contains"]

    assert "nanodump" in commands

def test_level():
    assert load_rule()["level"] == "critical"