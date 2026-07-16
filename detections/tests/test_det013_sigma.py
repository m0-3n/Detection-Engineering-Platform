from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-013-Suspicious-Local-Administrator-Creation.yml"
)

def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_id():
    assert load_rule()["id"] == "DET-013"

def test_title():
    assert load_rule()["title"] == "Suspicious Local Administrator Creation"

def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"

def test_create_user():
    commands = load_rule()["detection"]["create_user"]["CommandLine|contains"]

    assert "net user" in commands
    assert "/add" in commands
    assert "New-LocalUser" in commands

def test_add_admin():
    commands = load_rule()["detection"]["add_admin"]["CommandLine|contains"]

    assert "net localgroup administrators" in commands
    assert "Add-LocalGroupMember" in commands

def test_level():
    assert load_rule()["level"] == "high"