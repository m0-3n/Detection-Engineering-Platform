from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-014-Microsoft-Defender-Tampering.yml"
)

def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_id():
    assert load_rule()["id"] == "DET-014"

def test_title():
    assert load_rule()["title"] == "Microsoft Defender Tampering"

def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"

def test_powershell_detection():
    commands = load_rule()["detection"]["powershell_disable"]["CommandLine|contains"]

    assert "Set-MpPreference" in commands
    assert "-DisableRealtimeMonitoring" in commands
    assert "-DisableBehaviorMonitoring" in commands
    assert "-DisableScriptScanning" in commands
    assert "-DisableIOAVProtection" in commands

def test_service_detection():
    commands = load_rule()["detection"]["service_stop"]["CommandLine|contains|all"]

    assert "sc" in commands
    assert "stop" in commands
    assert "WinDefend" in commands

def test_registry_detection():
    commands = load_rule()["detection"]["registry_modification"]["CommandLine|contains"]

    assert "reg add" in commands
    assert "Windows Defender" in commands

def test_level():
    assert load_rule()["level"] == "high"