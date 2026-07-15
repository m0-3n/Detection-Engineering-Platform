from pathlib import Path
import yaml


RULE_PATH = Path("sigma\\windows\\DET-002-PowerShell-Remote-Content-Retrieval.yml")


def load_rule():
    with open(RULE_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_rule_id():
    rule = load_rule()
    assert rule["id"] == "DET-002"


def test_rule_title():
    rule = load_rule()
    assert rule["title"] == "PowerShell Remote Content Retrieval"


def test_logsource():
    rule = load_rule()

    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"


def test_detection_contains_downloadstring():
    rule = load_rule()

    indicators = rule["detection"]["remote_content"]["CommandLine|contains"]

    assert "DownloadString" in indicators


def test_detection_contains_downloadfile():
    rule = load_rule()

    indicators = rule["detection"]["remote_content"]["CommandLine|contains"]

    assert "DownloadFile" in indicators


def test_detection_contains_iwr():
    rule = load_rule()

    indicators = rule["detection"]["remote_content"]["CommandLine|contains"]

    assert "Invoke-WebRequest" in indicators


def test_detection_contains_irm():
    rule = load_rule()

    indicators = rule["detection"]["remote_content"]["CommandLine|contains"]

    assert "Invoke-RestMethod" in indicators


def test_level():
    rule = load_rule()
    assert rule["level"] == "medium"