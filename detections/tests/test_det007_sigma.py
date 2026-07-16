from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]

RULE_PATH = (
    ROOT
    / "detections"
    / "sigma"
    / "windows"
    / "DET-007-Certutil-Remote-Download.yml"
)

def load_rule():
    with RULE_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def test_rule_id():
    assert load_rule()["id"] == "DET-007"

def test_title():
    assert load_rule()["title"] == "Certutil Remote Download"

def test_logsource():
    rule = load_rule()
    assert rule["logsource"]["product"] == "windows"
    assert rule["logsource"]["category"] == "process_creation"

def test_certutil_process():
    indicators = load_rule()["detection"]["certutil_process"]["Image|endswith"]
    assert "\\certutil.exe" in indicators

def test_download_flags():
    flags = load_rule()["detection"]["download_flags"]["CommandLine|contains"]

    assert "-urlcache" in flags
    assert "-split" in flags
    assert "-f" in flags

def test_remote_url():
    urls = load_rule()["detection"]["remote_url"]["CommandLine|contains"]

    assert "http://" in urls
    assert "https://" in urls

def test_level():
    assert load_rule()["level"] == "high"