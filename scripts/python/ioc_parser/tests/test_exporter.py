from pathlib import Path
from scripts.python.ioc_parser.exporter import export_csv, export_json, export_txt
from models import IOC, IOCType


def sample_iocs():
    return [
        IOC("8.8.8.8", IOCType.IPV4, True),
        IOC("google.com", IOCType.DOMAIN, True),
    ]


def test_export_json(tmp_path: Path):
    output = tmp_path / "iocs.json"

    export_json(sample_iocs(), str(output))

    assert output.exists()


def test_export_csv(tmp_path: Path):
    output = tmp_path / "iocs.csv"

    export_csv(sample_iocs(), str(output))

    assert output.exists()


def test_export_txt(tmp_path: Path):
    output = tmp_path / "iocs.txt"

    export_txt(sample_iocs(), str(output))

    assert output.exists()