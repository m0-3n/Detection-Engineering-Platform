from scripts.python.ioc_parser.parser import parse_file
from scripts.python.ioc_parser.models import IOCType
from pathlib import Path

def test_parse_file():
    TEST_DIR = Path(__file__).parent

    sample = TEST_DIR / "sample_iocs.txt"
    results = parse_file(str(sample))

    assert len(results) == 5

    assert results[0].ioc_type == IOCType.IPV4
    assert results[1].ioc_type == IOCType.DOMAIN
    assert results[2].ioc_type == IOCType.URL
    assert results[3].ioc_type == IOCType.MD5
    assert results[4].ioc_type == IOCType.UNKNOWN