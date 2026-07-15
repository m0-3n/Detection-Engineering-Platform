from scripts.python.ioc_parser.parser import parse_file
from models import IOCType

def test_parse_file():
    results = parse_file("tests/sample_iocs.txt")

    assert len(results) == 5

    assert results[0].ioc_type == IOCType.IPV4
    assert results[1].ioc_type == IOCType.DOMAIN
    assert results[2].ioc_type == IOCType.URL
    assert results[3].ioc_type == IOCType.MD5
    assert results[4].ioc_type == IOCType.UNKNOWN