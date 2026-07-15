from pathlib import Path
from scripts.python.ioc_parser.models import IOC, IOCType
from scripts.python.ioc_parser.models import IOC
from scripts.python.ioc_parser.deduplicator import remove_duplicates
from scripts.python.ioc_parser.validator import (
    is_domain,
    is_ipv4,
    is_md5,
    is_sha1,
    is_sha256,
    is_url,
)


def _classify(value: str) -> IOC:
    value = value.strip()

    if is_ipv4(value):
        return IOC(value, IOCType.IPV4, True)

    if is_url(value):
        return IOC(value, IOCType.URL, True)

    if is_domain(value):
        return IOC(value, IOCType.DOMAIN, True)

    if is_md5(value):
        return IOC(value, IOCType.MD5, True)

    if is_sha1(value):
        return IOC(value, IOCType.SHA1, True)

    if is_sha256(value):
        return IOC(value, IOCType.SHA256, True)

    return IOC(value, IOCType.UNKNOWN, False)


def parse_file(path: str) -> list[IOC]:
    """
    Parse a text file containing one IOC per line.
    """

    results: list[IOC] = []

    with Path(path).open("r", encoding="utf-8") as file:
        for line in file:
            value = line.strip()

            if not value:
                continue

            results.append(_classify(value))

    return remove_duplicates(results)