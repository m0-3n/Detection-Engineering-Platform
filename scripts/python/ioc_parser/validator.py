from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from scripts.python.ioc_parser.constants import (
    DOMAIN_PATTERN,
    MD5_PATTERN,
    SHA1_PATTERN,
    SHA256_PATTERN,
)


def is_ipv4(value: str) -> bool:
    """
    Return True if the supplied value is a valid IPv4 address.
    """
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    """
    Return True if the supplied value is a valid domain name.
    """
    return DOMAIN_PATTERN.fullmatch(value) is not None


def is_url(value: str) -> bool:
    """
    Return True if the supplied value is a valid HTTP or HTTPS URL.
    """
    parsed = urlparse(value)

    return (
        parsed.scheme in ("http", "https")
        and bool(parsed.netloc)
    )


def is_md5(value: str) -> bool:
    return MD5_PATTERN.fullmatch(value) is not None


def is_sha1(value: str) -> bool:
    return SHA1_PATTERN.fullmatch(value) is not None


def is_sha256(value: str) -> bool:
    return SHA256_PATTERN.fullmatch(value) is not None