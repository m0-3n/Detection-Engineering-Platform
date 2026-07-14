from dataclasses import dataclass
from enum import Enum


class IOCType(Enum):
    IPV4 = "ipv4"
    URL = "url"
    DOMAIN = "domain"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"


@dataclass(slots=True, frozen=True)
class IOC:
    """
    Represents a single Indicator of Compromise.
    """

    value: str
    ioc_type: IOCType
    is_valid: bool