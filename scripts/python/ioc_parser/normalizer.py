from scripts.python.ioc_parser.models import IOC, IOCType
from urllib.parse import urlparse, urlunparse


def normalize(ioc: IOC) -> IOC:
    """
    Return a normalized IOC for comparison and export.
    """

    value = ioc.value

    if ioc.ioc_type == IOCType.DOMAIN:
        value = value.lower()

    elif ioc.ioc_type == IOCType.URL:
        parsed = urlparse(value)

        value = urlunparse(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )

    elif ioc.ioc_type in (
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    ):
        value = value.lower()

    return IOC(
        value=value,
        ioc_type=ioc.ioc_type,
        is_valid=ioc.is_valid,
    )