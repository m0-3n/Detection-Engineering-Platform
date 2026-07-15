from scripts.python.ioc_parser.models import IOC
from scripts.python.ioc_parser.normalizer import normalize


def remove_duplicates(iocs: list[IOC]) -> list[IOC]:
    """
    Remove duplicate IOCs while preserving order.
    """

    seen: set[tuple[str, str]] = set()

    results: list[IOC] = []

    for ioc in iocs:

        normalized = normalize(ioc)

        key = (
            normalized.value,
            normalized.ioc_type.value,
        )

        if key in seen:
            continue

        seen.add(key)

        results.append(normalized)

    return results