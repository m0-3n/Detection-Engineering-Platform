from deduplicator import remove_duplicates
from models import IOC, IOCType


def test_duplicate_domains():

    iocs = [

        IOC("google.com", IOCType.DOMAIN, True),

        IOC("GOOGLE.COM", IOCType.DOMAIN, True),

        IOC("google.com", IOCType.DOMAIN, True),
    ]

    result = remove_duplicates(iocs)

    assert len(result) == 1


def test_duplicate_ipv4():

    iocs = [

        IOC("8.8.8.8", IOCType.IPV4, True),

        IOC("8.8.8.8", IOCType.IPV4, True),
    ]

    result = remove_duplicates(iocs)

    assert len(result) == 1


def test_duplicate_hash():

    iocs = [

        IOC(
            "44D88612FEA8A8F36DE82E1278ABB02F",
            IOCType.MD5,
            True,
        ),

        IOC(
            "44d88612fea8a8f36de82e1278abb02f",
            IOCType.MD5,
            True,
        ),
    ]

    result = remove_duplicates(iocs)

    assert len(result) == 1