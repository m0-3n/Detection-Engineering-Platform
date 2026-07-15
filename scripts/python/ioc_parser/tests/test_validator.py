from scripts.python.ioc_parser.validator import (
    is_domain,
    is_ipv4,
    is_md5,
    is_sha1,
    is_sha256,
    is_url,
)


def test_ipv4():
    assert is_ipv4("8.8.8.8")
    assert not is_ipv4("999.999.999.999")


def test_domain():
    assert is_domain("google.com")
    assert not is_domain("google")


def test_url():
    assert is_url("https://google.com")
    assert not is_url("not-a-url")


def test_md5():
    assert is_md5("44d88612fea8a8f36de82e1278abb02f")


def test_sha1():
    assert is_sha1("3395856ce81f2b7382dee72602f798b642f14140")


def test_sha256():
    assert is_sha256(
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )