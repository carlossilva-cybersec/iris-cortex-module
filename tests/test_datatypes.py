import pytest

from iris_cortex_module.core.datatypes import (
    ObservableError, cortex_candidates, hash_kind, iris_tlp_to_cortex, iris_type_for_artifact, normalize_value,
)


@pytest.mark.parametrize("iris_type,value,expected", [
    ("ip-dst", "8.8.8.8", [("ip", "8.8.8.8")]),
    ("ip-src|port", "10.0.0.1|443", [("ip", "10.0.0.1")]),
    ("domain", "evil.com", [("domain", "evil.com")]),
    ("hostname", "www.evil.com", [("fqdn", "www.evil.com")]),
    ("url", "http://evil.com/x", [("url", "http://evil.com/x")]),
    ("sha256", "a" * 64, [("hash", "a" * 64)]),
    ("filename|sha256", "a.exe|" + "b" * 64, [("filename", "a.exe"), ("hash", "b" * 64)]),
    ("domain|ip", "evil.com|1.2.3.4", [("domain", "evil.com"), ("ip", "1.2.3.4")]),
    ("email-src", "a@evil.com", [("mail", "a@evil.com")]),
    ("user-agent", "curl/8", [("user-agent", "curl/8")]),
    ("AS", "AS13335", [("autonomous-system", "AS13335")]),
    ("mutex", "Global\\x", [("other", "Global\\x")]),
])
def test_mapping(iris_type, value, expected):
    assert cortex_candidates(iris_type, value) == expected


def test_mapping_override():
    assert cortex_candidates("mutex", "x", {"mutex": "regexp"}) == [("regexp", "x")]


@pytest.mark.parametrize("dt,value,expected", [
    ("ip", " 8.8.8.8 ", "8.8.8.8"),
    ("ip", "2001:DB8::1", "2001:db8::1"),
    ("ip", "10.0.0.0/8", "10.0.0.0/8"),
    ("domain", "Evil.COM.", "evil.com"),
    ("hash", "44D88612FEA8A8F36DE82E1278ABB02F", "44d88612fea8a8f36de82e1278abb02f"),
    ("autonomous-system", "AS13335", "13335"),
    ("mail", "a@evil.com", "a@evil.com"),
    ("url", "https://evil.com/a?b=1", "https://evil.com/a?b=1"),
    ("other", "anything", "anything"),
])
def test_normalize_valid(dt, value, expected):
    assert normalize_value(dt, value) == expected


@pytest.mark.parametrize("dt,value", [
    ("ip", "999.1.1.1"), ("ip", "evil.com"), ("domain", "no_tld"), ("domain", "-bad.com"),
    ("hash", "xyz"), ("hash", "a" * 33), ("url", "javascript:alert(1)"), ("url", "evil.com"),
    ("mail", "not-mail"), ("autonomous-system", "ASX"), ("other", ""), ("other", "a\x00b"),
    ("other", "x" * 9000), ("file", "whatever"),
])
def test_normalize_invalid(dt, value):
    with pytest.raises(ObservableError):
        normalize_value(dt, value)


def test_hash_kind_and_artifact_types():
    assert hash_kind("a" * 32) == "md5" and hash_kind("a" * 64) == "sha256" and hash_kind("zz") is None
    assert iris_type_for_artifact("hash", "a" * 40) == "sha1"
    assert iris_type_for_artifact("ip", "1.1.1.1") == "ip-any"
    assert iris_type_for_artifact("fqdn", "a.b.com") == "hostname"
    assert iris_type_for_artifact("file", "x") is None
    assert iris_type_for_artifact("weird", "x") is None


def test_tlp_mapping():
    assert [iris_tlp_to_cortex(n) for n in ("clear", "green", "amber", "amber+strict", "red")] == [0, 1, 2, 3, 3]
    assert iris_tlp_to_cortex(None) == 2
