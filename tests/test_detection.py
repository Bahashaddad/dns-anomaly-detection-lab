import pytest
from detect import calculate_risk_score, get_verdict, analyze_domain
from rules import normalize_domain, calculate_entropy, count_labels


def test_known_feature_values():
    assert calculate_entropy("aaaa") == 0
    assert calculate_entropy("abcd") == 2
    assert count_labels("www.example.test") == 3
    assert analyze_domain("teams.microsoft.com")["score"] == 0


def test_score_boundaries():
    assert calculate_risk_score(3.8, 12, 3, "A") == 35
    assert calculate_risk_score(3.8, 25, 4, "TXT") == 100
    assert get_verdict(49) == "LOW SCORE"
    assert get_verdict(50) == "SUSPICIOUS"
    assert get_verdict(75) == "HIGH RISK"


@pytest.mark.parametrize(
    "name",
    [
        "bad\n127.0.0.1 victim.test",
        "bad name.test",
        "a..test",
        "a" * 64 + ".test",
        b"\xff.test",
        "",
        "a.test..",
    ],
)
def test_malformed_names_rejected(name):
    with pytest.raises((ValueError, UnicodeError)):
        normalize_domain(name)


def test_case_trailing_dot_and_service_labels():
    assert normalize_domain(b"WWW.Example.TEST.") == "www.example.test"
    assert (
        normalize_domain("_service._tcp.example.test") == "_service._tcp.example.test"
    )


def test_popularity_is_not_trust_or_accidental_suffix_match():
    assert analyze_domain("www.example.test", popular_domains={"example.test"})[
        "popular"
    ]
    assert not analyze_domain("notexample.test", popular_domains={"example.test"})[
        "popular"
    ]
    high = "abcdefghijklmnopqrstuvwxyz012345.api.lab.example.test"
    assert analyze_domain(high, "TXT", {"example.test"})["verdict"] == "HIGH RISK"


def test_legacy_policy_is_explicit():
    name = "abcdefghijklmnopqrstuvwxyz012345.example.test"
    assert analyze_domain(name, "A", {"example.test"})["verdict"] == "SUSPICIOUS"
    assert analyze_domain(name, "A", {"example.test"}, True)["verdict"] == "HIGH RISK"
