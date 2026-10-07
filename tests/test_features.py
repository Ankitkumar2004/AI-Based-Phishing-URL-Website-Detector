import pytest
from src.feature_extraction import (
    extract_features,
    extract_security_indicators,
    calculate_shannon_entropy,
    sanitize_url
)


def test_valid_standard_url():
    url = "https://www.google.com/search?q=cybersecurity"
    features = extract_features(url)

    assert features["has_https"] == 1
    assert features["has_http"] == 0
    assert features["has_ip_address"] == 0
    assert features["hostname_present"] == 1
    assert features["hostname_length"] == len("www.google.com")
    assert features["number_of_dots"] >= 2
    assert features["is_shortened_url"] == 0


def test_malformed_and_schemaless_url():
    url = "subdomain.phish-target.xyz/login"
    sanitized = sanitize_url(url)
    assert sanitized.startswith("http://")

    features = extract_features(url)
    assert features["url_length"] > 0
    assert features["hostname_present"] == 1
    assert features["unusual_tld"] == 1
    assert features["kw_login"] == 1


def test_raw_ip_address_url():
    url = "http://192.168.1.50:8080/secure/bank.html"
    features = extract_features(url)

    assert features["has_ip_address"] == 1
    assert features["has_https"] == 0
    assert features["has_http"] == 1
    assert features["suspicious_port"] == 1
    assert features["kw_secure"] == 1
    assert features["kw_bank"] == 1

    indicators = extract_security_indicators(url, features)
    ip_indicator = next((i for i in indicators if i["title"] == "Raw IP Hostname"), None)
    assert ip_indicator is not None
    assert ip_indicator["type"] == "danger"


def test_suspicious_characters_and_at_symbol():
    url = "https://legit-brand.com@evil-attacker.com/login?token=abc%20xyz"
    features = extract_features(url)

    assert features["number_of_at_symbols"] == 1
    assert features["number_of_percent_symbols"] == 1
    assert features["special_character_count"] > 0

    indicators = extract_security_indicators(url, features)
    at_ind = next((i for i in indicators if "Credential Obfuscation" in i["title"]), None)
    assert at_ind is not None
    assert at_ind["type"] == "danger"


def test_excessively_long_url():
    long_path = "a" * 150
    url = f"https://example.com/{long_path}?token=12345"
    features = extract_features(url)

    assert features["url_length"] > 150
    assert features["path_length"] >= 150

    indicators = extract_security_indicators(url, features)
    len_ind = next((i for i in indicators if "Excessive URL Length" in i["title"]), None)
    assert len_ind is not None
    assert len_ind["type"] == "warning"


def test_shannon_entropy():
    # Repetitive string has low entropy
    low_entropy = calculate_shannon_entropy("aaaaaaa")
    assert low_entropy == 0.0

    # Diverse randomized string has higher entropy
    high_entropy = calculate_shannon_entropy("a8f93kd81mzp")
    assert high_entropy > 3.0


def test_url_shortener_detection():
    url = "https://bit.ly/3xY8a9"
    features = extract_features(url)
    assert features["is_shortened_url"] == 1

    indicators = extract_security_indicators(url, features)
    short_ind = next((i for i in indicators if "Shortener" in i["title"]), None)
    assert short_ind is not None
    assert short_ind["type"] == "danger"


def test_punycode_detection():
    url = "http://xn--appl-43d.com/login"
    features = extract_features(url)
    assert features["has_punycode"] == 1
