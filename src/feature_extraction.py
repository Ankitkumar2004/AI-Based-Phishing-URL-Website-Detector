import re
import math
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "account",
    "secure", "update", "password", "bank", "wallet",
    "confirm", "authentication", "free", "bonus", "claim"
]

HIGH_RISK_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".online", ".site",
    ".buzz", ".loan", ".date", ".bid", ".win", ".stream", ".gq", ".ml",
    ".cf", ".tk", ".ga", ".rest", ".fit", ".monster", ".bar"
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc"
}

IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def sanitize_url(raw_url: str) -> str:
    if not isinstance(raw_url, str):
        return ""
    url = raw_url.strip()
    if not url:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def extract_features(raw_url: str) -> Dict[str, Any]:
    cleaned_url = sanitize_url(raw_url)
    if not cleaned_url:
        cleaned_url = "http://empty.local/"

    try:
        parsed = urlparse(cleaned_url)
    except Exception:
        parsed = urlparse("http://malformed.local/")

    scheme = parsed.scheme.lower() if parsed.scheme else ""
    netloc = parsed.netloc.lower() if parsed.netloc else ""
    path = parsed.path if parsed.path else ""
    query = parsed.query if parsed.query else ""

    port = parsed.port
    hostname = parsed.hostname.lower() if parsed.hostname else netloc.split(":")[0]

    url_len = len(cleaned_url)
    host_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    count_dots = cleaned_url.count(".")
    count_hyphens = cleaned_url.count("-")
    count_underscores = cleaned_url.count("_")
    count_slashes = cleaned_url.count("/")
    count_question = cleaned_url.count("?")
    count_equal = cleaned_url.count("=")
    count_at = cleaned_url.count("@")
    count_ampersand = cleaned_url.count("&")
    count_percent = cleaned_url.count("%")
    count_digits = sum(1 for c in cleaned_url if c.isdigit())
    digit_ratio = round(count_digits / url_len, 4) if url_len > 0 else 0.0

    special_chars = sum(1 for c in cleaned_url if not c.isalnum() and c not in "/:.-_?=&")
    all_non_alnum = sum(1 for c in cleaned_url if not c.isalnum())
    suspicious_char_ratio = round(all_non_alnum / url_len, 4) if url_len > 0 else 0.0

    has_ip = 1 if (hostname and IP_REGEX.match(hostname)) else 0
    hostname_present = 1 if len(hostname) > 0 else 0

    subdomain_count = 0
    if hostname:
        parts = hostname.split(".")
        if len(parts) > 2:
            subdomain_count = len(parts) - 2

    domain_len = host_len
    has_https_val = 1 if scheme == "https" else 0
    has_http_val = 1 if scheme == "http" else 0

    suspicious_port = 0
    if port and port not in (80, 443):
        suspicious_port = 1

    unusual_tld = 0
    for tld in HIGH_RISK_TLDS:
        if hostname.endswith(tld):
            unusual_tld = 1
            break

    is_shortened = 1 if hostname in KNOWN_SHORTENERS else 0
    has_punycode = 1 if "xn--" in hostname else 0
    excessive_subdomains = 1 if subdomain_count >= 3 else 0
    hostname_entropy = calculate_shannon_entropy(hostname)

    keyword_features = {}
    total_suspicious_keywords = 0
    combined_text = (hostname + " " + path + " " + query).lower()
    for kw in SUSPICIOUS_KEYWORDS:
        present = 1 if kw in combined_text else 0
        keyword_features[f"kw_{kw}"] = present
        if present:
            total_suspicious_keywords += 1

    features: Dict[str, Any] = {
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "number_of_dots": count_dots,
        "number_of_hyphens": count_hyphens,
        "number_of_underscores": count_underscores,
        "number_of_slashes": count_slashes,
        "number_of_question_marks": count_question,
        "number_of_equal_signs": count_equal,
        "number_of_at_symbols": count_at,
        "number_of_ampersands": count_ampersand,
        "number_of_percent_symbols": count_percent,
        "number_of_digits": count_digits,
        "digit_ratio": digit_ratio,
        "special_character_count": special_chars,
        "suspicious_char_ratio": suspicious_char_ratio,

        "has_ip_address": has_ip,
        "hostname_present": hostname_present,
        "subdomain_count": subdomain_count,
        "domain_length": domain_len,
        "has_https": has_https_val,
        "has_http": has_http_val,
        "suspicious_port": suspicious_port,
        "unusual_tld": unusual_tld,

        "is_shortened_url": is_shortened,
        "has_punycode": has_punycode,
        "excessive_subdomains": excessive_subdomains,
        "hostname_entropy": hostname_entropy,
        "total_suspicious_keywords": total_suspicious_keywords,
    }

    features.update(keyword_features)
    return features


def extract_security_indicators(raw_url: str, features: Dict[str, Any]) -> List[Dict[str, str]]:
    indicators = []

    if features.get("has_https", 0) == 1:
        indicators.append({
            "type": "safe",
            "title": "HTTPS Encryption",
            "description": "Valid HTTPS transport security protocol detected."
        })
    else:
        indicators.append({
            "type": "warning",
            "title": "Missing HTTPS",
            "description": "Unencrypted HTTP or missing SSL/TLS protocol detected."
        })

    if features.get("has_ip_address", 0) == 1:
        indicators.append({
            "type": "danger",
            "title": "Raw IP Hostname",
            "description": "Direct numerical IP address used instead of a registered domain name."
        })
    else:
        indicators.append({
            "type": "safe",
            "title": "Domain Name",
            "description": "Standard alphanumeric domain hostname present."
        })

    if features.get("is_shortened_url", 0) == 1:
        indicators.append({
            "type": "danger",
            "title": "URL Shortener Service",
            "description": "Detected known link shortening service masking actual target destination."
        })

    if features.get("has_punycode", 0) == 1:
        indicators.append({
            "type": "danger",
            "title": "Punycode / Homograph Attack",
            "description": "Internationalized domain encoding ('xn--') detected, commonly used for spoofing."
        })

    if features.get("number_of_at_symbols", 0) > 0:
        indicators.append({
            "type": "danger",
            "title": "Credential Obfuscation (@ symbol)",
            "description": "URL contains '@' symbol, which ignores preceding characters in some browsers."
        })

    if features.get("unusual_tld", 0) == 1:
        indicators.append({
            "type": "warning",
            "title": "High-Risk Top-Level Domain",
            "description": "Domain utilizes a TLD frequently associated with spam or phishing campaigns."
        })

    url_len = features.get("url_length", 0)
    if url_len > 75:
        indicators.append({
            "type": "warning",
            "title": "Excessive URL Length",
            "description": f"URL length is {url_len} characters (long URLs often conceal malicious parameters)."
        })
    else:
        indicators.append({
            "type": "safe",
            "title": "Normal URL Length",
            "description": f"URL length ({url_len} chars) is within benign operating parameters."
        })

    subdomains = features.get("subdomain_count", 0)
    if subdomains >= 3:
        indicators.append({
            "type": "warning",
            "title": "Multiple Subdomains",
            "description": f"Detected {subdomains} subdomains, which may be attempting to impersonate legitimate brand hierarchies."
        })
    else:
        indicators.append({
            "type": "safe",
            "title": "Subdomain Structure",
            "description": "Clean subdomain hierarchy."
        })

    found_keywords = [
        kw for kw in SUSPICIOUS_KEYWORDS if features.get(f"kw_{kw}", 0) == 1
    ]
    if found_keywords:
        indicators.append({
            "type": "warning",
            "title": f"Targeting Keywords ({len(found_keywords)})",
            "description": f"Detected sensitive social engineering keywords: {', '.join(found_keywords)}."
        })
    else:
        indicators.append({
            "type": "safe",
            "title": "Keywords Clean",
            "description": "No overt credential-harvesting keywords found in URL path."
        })

    entropy = features.get("hostname_entropy", 0.0)
    if entropy > 4.2:
        indicators.append({
            "type": "warning",
            "title": "High Hostname Entropy",
            "description": f"Entropy score {entropy:.2f} bits indicates pseudo-random or algorithmically generated domain (DGA)."
        })

    if features.get("suspicious_port", 0) == 1:
        indicators.append({
            "type": "warning",
            "title": "Non-Standard Port",
            "description": "Non-standard network port specified in URL."
        })

    return indicators
