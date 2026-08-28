import re
import math
import ipaddress
from urllib.parse import urlparse
from collections import Counter
from typing import Dict, Any, List

# List of high-risk / commonly abused Top-Level Domains (TLDs)
SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "work", "click", "link", "gq", "cf", "tk", "ml", "ga",
    "rest", "fit", "bid", "country", "stream", "loan", "racing", "win", "men",
    "party", "trade", "accountant", "download", "cfd", "sbs", "icu", "monster",
    "cam", "vip", "ooo", "kim", "mom", "date", "faith", "review", "science",
    "ninja", "rocks", "space", "live", "lat", "uno", "casa", "tokyo", "club",
    "surf", "wang", "cyou", "quest", "beauty", "hair", "skin", "autos", "boats",
    "yokohama", "nagoya", "okinawa", "bar", "pro", "pw"
}

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "is.gd", "cutt.ly", "goo.gl", "ow.ly", "t.co",
    "tiny.cc", "rb.gy", "shorturl.at", "bl.ink", "rebrand.ly", "qr.ae"
}

# High-risk phishing and credential theft keyword patterns
SUSPICIOUS_KEYWORDS = [
    # Authentication & Account Security
    "login", "signin", "sign-in", "log-in", "logon", "signon", "auth", "authenticate",
    "password", "passcode", "credential", "verify", "verification", "validate", "validation",
    "security", "secure", "checkpoint", "two-factor", "2fa", "otp", "re-authenticate",
    "account", "myaccount", "account-recovery", "recover", "unlock", "reactivate",
    "suspended", "suspension", "urgent", "update-required", "action-required",
    
    # Financial & Banking Spoofing
    "paypal", "bank", "chase", "wellsfargo", "citibank", "hsbc", "barclays", "santander",
    "capitalone", "usbank", "pnc", "tdbank", "discover", "americanexpress", "amex",
    "billing", "invoice", "payment", "card-update", "refund", "tax-refund", "direct-deposit",
    
    # Cryptocurrency & Web3
    "crypto", "bitcoin", "ethereum", "binance", "coinbase", "wallet", "metamask",
    "meta-mask", "trustwallet", "ledger", "trezor", "airdrop", "claim-reward",
    "connect-wallet", "seed-phrase",
    
    # Tech Brand Spoofing
    "appleid", "apple-id", "icloud-login", "microsoft-security", "office365",
    "google-drive-share", "onedrive-doc", "dropbox-share", "netflix-verify",
    "amazon-security", "ebay-notice", "facebook-support", "instagram-badge",
    
    # Administrative & Exploits
    "admin", "cpanel", "webmail", "phpmyadmin", "shell", "cmd", "payload",
    "free-gift", "giveaway", "winner", "survey-reward"
]


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes the Shannon Entropy of a string to detect randomized/DGA domains and obfuscated tokens.
    H(X) = -sum(P(x) * log2(P(x)))
    """
    if not text:
        return 0.0
    length = len(text)
    freq = Counter(text)
    return round(-sum((count / length) * math.log2(count / length) for count in freq.values()), 3)


def is_ip(hostname: str) -> bool:
    """Checks if the given hostname string is an IPv4 or IPv6 address."""
    if not hostname:
        return False
    # Strip port if present
    host = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_url(raw_url: str) -> str:
    """Normalizes the input URL by trimming whitespace and ensuring a protocol scheme exists."""
    url = raw_url.strip()
    if not url.startswith("http://") and not url.startswith("https://") and not url.startswith("ftp://"):
        url = "https://" + url
    return url


def extract_url_features(raw_url: str) -> Dict[str, Any]:
    """
    Extracts 27+ structural and lexical features from the target URL.
    Returns a dictionary with comprehensive URL metrics.
    """
    clean_url = raw_url.strip()
    normalized = normalize_url(clean_url)
    parsed = urlparse(normalized)

    # Base parts
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    port = parsed.port
    is_https = parsed.scheme.lower() == "https"

    # Domain & TLD extraction
    domain_parts = hostname.split(".")
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    is_suspicious_tld = tld.lower() in SUSPICIOUS_TLDS

    # Check for IP address usage
    is_ip_addr = is_ip(hostname)

    # Subdomain depth
    # If not an IP, subdomains are parts before domain.tld (e.g. sub.example.com -> sub)
    if is_ip_addr or len(domain_parts) <= 2:
        subdomain_count = 0
    else:
        # e.g. a.b.example.com -> 2 subdomains
        subdomain_count = len(domain_parts) - 2

    # Character counts
    url_length = len(clean_url)
    hostname_length = len(hostname)
    dot_count = clean_url.count(".")
    hyphen_count = clean_url.count("-")
    underscore_count = clean_url.count("_")
    slash_count = clean_url.count("/")
    question_mark_count = clean_url.count("?")
    equal_count = clean_url.count("=")
    at_symbol_count = clean_url.count("@")
    
    # Special characters: @ ! $ * % + ~ ; & #
    special_chars = set("@!$*%+~;&#'\"^`<>{}|\\")
    special_char_count = sum(1 for c in clean_url if c in special_chars)

    # Digit count & ratio
    digit_count = sum(1 for c in clean_url if c.isdigit())
    digit_ratio = round(digit_count / max(url_length, 1), 3)

    # Entropy calculation
    entropy = calculate_shannon_entropy(hostname if hostname else clean_url)
    full_entropy = calculate_shannon_entropy(clean_url)

    # Suspicious keywords matching (search in hostname, path, and query)
    lower_target = clean_url.lower()
    matched_keywords = []
    for kw in SUSPICIOUS_KEYWORDS:
        # Check if keyword is part of the URL
        if kw in lower_target:
            matched_keywords.append(kw)

    # Redirection and obfuscation patterns
    has_at_symbol = at_symbol_count > 0
    # Double slash in path after protocol indicates open redirect attempt
    has_double_slash_redirect = "//" in path
    has_punycode = "xn--" in hostname
    has_port = port is not None and port not in (80, 443)
    is_shortened = hostname.lower() in SHORTENER_DOMAINS or any(
        short in hostname.lower() for short in ("bit.ly", "tinyurl", "is.gd", "cutt.ly")
    )

    return {
        "raw_url": clean_url,
        "normalized_url": normalized,
        "domain": hostname or clean_url,
        "tld": tld,
        "is_https": is_https,
        "is_ip_address": is_ip_addr,
        "url_length": url_length,
        "hostname_length": hostname_length,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "underscore_count": underscore_count,
        "slash_count": slash_count,
        "question_mark_count": question_mark_count,
        "equal_count": equal_count,
        "at_symbol_count": at_symbol_count,
        "special_char_count": special_char_count,
        "digit_count": digit_count,
        "digit_ratio": digit_ratio,
        "subdomain_count": subdomain_count,
        "entropy": entropy,
        "full_entropy": full_entropy,
        "is_suspicious_tld": is_suspicious_tld,
        "suspicious_keywords": matched_keywords,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_redirect": has_double_slash_redirect,
        "has_punycode": has_punycode,
        "has_port": has_port,
        "port": port,
        "is_shortened_url": is_shortened,
    }
