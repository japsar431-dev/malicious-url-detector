from typing import Dict, Any, Tuple, List
from backend.engine.feature_extractor import extract_url_features


def analyze_threat(raw_url: str) -> Dict[str, Any]:
    """
    Evaluates heuristic threat rules over extracted features.
    Computes a risk score from 0–100, determines classification (SAFE, SUSPICIOUS, MALICIOUS),
    and compiles human-readable detection reasons.
    """
    features = extract_url_features(raw_url)
    
    score = 0
    reasons: List[str] = []

    # 1. IP Address Usage
    if features["is_ip_address"]:
        score += 35
        reasons.append("Host is represented directly as an IP address instead of a domain name (+35)")

    # 2. Suspicious / Abused TLD
    if features["is_suspicious_tld"]:
        score += 25
        tld_val = features["tld"]
        reasons.append(f"Uses high-risk/frequently abused top-level domain '.{tld_val}' (+25)")

    # 3. Suspicious / Phishing Keywords
    keywords = features["suspicious_keywords"]
    if keywords:
        kw_count = len(keywords)
        if kw_count >= 3:
            score += 35
            reasons.append(f"Multiple high-risk phishing/credential theft keywords found ({', '.join(keywords[:5])}) (+35)")
        elif kw_count == 2:
            score += 25
            reasons.append(f"Suspicious security/credential keywords detected ({', '.join(keywords)}) (+25)")
        else:
            score += 15
            reasons.append(f"Phishing-sensitive keyword found in URL ('{keywords[0]}') (+15)")

        # Compound spoofing pattern check (e.g. brand + login/verify/secure)
        brand_tokens = {"paypal", "bank", "chase", "apple", "netflix", "crypto", "wallet", "binance", "meta"}
        action_tokens = {"login", "verify", "security", "secure", "account", "update", "recovery"}
        has_brand = any(b in features["raw_url"].lower() for b in brand_tokens)
        has_action = any(a in features["raw_url"].lower() for a in action_tokens)
        if has_brand and has_action and not features["domain"].endswith((".paypal.com", ".apple.com", ".netflix.com", ".chase.com")):
            score += 20
            reasons.append("Compound brand impersonation syntax detected with action terms (+20)")

    # 4. Shannon Entropy (Randomized / DGA Strings)
    if features["entropy"] >= 4.1:
        score += 25
        reasons.append(f"High hostname entropy ({features['entropy']:.2f}) indicates algorithmic domain generation (DGA) (+25)")
    elif features["entropy"] >= 3.75:
        score += 15
        reasons.append(f"Elevated domain entropy ({features['entropy']:.2f}) suggests obfuscated naming (+15)")

    # 5. URL Length Anomaly
    if features["url_length"] > 120:
        score += 20
        reasons.append(f"Excessive URL length ({features['url_length']} characters) used to obscure payload (+20)")
    elif features["url_length"] > 80:
        score += 10
        reasons.append(f"Abnormally long URL length ({features['url_length']} characters) (+10)")

    # 6. Deep Subdomain Nesting
    if features["subdomain_count"] >= 3:
        score += 20
        reasons.append(f"Excessive subdomain depth ({features['subdomain_count']} levels) used to disguise true host (+20)")
    elif features["subdomain_count"] == 2:
        score += 10
        reasons.append(f"Multiple subdomain levels ({features['subdomain_count']} levels) (+10)")

    # 7. Unusually High Dot Count
    if features["dot_count"] >= 4:
        score += 15
        reasons.append(f"High dot count ({features['dot_count']} dots) in URL structure (+15)")

    # 8. Excessive Hyphens & Special Characters
    if features["hyphen_count"] >= 3:
        score += 10
        reasons.append(f"Excessive hyphens in URL ({features['hyphen_count']} hyphens) (+10)")

    if features["special_char_count"] >= 4:
        score += 10
        reasons.append(f"Unusual density of special characters ({features['special_char_count']} special chars) (+10)")

    # 9. Authority Spoofing (@ symbol)
    if features["has_at_symbol"]:
        score += 30
        reasons.append("URL contains '@' character, typically used for authority spoofing / deceptive redirects (+30)")

    # 10. Open Redirect / Double Slash in Path
    if features["has_double_slash_redirect"]:
        score += 20
        reasons.append("Double slash '//' pattern in path detected, potential open redirect vector (+20)")

    # 11. Punycode / IDN Homograph Spoofing
    if features["has_punycode"]:
        score += 25
        reasons.append("Punycode (xn--) detected, possible internationalized domain homograph attack (+25)")

    # 12. Non-standard Port
    if features["has_port"]:
        score += 15
        reasons.append(f"Non-standard network port ({features['port']}) specified in target (+15)")

    # 13. URL Shortener Service
    if features["is_shortened_url"]:
        score += 15
        reasons.append("URL shortening service detected (destination endpoint is masked) (+15)")

    # 14. Insecure Protocol with Credential Target
    if not features["is_https"] and (keywords or features["is_ip_address"]):
        score += 15
        reasons.append("Insecure HTTP protocol used on sensitive/authentication target (+15)")

    # Clamp score strictly between 0 and 100
    risk_score = min(max(score, 0), 100)

    # Classification according to requirements:
    # 0–30: SAFE
    # 31–70: SUSPICIOUS
    # 71–100: MALICIOUS
    if risk_score <= 30:
        classification = "SAFE"
    elif risk_score <= 70:
        classification = "SUSPICIOUS"
    else:
        classification = "MALICIOUS"

    # Default reassurance reasons if safe/clean
    if not reasons:
        reasons = [
            "No malicious or suspicious threat heuristics triggered.",
            "Standard domain naming convention and structure.",
            "Protocol and entropy values within normal thresholds."
        ]

    return {
        "url": features["raw_url"],
        "domain": features["domain"],
        "risk_score": risk_score,
        "classification": classification,
        "detection_reasons": reasons,
        "extracted_features": features,
    }
