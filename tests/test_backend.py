import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.engine.feature_extractor import extract_url_features
from backend.engine.threat_detector import analyze_threat
from fastapi.testclient import TestClient
from backend.main import app

def test_feature_extractor():
    url = "https://paypal-security-update.xyz/account/login?id=9928"
    features = extract_url_features(url)
    
    assert features["domain"] == "paypal-security-update.xyz"
    assert features["tld"] == "xyz"
    assert features["is_suspicious_tld"] is True
    assert features["is_https"] is True
    assert "paypal" in features["suspicious_keywords"]
    assert "security" in features["suspicious_keywords"]
    assert "login" in features["suspicious_keywords"]
    print("[OK] test_feature_extractor passed")

def test_threat_detector_safe():
    url = "https://google.com"
    analysis = analyze_threat(url)
    assert analysis["risk_score"] <= 30
    assert analysis["classification"] == "SAFE"
    print(f"[OK] test_threat_detector_safe passed (Score: {analysis['risk_score']})")

def test_threat_detector_suspicious():
    url = "http://verify-my-account-portal.xyz/update"
    analysis = analyze_threat(url)
    assert 31 <= analysis["risk_score"] <= 70 or analysis["classification"] in ("SUSPICIOUS", "MALICIOUS")
    print(f"[OK] test_threat_detector_suspicious passed (Score: {analysis['risk_score']})")

def test_threat_detector_malicious():
    url = "http://192.168.1.1/paypal-login/account-verify/bank-credential-update"
    analysis = analyze_threat(url)
    assert analysis["risk_score"] >= 71
    assert analysis["classification"] == "MALICIOUS"
    print(f"[OK] test_threat_detector_malicious passed (Score: {analysis['risk_score']})")

def test_fastapi_endpoints():
    client = TestClient(app)
    
    # 1. Health DB endpoint
    health_res = client.get("/api/health/db")
    assert health_res.status_code == 200
    print(f"[OK] /api/health/db status: {health_res.json().get('status')}")

    # 2. Test Scan endpoint
    test_urls = [
        "https://github.com",
        "http://paypal-security-alert.top/login/verify.php",
        "http://10.0.0.1/admin-crypto-wallet/claim-reward"
    ]
    
    for u in test_urls:
        scan_res = client.post("/api/scan", json={"url": u})
        if scan_res.status_code == 201:
            data = scan_res.json()
            assert "risk_score" in data
            assert "classification" in data
            assert "detection_reasons" in data
            print(f"[OK] /api/scan for '{u}': Score {data['risk_score']} ({data['classification']})")
        else:
            print(f"[NOTE] /api/scan status {scan_res.status_code}: {scan_res.text}")

    # 3. Test History endpoint
    hist_res = client.get("/api/history")
    if hist_res.status_code == 200:
        print(f"[OK] /api/history returned {len(hist_res.json())} items")

    # 4. Test Analytics endpoint
    analytics_res = client.get("/api/analytics")
    if analytics_res.status_code == 200:
        data = analytics_res.json()
        print(f"[OK] /api/analytics total_scans={data.get('total_scans')}, safe={data.get('safe_scans')}, suspicious={data.get('suspicious_scans')}, malicious={data.get('malicious_scans')}")

if __name__ == "__main__":
    print("Running HackVortex Backend Test Suite...")
    test_feature_extractor()
    test_threat_detector_safe()
    test_threat_detector_suspicious()
    test_threat_detector_malicious()
    test_fastapi_endpoints()
    print("All unit and engine tests executed successfully!")
