import json
import urllib.request
import urllib.error

SERVER_URL = "http://127.0.0.1:8000"

def test_static_pages():
    pages = ["/", "/history.html", "/analytics.html", "/login.html", "/landing.html"]
    for p in pages:
        req = urllib.request.Request(f"{SERVER_URL}{p}")
        with urllib.request.urlopen(req) as res:
            assert res.status == 200
            content = res.read().decode("utf-8")
            assert "HackVortex" in content
            print(f"[OK] Static page served: {p} (HTTP {res.status}, {len(content)} bytes)")

def test_api_health():
    req = urllib.request.Request(f"{SERVER_URL}/api/health/db")
    with urllib.request.urlopen(req) as res:
        assert res.status == 200
        data = json.loads(res.read().decode("utf-8"))
        print(f"[OK] API Health DB check: {data}")

def test_live_scan():
    samples = [
        "https://google.com",
        "https://paypal-secure.com/account/verify?id=abc123",
        "http://192.168.1.1/login",
        "https://bit.ly/3xYzKp",
        "http://crypto-metamask-claim.xyz/airdrop"
    ]
    
    for sample in samples:
        req_data = json.dumps({"url": sample}).encode("utf-8")
        req = urllib.request.Request(
            f"{SERVER_URL}/api/scan",
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req) as res:
            assert res.status == 201
            scan = json.loads(res.read().decode("utf-8"))
            print(f"[OK] Scanned '{sample}':")
            print(f"     -> Score: {scan['risk_score']}/100 [{scan['classification']}]")
            print(f"     -> Domain: {scan['domain']}")
            print(f"     -> Detection Reasons ({len(scan['detection_reasons'])}): {scan['detection_reasons'][:2]}")

def test_live_history():
    req = urllib.request.Request(f"{SERVER_URL}/api/history")
    with urllib.request.urlopen(req) as res:
        assert res.status == 200
        history = json.loads(res.read().decode("utf-8"))
        print(f"[OK] History API returned {len(history)} live scan records")
        assert len(history) >= 5

def test_live_analytics():
    req = urllib.request.Request(f"{SERVER_URL}/api/analytics")
    with urllib.request.urlopen(req) as res:
        assert res.status == 200
        analytics = json.loads(res.read().decode("utf-8"))
        print(f"[OK] Analytics API returned:")
        print(f"     -> Total Scans: {analytics['total_scans']}")
        print(f"     -> Safe Scans: {analytics['safe_scans']} ({analytics['safe_percentage']}%)")
        print(f"     -> Suspicious Scans: {analytics['suspicious_scans']} ({analytics['suspicious_percentage']}%)")
        print(f"     -> Malicious Scans: {analytics['malicious_scans']} ({analytics['malicious_percentage']}%)")
        print(f"     -> Avg Risk Score: {analytics['average_risk_score']}")
        print(f"     -> Unique Domains: {analytics['unique_domains']}")

if __name__ == "__main__":
    print("Testing live FastAPI + Database server on http://127.0.0.1:8000...")
    test_static_pages()
    test_api_health()
    test_live_scan()
    test_live_history()
    test_live_analytics()
    print("All live end-to-end integration tests PASSED!")
