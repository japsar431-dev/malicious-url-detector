// Determine API Base URL dynamically
const API_BASE = "";

document.addEventListener("DOMContentLoaded", loadAnalytics);

async function loadAnalytics() {
    try {
        const response = await fetch(`${API_BASE}/api/analytics`);
        if (!response.ok) {
            throw new Error(`Failed to fetch analytics (Status: ${response.status})`);
        }

        const data = await response.json();
        updateAnalyticsUI(data);

    } catch (error) {
        console.warn("Backend analytics fetch failed, falling back to local calculation:", error);
        computeLocalAnalyticsFallback();
    }
}

function updateAnalyticsUI(data) {
    const total = data.total_scans || 0;
    const safe = data.safe_scans || 0;
    const suspicious = data.suspicious_scans || 0;
    const malicious = data.malicious_scans || 0;
    const average = data.average_risk_score || 0;
    const uniqueDomains = data.unique_domains || 0;

    const safePercent = Math.round(data.safe_percentage || 0);
    const suspiciousPercent = Math.round(data.suspicious_percentage || 0);
    const maliciousPercent = Math.round(data.malicious_percentage || 0);

    // Stat cards
    document.getElementById("totalScans").textContent = total;
    document.getElementById("safeScans").textContent = safe;
    document.getElementById("suspiciousScans").textContent = suspicious;
    document.getElementById("maliciousScans").textContent = malicious;
    document.getElementById("averageScore").textContent = average;
    document.getElementById("uniqueDomains").textContent = uniqueDomains;

    // Percentages labels
    document.getElementById("safePercent").textContent = safePercent + "%";
    document.getElementById("suspiciousPercent").textContent = suspiciousPercent + "%";
    document.getElementById("maliciousPercent").textContent = maliciousPercent + "%";

    // Progress bars
    document.getElementById("safeBar").style.width = safePercent + "%";
    document.getElementById("suspiciousBar").style.width = suspiciousPercent + "%";
    document.getElementById("maliciousBar").style.width = maliciousPercent + "%";

    // Toggle No Data notice
    const noDataEl = document.getElementById("noData");
    if (noDataEl) {
        noDataEl.style.display = total === 0 ? "block" : "none";
    }
}

function computeLocalAnalyticsFallback() {
    const history = JSON.parse(localStorage.getItem("hackVortexHistory")) || [];
    const total = history.length;
    let safe = 0;
    let suspicious = 0;
    let malicious = 0;
    let totalRisk = 0;
    const domains = new Set();

    history.forEach(function (scan) {
        const score = Number(scan.score || scan.risk_score) || 0;
        totalRisk += score;

        if (scan.status === "safe" || score <= 30) {
            safe++;
        } else if (scan.status === "warning" || (score >= 31 && score <= 70)) {
            suspicious++;
        } else if (scan.status === "danger" || score >= 71) {
            malicious++;
        }

        try {
            let address = (scan.url || "").trim();
            if (!address.startsWith("http://") && !address.startsWith("https://")) {
                address = "https://" + address;
            }
            const url = new URL(address);
            domains.add(url.hostname);
        } catch (e) { }
    });

    const average = total > 0 ? Math.round(totalRisk / total) : 0;
    const safePercent = total > 0 ? Math.round((safe / total) * 100) : 0;
    const suspiciousPercent = total > 0 ? Math.round((suspicious / total) * 100) : 0;
    const maliciousPercent = total > 0 ? Math.round((malicious / total) * 100) : 0;

    updateAnalyticsUI({
        total_scans: total,
        safe_scans: safe,
        suspicious_scans: suspicious,
        malicious_scans: malicious,
        average_risk_score: average,
        unique_domains: domains.size,
        safe_percentage: safePercent,
        suspicious_percentage: suspiciousPercent,
        malicious_percentage: maliciousPercent
    });
}