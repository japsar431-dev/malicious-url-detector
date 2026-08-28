const historyList = document.getElementById("historyList");

// Determine API Base URL dynamically
const API_BASE = window.location.origin.includes(":8000") ? "" : "http://127.0.0.1:8000";

document.addEventListener("DOMContentLoaded", fetchScanHistory);

async function fetchScanHistory() {
    // Show loading state
    historyList.innerHTML = `
        <div style="padding: 30px; text-align: center; color: #697486; font-size: 15px;">
            ✦ Loading scan history from database...
        </div>
    `;

    try {
        const response = await fetch(`${API_BASE}/api/history?limit=100`);
        if (!response.ok) {
            throw new Error(`Failed to load history (Status: ${response.status})`);
        }

        const data = await response.json();
        renderHistoryList(data);

    } catch (error) {
        console.warn("Backend fetch failed, checking local cache:", error);
        
        // Fallback to local storage cache if backend is starting or offline
        const localHistory = JSON.parse(localStorage.getItem("hackVortexHistory")) || [];
        if (localHistory.length > 0) {
            renderHistoryList(localHistory, true);
        } else {
            historyList.innerHTML = `
                <div style="background: rgba(255, 32, 45, 0.08); border: 1px solid rgba(255, 32, 45, 0.2); padding: 25px; border-radius: 12px; text-align: center;">
                    <p style="color: #ff3038; font-weight: bold; margin-bottom: 8px;">
                        ⚠ Could not connect to backend server
                    </p>
                    <p style="color: #88909d; font-size: 13px;">
                        Start the FastAPI server (<code>python run_backend.py</code>) to view full history from MySQL.
                    </p>
                </div>
            `;
        }
    }
}

function renderHistoryList(scans, isLocalFallback = false) {
    if (!scans || scans.length === 0) {
        historyList.innerHTML = `
            <div style="padding: 40px 20px; text-align: center; color: #727e90; background: #080c15; border: 1px dashed #1e2838; border-radius: 12px;">
                <p style="font-size: 16px; margin-bottom: 8px; color: #fff;">No scans recorded yet</p>
                <span style="font-size: 13px;">Go to the <a href="index.html" style="color: #ff3038; text-decoration: underline;">Scanner</a> to analyze your first URL.</span>
            </div>
        `;
        return;
    }

    historyList.innerHTML = "";

    if (isLocalFallback) {
        const notice = document.createElement("div");
        notice.style.cssText = "padding: 10px 15px; margin-bottom: 12px; background: rgba(255, 211, 77, 0.08); border: 1px solid rgba(255, 211, 77, 0.2); border-radius: 8px; color: #ffd34d; font-size: 12px;";
        notice.textContent = "ℹ Showing cached scans while backend is connecting...";
        historyList.appendChild(notice);
    }

    scans.forEach(function(scan) {
        const riskScore = scan.risk_score !== undefined ? scan.risk_score : scan.score;
        const classification = scan.classification || (scan.status === "danger" ? "MALICIOUS" : scan.status === "warning" ? "SUSPICIOUS" : "SAFE");

        let icon = "✓";
        let statusClass = "safe";
        let scoreClass = "safe-text";

        if (classification === "SUSPICIOUS" || (riskScore >= 31 && riskScore <= 70)) {
            icon = "!";
            statusClass = "warning";
            scoreClass = "warning-text";
        } else if (classification === "MALICIOUS" || riskScore >= 71) {
            icon = "!";
            statusClass = "danger";
            scoreClass = "danger-text";
        }

        const formattedTime = formatTimestamp(scan.created_at || scan.time);

        const item = document.createElement("div");
        item.className = "history-item";

        item.innerHTML = `
            <div class="status ${statusClass}">
                ${icon}
            </div>

            <div class="scan-info">
                <div class="url">
                    ${escapeHTML(scan.url)}
                </div>

                <div class="details">
                    <span class="score ${scoreClass}">
                        ${riskScore}/100 [${classification}]
                    </span>
                    <span>
                        ${formattedTime}
                    </span>
                    ${scan.domain ? `<span style="color: #4b5568;">• ${escapeHTML(scan.domain)}</span>` : ""}
                </div>
            </div>
        `;

        item.addEventListener("click", function() {
            showScanModal(scan, riskScore, classification, formattedTime);
        });

        historyList.appendChild(item);
    });
}

function showScanModal(scan, riskScore, classification, formattedTime) {
    const reasons = scan.detection_reasons || [];
    const reasonsList = reasons.length > 0 
        ? reasons.map(r => `• ${r}`).join("\n") 
        : "• No threat indicators triggered";

    alert(
        "✦ HackVortex Scan Details\n" +
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
        "URL: " + scan.url + "\n" +
        "Domain: " + (scan.domain || "N/A") + "\n" +
        "Risk Score: " + riskScore + "/100\n" +
        "Classification: " + classification + "\n" +
        "Scanned At: " + formattedTime + "\n\n" +
        "Detection Reasons:\n" + reasonsList
    );
}

function formatTimestamp(timestamp) {
    if (!timestamp) return "Recently";
    try {
        const date = new Date(timestamp);
        if (isNaN(date.getTime())) return String(timestamp);
        
        // Relative time or localized format
        const diffSeconds = Math.floor((Date.now() - date.getTime()) / 1000);
        if (diffSeconds < 60) return "Just now";
        if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
        if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;
        
        return date.toLocaleDateString() + " " + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (e) {
        return String(timestamp);
    }
}

// Prevent HTML injection
function escapeHTML(text) {
    if (!text) return "";
    const div = document.createElement("div");
    div.textContent = String(text);
    return div.innerHTML;
}