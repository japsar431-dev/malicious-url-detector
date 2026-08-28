const urlInput = document.getElementById("urlInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const result = document.getElementById("result");

// Determine API Base URL dynamically (handles both Live Server / file:// and direct FastAPI hosting)
const API_BASE = "";

analyzeBtn.addEventListener("click", analyzeURL);

async function analyzeURL() {
    const url = urlInput.value.trim();

    if (url === "") {
        result.innerHTML = `
            <p class="warning">
                ⚠ Please enter a URL first.
            </p>
        `;
        return;
    }

    // Show loading state
    analyzeBtn.disabled = true;
    const originalBtnText = analyzeBtn.innerHTML;
    analyzeBtn.innerHTML = `⌕ &nbsp; Scanning...`;
    result.innerHTML = `
        <div style="padding: 20px; color: #8fa0b5; font-size: 16px;">
            ✦ Extracting structural features and analyzing threat heuristics...
        </div>
    `;

    try {
        const response = await fetch(`${API_BASE}/api/scan`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `Server responded with status ${response.status}`);
        }

        const scan = await response.json();
        renderScanResult(scan);

        // Also update local cache for instant offline view if needed
        syncLocalHistory(scan);

    } catch (error) {
        console.error("Scan error:", error);
        result.innerHTML = `
            <div style="background: rgba(255, 32, 45, 0.1); border: 1px solid #ff202d; padding: 18px; border-radius: 12px; margin-top: 20px; text-align: left;">
                <p class="danger" style="margin-bottom: 8px; font-size: 16px;">
                    ✖ Failed to connect to Backend Scanner: ${escapeHTML(error.message)}
                </p>
                <span style="font-size: 13px; color: #88909d; font-weight: normal;">
                    Ensure the FastAPI backend is running on <code>http://127.0.0.1:8000</code> and MySQL is active.
                </span>
            </div>
        `;
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = originalBtnText;
    }
}

function renderScanResult(scan) {
    const riskScore = scan.risk_score;
    const classification = scan.classification;
    const reasons = scan.detection_reasons || [];
    const features = scan.extracted_features || {};

    let statusClass = "safe";
    let statusIcon = "🟢";
    let badgeText = "URL Appears Safe";

    if (classification === "MALICIOUS" || riskScore >= 71) {
        statusClass = "danger";
        statusIcon = "🔴";
        badgeText = "Malicious / High Risk URL";
    } else if (classification === "SUSPICIOUS" || riskScore >= 31) {
        statusClass = "warning";
        statusIcon = "🟡";
        badgeText = "Suspicious URL";
    }

    let reasonsHtml = "";
    if (reasons.length > 0) {
        reasonsHtml = `
            <div style="margin-top: 18px; text-align: left; background: #080b13; border: 1px solid #1c222e; border-radius: 12px; padding: 16px 20px;">
                <div style="font-size: 13px; letter-spacing: 1.5px; color: #8c97a8; font-weight: bold; margin-bottom: 12px;">
                    DETECTION HEURISTICS & REASONS
                </div>
                <ul style="list-style: none; padding: 0; margin: 0;">
                    ${reasons.map(r => `
                        <li style="font-size: 14px; font-weight: normal; color: #d0d7e2; padding: 5px 0; display: flex; align-items: flex-start; gap: 8px;">
                            <span style="color: ${statusClass === 'danger' ? '#ff3038' : statusClass === 'warning' ? '#ffd34d' : '#35e58a'}; font-weight: bold;">▸</span>
                            <span>${escapeHTML(r)}</span>
                        </li>
                    `).join('')}
                </ul>
            </div>
        `;
    }

    let featuresSummaryHtml = "";
    if (features) {
        featuresSummaryHtml = `
            <div style="margin-top: 14px; display: flex; gap: 10px; flex-wrap: wrap; justify-content: center; font-size: 12px; font-weight: normal; color: #9da6b4;">
                <span style="background: #10141f; border: 1px solid #232a38; padding: 6px 12px; border-radius: 8px;">
                    Domain: <strong style="color: #fff;">${escapeHTML(scan.domain || features.domain || 'N/A')}</strong>
                </span>
                <span style="background: #10141f; border: 1px solid #232a38; padding: 6px 12px; border-radius: 8px;">
                    TLD: <strong style="color: ${features.is_suspicious_tld ? '#ff3038' : '#fff'};">.${escapeHTML(features.tld || 'none')}</strong>
                </span>
                <span style="background: #10141f; border: 1px solid #232a38; padding: 6px 12px; border-radius: 8px;">
                    Protocol: <strong style="color: ${features.is_https ? '#35e58a' : '#ffd34d'};">${features.is_https ? 'HTTPS' : 'HTTP'}</strong>
                </span>
                <span style="background: #10141f; border: 1px solid #232a38; padding: 6px 12px; border-radius: 8px;">
                    Entropy: <strong style="color: #fff;">${features.entropy || 0}</strong>
                </span>
                <span style="background: #10141f; border: 1px solid #232a38; padding: 6px 12px; border-radius: 8px;">
                    Classification: <strong style="color: ${statusClass === 'danger' ? '#ff3038' : statusClass === 'warning' ? '#ffd34d' : '#35e58a'};">${classification}</strong>
                </span>
            </div>
        `;
    }

    result.innerHTML = `
        <div style="margin-top: 25px; animation: fadeIn 0.3s ease;">
            <p class="${statusClass}">
                ${statusIcon} ${badgeText} — Risk Score: ${riskScore}/100 [${classification}]
            </p>
            ${featuresSummaryHtml}
            ${reasonsHtml}
        </div>
    `;
}

function syncLocalHistory(scan) {
    try {
        const history = JSON.parse(localStorage.getItem("hackVortexHistory")) || [];
        const item = {
            id: scan.id,
            url: scan.url,
            score: scan.risk_score,
            status: scan.classification === "MALICIOUS" ? "danger" : scan.classification === "SUSPICIOUS" ? "warning" : "safe",
            time: new Date(scan.created_at || Date.now()).toLocaleString()
        };
        history.unshift(item);
        if (history.length > 50) history.pop();
        localStorage.setItem("hackVortexHistory", JSON.stringify(history));
    } catch (e) {
        // LocalStorage fallback error ignored
    }
}

function escapeHTML(text) {
    if (!text) return "";
    const div = document.createElement("div");
    div.textContent = String(text);
    return div.innerHTML;
}

// Example buttons
const examples = document.querySelectorAll(".example");
examples.forEach(function (example) {
    example.addEventListener("click", function () {
        const text = example.textContent
            .replace("🔗", "")
            .trim();
        urlInput.value = text;
        urlInput.focus();
    });
});

// Press Enter to analyze
urlInput.addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
        analyzeBtn.click();
    }
});

function logout() {
    localStorage.removeItem("hackvortexloggedin");
    localStorage.removeItem("hackvortexuser");
    window.location.href = "/login.html";
}