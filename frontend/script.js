const scanButton = document.getElementById("scanButton");
const urlInput = document.getElementById("urlInput");
const resultDiv = document.getElementById("result");

scanButton.addEventListener("click", async () => {

    let url = urlInput.value.trim();

    if (!url) {
        resultDiv.innerHTML = "<p>Please enter a website URL.</p>";
        return;
    }

    // Add HTTPS automatically if user doesn't provide a protocol
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
        url = "https://" + url;
    }

    try {
    new URL(url);
} catch {
    resultDiv.innerHTML = `
        <div class="finding">
            <h3>❌ Invalid URL</h3>
            <p>Please enter a valid website URL.</p>
            <p>Example: https://google.com</p>
        </div>
    `;
    return;
}

    resultDiv.innerHTML = "<p>🔍 Analyzing website...</p>";

    try {

        const response = await fetch(
            `http://127.0.0.1:8000/scan?url=${encodeURIComponent(url)}`
        );

        if (!response.ok) {
            throw new Error("ThreatLens server returned an error.");
        }

        const data = await response.json();

        console.log("ThreatLens Result:", data);

        // Determine risk colour
        let riskClass = "low";

        if (data.riskScore > 80) {
            riskClass = "critical";
        } else if (data.riskScore > 50) {
            riskClass = "high";
        } else if (data.riskScore > 20) {
            riskClass = "moderate";
        }

        // Generate security findings
        const findingTitles = {
    "TARGETED_PHISHING": "🎯 Targeted phishing attempt detected",        
    "BRAND_IMPERSONATION": "🎭 Brand impersonation detected",
    "IP_ADDRESS": "🖥 Website uses an IP address",
    "LONG_URL": "📏 Unusually long URL",
    "AT_SYMBOL": "📧 URL contains '@' symbol",
    "ENCODED_URL": "🔐 Encoded URL detected",
    "MULTIPLE_SUBDOMAINS": "🌍 Multiple subdomains detected",
    "MULTIPLE_HYPHENS": "➖ Multiple hyphens in domain",
    "INVALID_URL": "❌ Invalid website address",
    "NO_HTTPS": "🔒 Website is not using HTTPS",
    "SUSPICIOUS_TLD": "🌐 Suspicious domain extension",
    "SUSPICIOUS_KEYWORDS": "⚠ Sensitive keywords detected",
    "LOGIN_OVER_HTTP": "🚨 Login page without HTTPS",
    "CHARACTER_SUBSTITUTION": "🎭 Brand impersonation detected",
    "POSSIBLE_TYPOSQUATTING": "🔍 Possible typosquatting detected",
    "HIGH_PHISHING_CONFIDENCE": "🚨 High phishing confidence"
};
        let findingsHTML = "";

        if (!data.findings || data.findings.length === 0) {

            findingsHTML = `
                <div class="safe-message">
                    ✅ No suspicious URL indicators detected.
                </div>
            `;

        } else {

            findingsHTML = data.findings.map(finding => `
                <div class="finding">

                    <strong>${findingTitles[finding.id] || finding.id}</strong>

                    <p>${finding.message}</p>

                    <small>
                        Severity: ${finding.severity}
                        &nbsp; | &nbsp;
                        Risk: +${finding.score}
                    </small>

                </div>
            `).join("");
        }

        // Display final ThreatLens report
        resultDiv.innerHTML = `

            <div class="report">

                <h2>ThreatLens Security Report</h2>

                <p class="scanned-url">
                    ${data.url}
                </p>

                <div class="risk-container">

                    <div class="risk-circle ${riskClass}">

                        <span class="risk-number">
                            ${data.riskScore}%
                        </span>

                        <span class="risk-status">
                            ${data.status} RISK
                        </span>

                    </div>

                </div>

                <h3>Security Findings</h3>

                ${findingsHTML}

            </div>
        `;

    } catch (error) {

        console.error("ThreatLens Error:", error);

        resultDiv.innerHTML = `
            <p>
                ❌ Unable to connect to the ThreatLens server.
            </p>
        `;
    }
});