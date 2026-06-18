const API_URL = "/scan";

let currentScanResult = null;

const riskWidth = {
    clean: 5,
    low: 25,
    medium: 55,
    high: 85,
    critical: 100
};

const riskColor = {
    clean: "#22c55e",
    low: "#eab308",
    medium: "#f97316",
    high: "#ef4444",
    critical: "#dc2626"
};

const riskIcons = {
    clean: "✅",
    low: "⚠️",
    medium: "🟠",
    high: "🔴",
    critical: "☠️"
};

const riskTitles = {
    clean: "Clean File",
    low: "Low Risk",
    medium: "Medium Risk",
    high: "High Risk",
    critical: "Critical Threat"
};

const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("fileInput");

dropzone.addEventListener("click", () => {
    fileInput.click();
});

fileInput.addEventListener("change", () => {
    if (fileInput.files.length) {
        handleFile(fileInput.files[0]);
    }
});

dropzone.addEventListener("dragover", e => {
    e.preventDefault();
    dropzone.classList.add("dragover");
});

dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("dragover");
});

dropzone.addEventListener("drop", e => {
    e.preventDefault();

    dropzone.classList.remove("dragover");

    const file = e.dataTransfer.files[0];

    if (file) {
        handleFile(file);
    }
});

async function handleFile(file) {

    document.getElementById("loadingSection").classList.remove("hidden");
    document.getElementById("results").classList.add("hidden");

    const formData = new FormData();
    formData.append("file", file);

    try {

        const response = await fetch(API_URL, {
            method: "POST",
            body: formData
        });

        const result = await response.json();

        document.getElementById("loadingSection").classList.add("hidden");

        if (result.error) {
            alert(result.error);
            return;
        }

        currentScanResult = result;

        renderResults(result);

    } catch (err) {

        document.getElementById("loadingSection").classList.add("hidden");

        alert("Scan failed.");

        console.error(err);
    }
}

function animateNumber(elementId, target, suffix = "") {

    const element = document.getElementById(elementId);

    let current = 0;

    const step = Math.max(1, Math.floor(target / 50));

    const interval = setInterval(() => {

        current += step;

        if (current >= target) {

            current = target;

            clearInterval(interval);
        }

        element.textContent = current + suffix;

    }, 20);
}

function renderResults(result) {

    document.getElementById("results").classList.remove("hidden");

    renderStatus(result);

    renderMetrics(result);

    renderVirusTotal(result);

    renderYara(result);

    renderSuspiciousLines(result);

    renderKeywords(result);

    renderPatterns(result);

    renderUrls(result);

    renderIPs(result);

    renderMetadata(result);
}

function renderStatus(result) {

    const risk = result.risk_level;

    const card = document.getElementById("statusCard");

    card.className = `status-card ${risk}`;

    document.getElementById("statusIcon").textContent =
        riskIcons[risk];

    document.getElementById("statusTitle").textContent =
        riskTitles[risk];

    document.getElementById("statusSub").textContent =
        result.summary;

    const bar = document.getElementById("riskBar");

    bar.style.width =
        riskWidth[risk] + "%";

    bar.style.background =
        riskColor[risk];
}

function renderMetrics(result) {

    animateNumber(
        "metricScore",
        result.score
    );

    animateNumber(
        "metricConfidence",
        result.confidence || 0,
        "%"
    );

    document.getElementById("metricEntropy").textContent =
        result.entropy;

    document.getElementById("metricChunks").textContent =
        result.high_entropy_chunks || 0;

    document.getElementById("metricScanTime").textContent =
        `${result.scan_time || 0}s`;

    const findings =
        (result.found_keywords?.length || 0) +
        (result.found_patterns?.length || 0) +
        (result.yara_matches?.length || 0);

    document.getElementById("metricFindings").textContent =
        findings;
}

function renderVirusTotal(result) {

    const container =
        document.getElementById("virustotalPanel");

    const vt = result.virustotal;

    if (!vt) {

        container.innerHTML = `
            <div class="empty-state">
                VirusTotal not configured
            </div>
        `;

        return;
    }

    container.innerHTML = `
        <div class="vt-grid">

            <div class="vt-card">
                <h3>Malicious</h3>
                <span class="malicious">
                    ${vt.malicious || 0}
                </span>
            </div>

            <div class="vt-card">
                <h3>Suspicious</h3>
                <span class="suspicious">
                    ${vt.suspicious || 0}
                </span>
            </div>

            <div class="vt-card">
                <h3>Harmless</h3>
                <span class="harmless">
                    ${vt.harmless || 0}
                </span>
            </div>

        </div>
    `;
}

function renderYara(result) {

    const container =
        document.getElementById("yaraContainer");

    const matches =
        result.yara_matches || [];

    if (!matches.length) {

        container.innerHTML = `
            <div class="empty-state">
                No YARA matches
            </div>
        `;

        return;
    }

    container.innerHTML = "";

    matches.forEach(match => {

        const badge =
            document.createElement("span");

        badge.className =
            "badge badge-red";

        badge.textContent =
            match;

        container.appendChild(badge);
    });
}

function renderSuspiciousLines(result) {

    const container =
        document.getElementById("suspiciousLines");

    const lines =
        result.suspicious_lines || [];

    if (!lines.length) {

        container.innerHTML = `
            <div class="empty-state">
                No suspicious lines detected
            </div>
        `;

        return;
    }

    container.innerHTML = "";

    lines.forEach(line => {

        const div =
            document.createElement("div");

        div.className =
            "code-line";

        div.innerHTML = `
            <div class="line-number">
                Line ${line.line}
                (${line.reason})
            </div>

            <pre>${escapeHtml(line.content)}</pre>
        `;

        container.appendChild(div);
    });
}

function renderKeywords(result) {

    const container =
        document.getElementById("keywordItems");

    const keywords =
        result.found_keywords || [];

    if (!keywords.length) {

        container.innerHTML = `
            <div class="empty-state">
                No keywords detected
            </div>
        `;

        return;
    }

    container.innerHTML = "";

    keywords.forEach(keyword => {

        const div =
            document.createElement("div");

        div.className =
            "keyword-item";

        div.textContent =
            keyword;

        container.appendChild(div);
    });
}

function renderPatterns(result) {

    const container =
        document.getElementById("patternItems");

    const patterns =
        result.found_patterns || [];

    if (!patterns.length) {

        container.innerHTML = `
            <div class="empty-state">
                No pattern matches
            </div>
        `;

        return;
    }

    container.innerHTML = "";

    patterns.forEach(pattern => {

        const div =
            document.createElement("div");

        div.className =
            "pattern-item";

        if (typeof pattern === "object") {

            div.textContent =
                `${pattern.label} (${pattern.severity})`;

        } else {

            div.textContent =
                pattern;
        }

        container.appendChild(div);
    });
}

function renderUrls(result) {

    const container =
        document.getElementById("urlContainer");

    const urls =
        result.urls || [];

    if (!urls.length) {

        container.innerHTML = `
            <div class="empty-state">
                No URLs detected
            </div>
        `;

        return;
    }

    container.innerHTML = "";

    urls.forEach(url => {

        const div =
            document.createElement("div");

        div.className =
            "list-item";

        div.textContent =
            url;

        container.appendChild(div);
    });
}

function renderIPs(result) {

    const container =
        document.getElementById("ipContainer");

    const ips =
        result.ips || [];

    if (!ips.length) {

        container.innerHTML = `
            <div class="empty-state">
                No IP addresses detected
            </div>
        `;

        return;
    }

    container.innerHTML = "";

    ips.forEach(ip => {

        const div =
            document.createElement("div");

        div.className =
            "list-item";

        div.textContent =
            ip;

        container.appendChild(div);
    });
}

function renderMetadata(result) {

    document.getElementById("hashValue").textContent =
        result.hash;

    document.getElementById("riskLevel").textContent =
        result.risk_level.toUpperCase();
}

document
.getElementById("copyHashBtn")
.addEventListener("click", () => {

    const hash =
        document.getElementById("hashValue").textContent;

    navigator.clipboard.writeText(hash);

    alert("Hash copied.");
});

document
.getElementById("exportBtn")
.addEventListener("click", () => {

    if (!currentScanResult) return;

    const blob =
        new Blob(
            [
                JSON.stringify(
                    currentScanResult,
                    null,
                    2
                )
            ],
            {
                type: "application/json"
            }
        );

    const url =
        URL.createObjectURL(blob);

    const a =
        document.createElement("a");

    a.href = url;

    a.download =
        "cybershield-report.json";

    a.click();

    URL.revokeObjectURL(url);
});

function escapeHtml(text) {

    if (!text) return "";

    return text
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
}
