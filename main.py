from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

import hashlib
import math
import re
import os
import json
import time
import ipaddress
import requests

from collections import Counter

app = Flask(__name__)
CORS(app)

# =====================================================
# CONFIG
# =====================================================

MAX_FILE_SIZE = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".txt",
    ".js",
    ".py",
    ".html",
    ".cpp",
    ".css",
    ".json",
    ".ps1",
    ".bat",
    ".vbs"
}

VT_API_KEY = os.getenv("VT_API_KEY")

VT_CACHE_FILE = "vt_cache.json"

# =====================================================
# OPTIONAL YARA
# =====================================================

YARA_ENABLED = False
yara = None

try:
    import yara

    YARA_ENABLED = True

except Exception:
    YARA_ENABLED = False

# =====================================================
# KEYWORDS
# =====================================================

HIGH_RISK = [
    "ransomware",
    "shellcode",
    "rootkit",
    "backdoor",
    "keylogger",
    "dropper",
    "rat",
    "botnet",
    "wscript.shell",
    "powershell -enc",
    "remote code execution",
    "privilege escalation"
]

MEDIUM_RISK = [
    "malware",
    "trojan",
    "worm",
    "spyware",
    "payload",
    "loader",
    "stealer",
    "eval",
    "base64",
    "fromcharcode",
    "powershell",
    "cmd.exe",
    "encrypt",
    "decrypt",
    "bitcoin",
    "monero",
    "credentials"
]

LOW_RISK = [
    "xor",
    "rc4",
    "aes",
    "curl",
    "wget",
    "cookie",
    "token",
    "session",
    ".exe",
    ".dll",
    ".bat",
    ".ps1",
]

# =====================================================
# REGEX
# =====================================================

PATTERNS = [
    (r'eval\s*\(', "eval() call", "high"),
    (r'base64_decode\s*\(', "base64 decode", "high"),
    (r'fromcharcode', "charcode obfuscation", "high"),
    (r'\\x[0-9a-fA-F]{2}', "hex encoding", "medium"),
    (r'document\.write\s*\(', "document.write", "medium"),
    (r'powershell\s+-enc', "encoded powershell", "high"),
    (r'cmd\.exe\s*/c', "cmd execution", "high"),
]

URL_REGEX = r'https?://[^\s\'"]+'

# =====================================================
# UTILITIES
# =====================================================

def get_hash(content_bytes):
    return hashlib.sha256(content_bytes).hexdigest()


def calculate_entropy(content):

    if not content:
        return 0

    counts = Counter(content)

    total = len(content)

    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
    )


def chunk_entropy(content, chunk_size=512):

    high_chunks = 0

    for i in range(0, len(content), chunk_size):

        chunk = content[i:i + chunk_size]

        if calculate_entropy(chunk) > 7:
            high_chunks += 1

    return high_chunks


def load_cache():

    if not os.path.exists(VT_CACHE_FILE):
        return {}

    try:
        with open(VT_CACHE_FILE, "r") as f:
            return json.load(f)
    except:
        return {}


def save_cache(cache):

    try:
        with open(VT_CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except:
        pass


# =====================================================
# VT LOOKUP
# =====================================================

def vt_lookup(file_hash):

    if not VT_API_KEY:
        return None

    cache = load_cache()

    if file_hash in cache:
        return cache[file_hash]

    try:

        headers = {
            "x-apikey": VT_API_KEY
        }

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        if response.status_code != 200:
            return None

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        result = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }

        cache[file_hash] = result

        save_cache(cache)

        return result

    except:
        return None


# =====================================================
# YARA
# =====================================================

def yara_scan(content_bytes):

    if not YARA_ENABLED:
        return []

    try:

        rules = yara.compile(filepath="rules.yar")

        matches = rules.match(data=content_bytes)

        return [m.rule for m in matches]

    except:
        return []


# =====================================================
# EXTRACTION
# =====================================================

def extract_urls(content):

    return list(set(re.findall(URL_REGEX, content)))


def extract_ips(urls):

    ips = []

    for url in urls:

        try:

            host = url.split("//")[1].split("/")[0]

            ipaddress.ip_address(host)

            ips.append(host)

        except:
            pass

    return ips


def extract_suspicious_lines(content):

    findings = []

    lines = content.splitlines()

    indicators = HIGH_RISK + MEDIUM_RISK

    for idx, line in enumerate(lines, start=1):

        lower = line.lower()

        for indicator in indicators:

            if indicator.lower() in lower:

                findings.append({
                    "line": idx,
                    "reason": indicator,
                    "content": line[:250]
                })

                break

    return findings[:25]


# =====================================================
# SCORING
# =====================================================

def get_score(content, keywords, patterns):

    score = 0

    score += len(keywords) * 2

    score += len(patterns) * 3

    # Behavior combinations

    if "eval" in content and "base64" in content:
        score += 8

    if "fromcharcode" in content and "eval" in content:
        score += 8

    if "powershell" in content and "-enc" in content:
        score += 10

    if "wscript.shell" in content:
        score += 10

    if "cmd.exe" in content:
        score += 5

    return score


def confidence_score(score, yara_hits, vt_result):

    confidence = score * 4

    confidence += len(yara_hits) * 12

    if vt_result:
        confidence += vt_result.get("malicious", 0) * 2

    return min(confidence, 100)


def get_risk(score, entropy, vt_result):

    if vt_result and vt_result.get("malicious", 0) >= 5:
        return "critical"

    if score >= 20 or entropy > 7.5:
        return "high"

    if score >= 10:
        return "medium"

    if score > 0:
        return "low"

    return "clean"


# =====================================================
# ROUTES
# =====================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    started = time.time()

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    ext = "." + file.filename.rsplit(".", 1)[-1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "Unsupported file type"}), 400

    content_bytes = file.read()

    if len(content_bytes) > MAX_FILE_SIZE:
        return jsonify({"error": "File too large"}), 400

    sha256 = get_hash(content_bytes)

    content = content_bytes.decode(
        "utf-8",
        errors="ignore"
    )

    lower = content.lower()

    entropy = round(calculate_entropy(lower), 2)

    entropy_chunks = chunk_entropy(lower)

    keywords = []

    for keyword in HIGH_RISK + MEDIUM_RISK + LOW_RISK:
        if keyword.lower() in lower:
            keywords.append(keyword)

    patterns = []

    for regex, label, severity in PATTERNS:

        if re.search(regex, lower):
            patterns.append({
                "label": label,
                "severity": severity
            })

    urls = extract_urls(content)

    ips = extract_ips(urls)

    suspicious_lines = extract_suspicious_lines(content)

    yara_matches = yara_scan(content_bytes)

    vt_result = vt_lookup(sha256)

    score = get_score(
        lower,
        keywords,
        patterns
    )

    if entropy_chunks >= 3:
        score += 5

    if ips:
        score += 5

    YARA_SEVERITY = {
    "EncodedPowerShell": 15,
    "JavaScriptObfuscation": 8,
    "SuspiciousDownloader": 10,
    "CredentialTheft": 12,
    "KeyloggerIndicators": 15,
    "RATIndicators": 15,
    "PersistenceMechanism": 8,
    "CryptoMiner": 10,
    "RansomwareIndicators": 20,
    "AntiAnalysis": 10,
    "EmbeddedExecutable": 5,
    "SuspiciousPython": 8,
    "SuspiciousHTML": 8
}
    for match in yara_matches:
    score += YARA_SEVERITY.get(match, 5)

    risk_level = get_risk(
        score,
        entropy,
        vt_result
    )

    confidence = confidence_score(
        score,
        yara_matches,
        vt_result
    )

    elapsed = round(time.time() - started, 3)

    return jsonify({

        "clean": risk_level == "clean",

        "risk_level": risk_level,

        "score": score,

        "confidence": confidence,

        "entropy": entropy,

        "high_entropy_chunks": entropy_chunks,

        "hash": sha256,

        "urls": urls,

        "ips": ips,

        "found_keywords": keywords,

        "found_patterns": patterns,

        "suspicious_lines": suspicious_lines,

        "yara_enabled": YARA_ENABLED,

        "yara_matches": yara_matches,

        "virustotal": vt_result,

        "scan_time": elapsed,

        "summary":
            f"Risk: {risk_level.upper()} | "
            f"Score: {score} | "
            f"Confidence: {confidence}%"
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
