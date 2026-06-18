from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import hashlib
import math
import re
from collections import Counter

app = Flask(__name__)
CORS(app)

ALLOWED_EXTENSIONS = {'.txt', '.js', '.py', '.html', '.cpp'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

KNOWN_HASHES = set([])

HIGH_RISK = [
    "ransomware", "exploit", "shellcode", "rootkit", "backdoor",
    "keylogger", "cryptominer", "dropper", "rat", "botnet",
    "wscript.shell", "activexobject", "createobject",
    "remote code execution", "privilege escalation",
    "aes-256", "send btc", "payment address", "recover files",
    "isdebuggerpresent", "anti-debug", "anti-vm"
]

MEDIUM_RISK = [
    "malware", "trojan", "worm", "spyware", "adware", "payload",
    "stealer", "hijacker", "loader", "miner",
    "eval", "base64", "obfuscate", "fromcharcode", "unescape",
    "powershell", "cmd.exe", "wscript", "cscript",
    "encrypt", "decrypt", "ransom", "bitcoin", "btc", "monero",
    "injection", "sql injection", "xss", "csrf", "buffer overflow",
    "sandbox", "vmware", "virtualbox", "debugger",
    "password", "credentials", "keylog", "autofill"
]

LOW_RISK = [
    "virus", "xor", "rot13", "rc4", "aes", "packed",
    "atob", "btoa", "escape", "wget", "curl", "beacon",
    "wallet", "mining", "stratum", "coinhive",
    "net user", "whoami", "systeminfo", "regedit", "taskkill",
    "cookie", "session", "token", "sleep", "delay",
    ".exe", ".dll", ".bat", ".ps1", ".vbs", ".hta",
    "registry", "reg add", "schtasks", "startup", "runonce"
]

PATTERNS = [
    (r'eval\s*\(', "eval() call", "high"),
    (r'base64_decode\s*\(', "base64_decode call", "high"),
    (r'\\x[0-9a-fA-F]{2}', "hex encoded string", "medium"),
    (r'(http|ftp)s?://\S+', "embedded URL", "low"),
    (r'[0-9a-fA-F]{32,}', "long hex string (possible hash/key)", "medium"),
    (r'chr\(\d+\)', "char encoding", "medium"),
    (r'document\.write\s*\(', "document.write call", "medium"),
    (r'window\[.+\]\s*\(', "obfuscated window call", "high"),
    (r'unescape\s*\(%u', "unicode escape", "high"),
    (r'new\s+ActiveXObject', "ActiveX object", "high"),
    (r'WScript\s*\.\s*Shell', "WScript.Shell", "high"),
    (r'powershell\s+-[eE]nc', "encoded powershell", "high"),
    (r'(?i)cmd\.exe\s*/c', "cmd execution", "high"),
]


def get_hash(content_bytes):
    return hashlib.sha256(content_bytes).hexdigest()


def calculate_entropy(content):
    if not content:
        return 0
    counts = Counter(content)
    total = len(content)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def get_severity_score(found_keywords, found_patterns):
    score = 0
    for k in found_keywords:
        if k in HIGH_RISK:
            score += 3
        elif k in MEDIUM_RISK:
            score += 2
        elif k in LOW_RISK:
            score += 1
    for _, _, severity in found_patterns:
        if severity == "high":
            score += 3
        elif severity == "medium":
            score += 2
        elif severity == "low":
            score += 1
    return score


def get_risk_level(score, entropy, hash_match):
    if hash_match:
        return "critical"
    if score >= 10 or entropy > 7.5:
        return "high"
    if score >= 5 or entropy > 6.5:
        return "medium"
    if score >= 1:
        return "low"
    return "clean"


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']

    ext = '.' + file.filename.rsplit('.', 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "Unsupported file type"}), 400

    content_bytes = file.read()
    if len(content_bytes) > MAX_FILE_SIZE:
        return jsonify({"error": "File too large (max 5MB)"}), 400

    file_hash = get_hash(content_bytes)
    hash_match = file_hash in KNOWN_HASHES

    content = content_bytes.decode('utf-8', errors='ignore').lower()
    entropy = round(calculate_entropy(content), 2)

    all_keywords = HIGH_RISK + MEDIUM_RISK + LOW_RISK
    found_keywords = [k for k in all_keywords if k.lower() in content]

    found_patterns = []
    for pattern, label, severity in PATTERNS:
        if re.search(pattern, content):
            found_patterns.append((pattern, label, severity))

    score = get_severity_score(found_keywords, found_patterns)
    risk_level = get_risk_level(score, entropy, hash_match)

    return jsonify({
        "clean": risk_level == "clean",
        "risk_level": risk_level,
        "score": score,
        "entropy": entropy,
        "high_entropy": entropy > 7.5,
        "hash": file_hash,
        "known_malware": hash_match,
        "found_keywords": found_keywords,
        "found_patterns": [label for _, label, _ in found_patterns],
        "summary": f"Risk level: {risk_level.upper()} | Score: {score} | Entropy: {entropy}"
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
