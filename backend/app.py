"""
app.py — Flask REST API for Email Traffic Analyzer
Endpoints:
  POST /upload  → accept PCAP file, return analysis JSON
  GET  /health  → liveness check
"""

import os
import uuid
import json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

from analyzer import analyze_pcap

# ─── App Configuration ─────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)  # Allow cross-origin requests from the frontend

UPLOAD_FOLDER   = os.path.join(os.path.dirname(__file__), "uploads")
ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}
MAX_FILE_SIZE   = 100 * 1024 * 1024  # 100 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"]    = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


def allowed_file(filename: str) -> bool:
    """Check if file has an allowed extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the frontend index page."""
    return send_from_directory(app.static_folder, "index.html")


@app.route("/health", methods=["GET"])
def health():
    """Simple liveness check."""
    return jsonify({"status": "ok", "service": "Email Traffic Analyzer"})


@app.route("/upload", methods=["POST"])
def upload_and_analyze():
    """
    Receive a PCAP file, run analysis, return JSON results.
    Accepts: multipart/form-data with field name 'pcap'
    Returns: JSON analysis result
    """
    # ── Validate request ──────────────────────────────────────────────────────
    if "pcap" not in request.files:
        return jsonify({"error": "No file field named 'pcap' in request"}), 400

    file = request.files["pcap"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({
            "error": f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        }), 415

    # ── Save to temp location ─────────────────────────────────────────────────
    safe_name = secure_filename(file.filename)
    unique_id = uuid.uuid4().hex[:8]
    save_name = f"{unique_id}_{safe_name}"
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], save_name)

    try:
        file.save(save_path)
    except Exception as exc:
        return jsonify({"error": f"Failed to save file: {exc}"}), 500

    # ── Analyze ───────────────────────────────────────────────────────────────
    try:
        result = analyze_pcap(save_path)
    except Exception as exc:
        return jsonify({"error": f"Analysis failed: {exc}"}), 500
    finally:
        # Clean up uploaded file after analysis
        try:
            os.remove(save_path)
        except OSError:
            pass

    # ── Return results ────────────────────────────────────────────────────────
    result["filename"] = safe_name
    return jsonify(result), 200


@app.route("/demo", methods=["GET"])
def demo():
    """
    Return a synthetic demo result so the UI can be previewed
    without a real PCAP file.
    """
    demo_data = {
        "filename": "demo_capture.pcap",
        "total_packets": 12,
        "stats": {"SMTP": 5, "POP3": 4, "IMAP": 3},
        "emails": ["alice@example.com", "bob@corp.net", "admin@mail.org"],
        "security": [
            "Plaintext POP3 credentials detected",
            "Unencrypted SMTP traffic detected (data transmitted in plaintext)",
        ],
        "anomalies": [],
        "packets": [
            {
                "id": 0, "timestamp": "2024-05-01 10:00:01 UTC",
                "src_ip": "192.168.1.10", "dst_ip": "192.168.1.1",
                "src_port": 45200, "dst_port": 25,
                "protocol": "SMTP", "command": "EHLO",
                "payload": "EHLO client.example.com\r\n",
                "encrypted": False, "suspicious": False,
                "warnings": [], "emails": [], "length": 74,
            },
            {
                "id": 1, "timestamp": "2024-05-01 10:00:02 UTC",
                "src_ip": "192.168.1.10", "dst_ip": "192.168.1.1",
                "src_port": 45200, "dst_port": 25,
                "protocol": "SMTP", "command": "MAIL FROM",
                "payload": "MAIL FROM:<alice@example.com>\r\n",
                "encrypted": False, "suspicious": False,
                "warnings": [], "emails": ["alice@example.com"], "length": 82,
            },
            {
                "id": 2, "timestamp": "2024-05-01 10:00:03 UTC",
                "src_ip": "192.168.1.10", "dst_ip": "192.168.1.1",
                "src_port": 45200, "dst_port": 25,
                "protocol": "SMTP", "command": "RCPT TO",
                "payload": "RCPT TO:<bob@corp.net>\r\n",
                "encrypted": False, "suspicious": False,
                "warnings": [], "emails": ["bob@corp.net"], "length": 78,
            },
            {
                "id": 3, "timestamp": "2024-05-01 10:00:05 UTC",
                "src_ip": "192.168.1.20", "dst_ip": "192.168.1.1",
                "src_port": 51000, "dst_port": 110,
                "protocol": "POP3", "command": "USER",
                "payload": "USER alice\r\n",
                "encrypted": False, "suspicious": True,
                "warnings": ["Plaintext POP3 credentials detected"],
                "emails": [], "length": 60,
            },
            {
                "id": 4, "timestamp": "2024-05-01 10:00:06 UTC",
                "src_ip": "192.168.1.20", "dst_ip": "192.168.1.1",
                "src_port": 51000, "dst_port": 110,
                "protocol": "POP3", "command": "PASS",
                "payload": "PASS secret123\r\n",
                "encrypted": False, "suspicious": True,
                "warnings": ["Plaintext POP3 credentials detected"],
                "emails": [], "length": 64,
            },
            {
                "id": 5, "timestamp": "2024-05-01 10:00:08 UTC",
                "src_ip": "192.168.1.30", "dst_ip": "192.168.1.1",
                "src_port": 52100, "dst_port": 143,
                "protocol": "IMAP", "command": "LOGIN",
                "payload": "a001 LOGIN admin@mail.org p@ssw0rd\r\n",
                "encrypted": False, "suspicious": True,
                "warnings": ["Plaintext IMAP LOGIN credentials detected"],
                "emails": ["admin@mail.org"], "length": 88,
            },
            {
                "id": 6, "timestamp": "2024-05-01 10:00:10 UTC",
                "src_ip": "192.168.1.30", "dst_ip": "192.168.1.1",
                "src_port": 52100, "dst_port": 143,
                "protocol": "IMAP", "command": "SELECT",
                "payload": "a002 SELECT INBOX\r\n",
                "encrypted": False, "suspicious": False,
                "warnings": [], "emails": [], "length": 72,
            },
            {
                "id": 7, "timestamp": "2024-05-01 10:00:12 UTC",
                "src_ip": "192.168.1.30", "dst_ip": "192.168.1.1",
                "src_port": 52100, "dst_port": 143,
                "protocol": "IMAP", "command": "FETCH",
                "payload": "a003 FETCH 1 BODY[]\r\n",
                "encrypted": False, "suspicious": False,
                "warnings": [], "emails": [], "length": 70,
            },
            {
                "id": 8, "timestamp": "2024-05-01 10:00:15 UTC",
                "src_ip": "192.168.1.20", "dst_ip": "192.168.1.1",
                "src_port": 51000, "dst_port": 110,
                "protocol": "POP3", "command": "RETR",
                "payload": "RETR 1\r\n",
                "encrypted": False, "suspicious": False,
                "warnings": [], "emails": [], "length": 56,
            },
            {
                "id": 9, "timestamp": "2024-05-01 10:00:18 UTC",
                "src_ip": "192.168.1.10", "dst_ip": "192.168.1.1",
                "src_port": 45200, "dst_port": 25,
                "protocol": "SMTP", "command": "AUTH",
                "payload": "AUTH LOGIN\r\n",
                "encrypted": False, "suspicious": True,
                "warnings": ["SMTP AUTH LOGIN (Base64-encoded, not encrypted)"],
                "emails": [], "length": 60,
            },
            {
                "id": 10, "timestamp": "2024-05-01 10:00:20 UTC",
                "src_ip": "192.168.1.10", "dst_ip": "192.168.1.1",
                "src_port": 45200, "dst_port": 25,
                "protocol": "SMTP", "command": "DATA",
                "payload": "DATA\r\nFrom: alice@example.com\r\nTo: bob@corp.net\r\nSubject: Hello!\r\n\r\nTest email body.\r\n.\r\n",
                "encrypted": False, "suspicious": False,
                "warnings": [], "emails": ["alice@example.com", "bob@corp.net"], "length": 180,
            },
            {
                "id": 11, "timestamp": "2024-05-01 10:00:22 UTC",
                "src_ip": "192.168.1.20", "dst_ip": "192.168.1.1",
                "src_port": 51000, "dst_port": 110,
                "protocol": "POP3", "command": "QUIT",
                "payload": "QUIT\r\n",
                "encrypted": False, "suspicious": False,
                "warnings": [], "emails": [], "length": 54,
            },
        ],
        "streams": {
            "192.168.1.10:45200 → 192.168.1.1:25": [
                {"direction": "client→server", "payload": "EHLO client.example.com\r\n", "command": "EHLO", "protocol": "SMTP"},
                {"direction": "client→server", "payload": "MAIL FROM:<alice@example.com>\r\n", "command": "MAIL FROM", "protocol": "SMTP"},
                {"direction": "client→server", "payload": "RCPT TO:<bob@corp.net>\r\n", "command": "RCPT TO", "protocol": "SMTP"},
                {"direction": "client→server", "payload": "AUTH LOGIN\r\n", "command": "AUTH", "protocol": "SMTP"},
                {"direction": "client→server", "payload": "DATA\r\nFrom: alice@example.com\r\nTo: bob@corp.net\r\nSubject: Hello!\r\n\r\nTest email body.\r\n.\r\n", "command": "DATA", "protocol": "SMTP"},
            ],
            "192.168.1.20:51000 → 192.168.1.1:110": [
                {"direction": "client→server", "payload": "USER alice\r\n", "command": "USER", "protocol": "POP3"},
                {"direction": "client→server", "payload": "PASS secret123\r\n", "command": "PASS", "protocol": "POP3"},
                {"direction": "client→server", "payload": "RETR 1\r\n", "command": "RETR", "protocol": "POP3"},
                {"direction": "client→server", "payload": "QUIT\r\n", "command": "QUIT", "protocol": "POP3"},
            ],
            "192.168.1.30:52100 → 192.168.1.1:143": [
                {"direction": "client→server", "payload": "a001 LOGIN admin@mail.org p@ssw0rd\r\n", "command": "LOGIN", "protocol": "IMAP"},
                {"direction": "client→server", "payload": "a002 SELECT INBOX\r\n", "command": "SELECT", "protocol": "IMAP"},
                {"direction": "client→server", "payload": "a003 FETCH 1 BODY[]\r\n", "command": "FETCH", "protocol": "IMAP"},
            ],
        },
        "errors": [],
    }
    return jsonify(demo_data), 200


# ─── Error Handlers ────────────────────────────────────────────────────────────

@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({"error": f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)} MB"}), 413


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


# ─── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  📧 Email Traffic Analyzer — Backend Starting")
    print("=" * 55)
    print("  → http://127.0.0.1:5000")
    print("  → http://127.0.0.1:5000/health")
    print("  → POST http://127.0.0.1:5000/upload")
    print("  → GET  http://127.0.0.1:5000/demo")
    print("=" * 55)
    app.run(debug=True, host="0.0.0.0", port=5000)