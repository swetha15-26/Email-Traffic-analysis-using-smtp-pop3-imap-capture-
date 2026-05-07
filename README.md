# Email-Traffic-analysis-using-smtp-pop3-imap-capture-
Email Traffic Analysis is a project that captures and analyzes SMTP, POP3, and IMAP protocols to study how emails are transferred across networks. Using Wireshark, it monitors client-server communication, packet flow, and protocol behavior, helping understand email transmission, network traffic, and cybersecurity concepts# 📡 Email Traffic Analyzer

A production-ready web application for analyzing **SMTP, POP3, and IMAP** email protocols from Wireshark PCAP captures. Upload a `.pcap` file to instantly extract packet metadata, reconstruct TCP streams, identify credentials, and visualize protocol distribution.

---

## ✨ Features

| Feature | Details |
|---|---|
| **Protocol Detection** | Identifies SMTP (25/587/465), POP3 (110/995), IMAP (143/993) |
| **Command Extraction** | EHLO, MAIL FROM, RCPT TO, DATA / USER, PASS, RETR / LOGIN, SELECT, FETCH |
| **TCP Stream Reconstruction** | Follow complete client↔server conversations |
| **Security Insights** | Detects plaintext credentials, unencrypted protocols, AUTH patterns |
| **Anomaly Detection** | Flags brute-force AUTH attempts, unusual RETR volumes |
| **Visualization** | Doughnut chart of protocol distribution with Chart.js |
| **Email Extraction** | Pulls all email addresses from packet payloads |
| **Export** | Download results as JSON or CSV |
| **Drag & Drop** | Modern drop-zone upload interface |
| **Demo Mode** | Preview the tool with synthetic data — no PCAP needed |

---

## 🗂 Project Structure

```
email-traffic-analyzer/
│
├── backend/
│   ├── app.py            ← Flask REST API (upload, analyze, demo)
│   ├── analyzer.py       ← Scapy-based PCAP analysis engine
│   ├── requirements.txt  ← Python dependencies
│   └── uploads/          ← Temporary upload directory (auto-created)
│
├── frontend/
│   ├── index.html        ← Main UI (single-page application)
│   ├── style.css         ← Industrial terminal design system
│   └── script.js         ← All client-side logic
│
└── README.md
```

---

## ⚙️ Setup & Installation

### Prerequisites

- Python 3.10+
- pip
- A modern browser (Chrome, Firefox, Edge)
- *Optional:* Wireshark to capture PCAP files

### 1. Clone / download the project

```bash
git clone https://github.com/yourname/email-traffic-analyzer
cd email-traffic-analyzer
```

### 2. Install Python dependencies

```bash
cd backend
pip install -r requirements.txt
```

> **Note on Scapy:** On Linux you may need `sudo` or add your user to the `pcap` group. On Windows, install [Npcap](https://npcap.com/) first.

### 3. Start the Flask backend

```bash
# From the backend/ directory:
python app.py
```

You should see:
```
═══════════════════════════════════════════════════════
  📧 Email Traffic Analyzer — Backend Starting
═══════════════════════════════════════════════════════
  → http://127.0.0.1:5000
```

### 4. Open the frontend

Open `frontend/index.html` in your browser **or** navigate to:

```
http://127.0.0.1:5000
```

Flask serves the frontend automatically from the root `/` endpoint.

---

## 🚀 Usage

### Option A — Upload a real PCAP file

1. Open the app in your browser
2. Drag & drop a `.pcap` file onto the upload zone, or click **Browse File**
3. Click **🔍 Analyze**
4. Explore:
   - **Packet Log** — sortable, filterable table of all email packets
   - **TCP Stream Viewer** — reconstructed full conversations
   - **Security Insights** — plaintext credential warnings
   - **Distribution Chart** — SMTP vs POP3 vs IMAP breakdown

### Option B — Demo mode (no file needed)

Click **▶ Try Demo** to load synthetic sample data and explore the full UI.

### Capturing email traffic with Wireshark

```bash
# Capture on interface eth0, save to file, filter email ports
wireshark -i eth0 -k -f "tcp port 25 or port 587 or port 110 or port 143"

# Or with tcpdump:
sudo tcpdump -i eth0 -w capture.pcap "tcp port 25 or port 587 or port 110 or port 143"
```

---

## 🔌 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET`  | `/`       | Serve frontend |
| `GET`  | `/health` | Liveness check |
| `POST` | `/upload` | Upload & analyze PCAP (field: `pcap`) |
| `GET`  | `/demo`   | Return synthetic demo analysis |

### Sample `/upload` response

```json
{
  "filename": "capture.pcap",
  "total_packets": 12,
  "stats": { "SMTP": 5, "POP3": 4, "IMAP": 3 },
  "packets": [
    {
      "id": 0,
      "timestamp": "2024-05-01 10:00:01 UTC",
      "src_ip": "192.168.1.10",
      "dst_ip": "192.168.1.1",
      "src_port": 45200,
      "dst_port": 25,
      "protocol": "SMTP",
      "command": "EHLO",
      "payload": "EHLO client.example.com\r\n",
      "encrypted": false,
      "suspicious": false,
      "warnings": [],
      "emails": [],
      "length": 74
    }
  ],
  "streams": {
    "192.168.1.10:45200 → 192.168.1.1:25": [
      { "direction": "client→server", "payload": "EHLO client.example.com\r\n", "command": "EHLO", "protocol": "SMTP" }
    ]
  },
  "security": [
    "Plaintext POP3 credentials detected",
    "Unencrypted SMTP traffic detected"
  ],
  "anomalies": [],
  "emails": ["alice@example.com", "bob@corp.net"],
  "errors": []
}
```

---

## 🛡 Security Notes

- Uploaded PCAP files are **deleted from disk immediately** after analysis
- No packet data is persisted between sessions
- The tool is designed for **local forensic use** — do not expose the Flask server to the public internet without authentication

---

## 🐛 Troubleshooting

| Problem | Solution |
|---|---|
| "Cannot reach backend" | Make sure `python app.py` is running on port 5000 |
| "scapy is not installed" | Run `pip install scapy` in the backend folder |
| Empty results from PCAP | Ensure the file contains TCP traffic on email ports |
| Scapy permission error | On Linux, run with `sudo` or set capabilities: `sudo setcap cap_net_raw+ep $(which python3)` |
| Large PCAP is slow | Files over 50MB may take 10–30s; progress bar shows status |

---

## 📦 Dependencies

```
flask>=3.0.0
flask-cors>=4.0.0
scapy>=2.5.0
werkzeug>=3.0.0
```

Frontend (CDN, no install needed):
- [Chart.js 4.4](https://www.chartjs.org/)
- [JetBrains Mono](https://fonts.google.com/specimen/JetBrains+Mono) + [Syne](https://fonts.google.com/specimen/Syne) (Google Fonts)

---

## 📄 License

MIT — free to use and modify.
