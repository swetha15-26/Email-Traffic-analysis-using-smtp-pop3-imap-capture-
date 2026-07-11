"""
analyzer.py — Core PCAP analysis engine for Email Traffic Analyzer
Supports SMTP (25/587/465), POP3 (110/995), IMAP (143/993)
Uses scapy for broad compatibility without Wireshark dependency.
"""

import os
import re
import json
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ─── Protocol Port Mappings ────────────────────────────────────────────────────
PROTOCOL_PORTS = {
    "SMTP":  {25, 587, 465},
    "POP3":  {110, 995},
    "IMAP":  {143, 993},
}

# Encrypted ports (TLS)
ENCRYPTED_PORTS = {465, 995, 993}

# ─── Command Pattern Matchers ──────────────────────────────────────────────────
SMTP_COMMANDS   = re.compile(
    r"^(EHLO|HELO|MAIL FROM|RCPT TO|DATA|QUIT|AUTH|STARTTLS|RSET|VRFY|NOOP)", re.IGNORECASE
)
POP3_COMMANDS   = re.compile(
    r"^(USER|PASS|RETR|DELE|LIST|STAT|QUIT|TOP|UIDL|NOOP|RSET|APOP)", re.IGNORECASE
)
IMAP_COMMANDS   = re.compile(
    r"^[A-Z0-9]+\s+(LOGIN|SELECT|FETCH|STORE|SEARCH|LOGOUT|LIST|LSUB|CREATE|DELETE|RENAME|SUBSCRIBE|NOOP|CHECK|CLOSE|EXAMINE|EXPUNGE|COPY|UID|STARTTLS|AUTHENTICATE|CAPABILITY|NAMESPACE)",
    re.IGNORECASE
)

# Credential patterns for security scanning
CREDENTIAL_PATTERNS = [
    re.compile(r"^(USER|PASS)\s+\S+", re.IGNORECASE),           # POP3
    re.compile(r"^AUTH\s+LOGIN", re.IGNORECASE),                 # SMTP AUTH LOGIN
    re.compile(r"LOGIN\s+\S+\s+\S+", re.IGNORECASE),            # IMAP LOGIN
    re.compile(r"^(MAIL FROM|RCPT TO):", re.IGNORECASE),        # SMTP addresses
]

EMAIL_PATTERN   = re.compile(r"[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE)
BASE64_PATTERN  = re.compile(r"^[A-Za-z0-9+/]{10,}={0,2}$")


def detect_protocol(sport: int, dport: int) -> str | None:
    """Return protocol name based on source/destination port, or None."""
    for proto, ports in PROTOCOL_PORTS.items():
        if sport in ports or dport in ports:
            return proto
    return None


def classify_command(protocol: str, payload: str) -> str:
    """Extract the email command from a payload line."""
    first_line = payload.strip().split("\n")[0].strip()
    if protocol == "SMTP"  and SMTP_COMMANDS.match(first_line):
        return SMTP_COMMANDS.match(first_line).group(0).upper()
    if protocol == "POP3"  and POP3_COMMANDS.match(first_line):
        return POP3_COMMANDS.match(first_line).group(0).upper()
    if protocol == "IMAP"  and IMAP_COMMANDS.match(first_line):
        m = IMAP_COMMANDS.match(first_line)
        return m.group(1).upper() if m else "DATA"
    return "DATA"


def is_encrypted_port(sport: int, dport: int) -> bool:
    return sport in ENCRYPTED_PORTS or dport in ENCRYPTED_PORTS


def scan_credentials(payload: str) -> list[str]:
    """Return list of credential warnings found in payload."""
    warnings = []
    for pat in CREDENTIAL_PATTERNS:
        if pat.search(payload):
            if re.search(r"^(USER|PASS)\s+", payload, re.IGNORECASE):
                warnings.append("Plaintext POP3 credentials detected")
            elif re.search(r"^AUTH\s+LOGIN", payload, re.IGNORECASE):
                warnings.append("SMTP AUTH LOGIN (Base64-encoded, not encrypted)")
            elif re.search(r"LOGIN\s+\S+\s+\S+", payload, re.IGNORECASE):
                warnings.append("Plaintext IMAP LOGIN credentials detected")
    return list(set(warnings))


def extract_emails(payload: str) -> list[str]:
    """Pull email addresses from payload text."""
    return list(set(EMAIL_PATTERN.findall(payload)))


def analyze_pcap(filepath: str) -> dict:
    """
    Main entry point.
    Returns a structured dict with:
      - packets:      list of parsed packet records
      - streams:      reconstructed TCP streams
      - stats:        protocol distribution counts
      - security:     list of security warnings
      - emails:       discovered email addresses
      - errors:       any parse errors
    """
    if not SCAPY_AVAILABLE:
        return {"error": "scapy is not installed. Run: pip install scapy"}

    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}"}

    # ── Load packets ──────────────────────────────────────────────────────────
    try:
        raw_packets = rdpcap(filepath)
    except Exception as exc:
        return {"error": f"Failed to read PCAP: {exc}"}

    packets        = []
    streams        = defaultdict(list)   # key: (src_ip, dst_ip, sport, dport)
    stats          = defaultdict(int)
    security_issues= []
    all_emails     = set()
    packet_id      = 0

    for pkt in raw_packets:
        # Only process TCP/IP packets with a payload
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        if not pkt.haslayer(Raw):
            continue

        ip    = pkt[IP]
        tcp   = pkt[TCP]
        sport = tcp.sport
        dport = tcp.dport

        protocol = detect_protocol(sport, dport)
        if protocol is None:
            continue  # Skip non-email traffic

        # Decode payload safely
        try:
            payload = pkt[Raw].load.decode("utf-8", errors="replace")
        except Exception:
            payload = ""

        if not payload.strip():
            continue

        encrypted  = is_encrypted_port(sport, dport)
        command    = classify_command(protocol, payload)
        warnings   = [] if encrypted else scan_credentials(payload)
        emails     = extract_emails(payload)
        suspicious = bool(warnings)

        all_emails.update(emails)
        security_issues.extend(warnings)
        stats[protocol] += 1

        # Timestamp
        try:
            ts = float(pkt.time)
            timestamp = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            timestamp = "N/A"

        record = {
            "id":          packet_id,
            "timestamp":   timestamp,
            "src_ip":      ip.src,
            "dst_ip":      ip.dst,
            "src_port":    sport,
            "dst_port":    dport,
            "protocol":    protocol,
            "command":     command,
            "payload":     payload[:500],   # cap at 500 chars for UI
            "encrypted":   encrypted,
            "suspicious":  suspicious,
            "warnings":    warnings,
            "emails":      emails,
            "length":      len(pkt),
        }

        packets.append(record)

        # Stream reconstruction key (canonical direction)
        if sport in PROTOCOL_PORTS.get(protocol, set()):
            stream_key = f"{ip.dst}:{dport} → {ip.src}:{sport}"
        else:
            stream_key = f"{ip.src}:{sport} → {ip.dst}:{dport}"

        streams[stream_key].append({
            "direction": "server→client" if sport in PROTOCOL_PORTS.get(protocol, set()) else "client→server",
            "payload":   payload[:300],
            "command":   command,
            "protocol":  protocol,
        })

        packet_id += 1

    # ── Security summary ──────────────────────────────────────────────────────
    security_summary = []
    seen = set()
    for issue in security_issues:
        if issue not in seen:
            seen.add(issue)
            security_summary.append(issue)

    unencrypted_protocols = [p for p in stats if any(
        not is_encrypted_port(pkt["src_port"], pkt["dst_port"])
        for pkt in packets if pkt["protocol"] == p
    )]
    for p in unencrypted_protocols:
        msg = f"Unencrypted {p} traffic detected (data transmitted in plaintext)"
        if msg not in security_summary:
            security_summary.append(msg)

    # ── Anomaly detection ─────────────────────────────────────────────────────
    anomalies = []
    smtp_auth_count = sum(1 for p in packets if p["command"] == "AUTH")
    if smtp_auth_count > 5:
        anomalies.append(f"High AUTH attempt count ({smtp_auth_count}) — possible brute-force")

    retr_count = sum(1 for p in packets if p["command"] == "RETR")
    if retr_count > 20:
        anomalies.append(f"Unusual POP3 RETR volume ({retr_count} messages retrieved)")

    return {
        "total_packets":   len(packets),
        "packets":         packets,
        "streams":         {k: v for k, v in list(streams.items())[:20]},  # top 20 streams
        "stats":           dict(stats),
        "security":        security_summary,
        "anomalies":       anomalies,
        "emails":          list(all_emails),
        "errors":          [],
    }