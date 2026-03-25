"""
=====================================================================
  CONNECTION MONITOR - Server & Client Interception Detection
  Version 5.0 - Now includes Alert Dashboard
=====================================================================
  What this script does:
    1. Monitors incoming/outgoing connections on a specified port
    2. Detects ARP spoofing (Man-in-the-Middle interception)
    3. Detects port scanning (attacker probing your server)
    4. Detects SSL stripping (attacker downgrading HTTPS to HTTP)
    5. Inspects packets for SQL injection, malware, and suspicious commands
    6. Runs a web dashboard to view all alerts in your browser
    7. Alerts via: terminal, log file, email

  Requirements (install before running):
    sudo pip3 install scapy psutil plyer --break-system-packages

  How to run:
    sudo python3 connection_monitor.py

  Dashboard:
    Open your browser and go to http://192.168.126.131:9999

  NOTE: Requires admin/root privileges for ARP and packet sniffing.
=====================================================================
"""

import time
import json
import socket
import logging
import smtplib
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    import psutil
    from scapy.all import sniff, ARP, TCP, IP
    from plyer import notification
except ImportError as e:
    print(f"[!] Missing library: {e}")
    print("[!] Run: sudo pip3 install scapy psutil plyer --break-system-packages")
    exit(1)


# =====================================================================
#  CONFIGURATION
# =====================================================================

MONITOR_PORT        = 80
CHECK_INTERVAL      = 5
PORT_SCAN_THRESHOLD = 5
PORT_SCAN_WINDOW    = 10
HTTP_PORTS          = [80, 8080]
HTTPS_PORT          = 443
DASHBOARD_PORT      = 9999
LOG_FILE            = "connection_monitor.log"

SENSITIVE_DOMAINS = [
    "bank", "login", "account", "secure", "pay",
    "password", "admin", "checkout", "auth"
]

EMAIL_ALERTS   = False
EMAIL_SENDER   = "your_alert_email@gmail.com"
EMAIL_PASSWORD = "your16charapppassword"
EMAIL_RECEIVER = "your_main_email@gmail.com"
SMTP_SERVER    = "smtp.gmail.com"
SMTP_PORT      = 587
DESKTOP_ALERTS = False


# =====================================================================
#  ALERT STORAGE
# =====================================================================

alert_history      = []
alert_history_lock = threading.Lock()
alert_counts       = defaultdict(int)


def store_alert(alert_type, details):
    with alert_history_lock:
        alert_history.append({
            "time":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type":    alert_type,
            "details": details
        })
        alert_counts[alert_type] += 1
        if len(alert_history) > 200:
            alert_history.pop(0)


# =====================================================================
#  LOGGING SETUP
# =====================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# =====================================================================
#  ALERT FUNCTIONS
# =====================================================================

def send_email_alert(subject, body):
    if not EMAIL_ALERTS:
        return
    try:
        msg = MIMEMultipart()
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = EMAIL_RECEIVER
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        logger.info(f"[EMAIL] Alert sent to {EMAIL_RECEIVER}")
    except Exception as e:
        logger.error(f"[EMAIL ERROR] {e}")


def send_desktop_alert(title, message):
    if not DESKTOP_ALERTS:
        return
    try:
        notification.notify(title=title, message=message, timeout=10)
    except Exception as e:
        logger.warning(f"[DESKTOP ALERT ERROR] {e}")


def trigger_alert(alert_type, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.warning(f"[{alert_type}] {details}")
    store_alert(alert_type, details)
    send_email_alert(
        subject=f"[NETWORK ALERT] {alert_type}",
        body=f"Time: {timestamp}\n\nDetails: {details}"
    )
    send_desktop_alert(title=f"Network Alert: {alert_type}", message=details)


# =====================================================================
#  MODULE 1: PORT CONNECTION MONITOR
# =====================================================================

def monitor_port_connections():
    logger.info(f"[PORT MONITOR] Watching port {MONITOR_PORT} every {CHECK_INTERVAL}s...")
    seen_connections = set()
    while True:
        try:
            current_connections = set()
            for conn in psutil.net_connections(kind="inet"):
                if conn.laddr.port == MONITOR_PORT or (conn.raddr and conn.raddr.port == MONITOR_PORT):
                    remote  = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    local   = f"{conn.laddr.ip}:{conn.laddr.port}"
                    conn_id = f"{local} <-> {remote} [{conn.status}]"
                    current_connections.add(conn_id)
                    if conn_id not in seen_connections:
                        trigger_alert("NEW CONNECTION", f"New connection on port {MONITOR_PORT}: {conn_id}")
            seen_connections = current_connections
            time.sleep(CHECK_INTERVAL)
        except Exception as e:
            logger.error(f"[PORT MONITOR ERROR] {e}")
            time.sleep(CHECK_INTERVAL)


# =====================================================================
#  MODULE 2: ARP SPOOFING DETECTOR
# =====================================================================

arp_table = {}

def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        sender_ip  = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc
        if sender_ip in arp_table:
            if arp_table[sender_ip] != sender_mac:
                trigger_alert(
                    "ARP SPOOFING DETECTED",
                    f"IP {sender_ip} changed MAC from {arp_table[sender_ip]} to {sender_mac}. Possible MitM attack!"
                )
        else:
            arp_table[sender_ip] = sender_mac
            logger.info(f"[ARP] Learned: {sender_ip} is at {sender_mac}")


# =====================================================================
#  MODULE 3: PORT SCAN DETECTOR
# =====================================================================

port_scan_tracker = defaultdict(list)
port_scan_lock    = threading.Lock()
alerted_scanners  = set()

def detect_port_scan(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[TCP].flags == 0x02:
            attacker_ip  = packet[IP].src
            target_port  = packet[TCP].dport
            current_time = time.time()
            with port_scan_lock:
                port_scan_tracker[attacker_ip].append((target_port, current_time))
                port_scan_tracker[attacker_ip] = [
                    (p, t) for p, t in port_scan_tracker[attacker_ip]
                    if current_time - t <= PORT_SCAN_WINDOW
                ]
                unique_ports = set(p for p, t in port_scan_tracker[attacker_ip])
                if len(unique_ports) >= PORT_SCAN_THRESHOLD and attacker_ip not in alerted_scanners:
                    alerted_scanners.add(attacker_ip)
                    trigger_alert(
                        "PORT SCAN DETECTED",
                        f"IP {attacker_ip} scanned {len(unique_ports)} ports in {PORT_SCAN_WINDOW}s. "
                        f"Ports: {sorted(unique_ports)}. Likely reconnaissance before an attack!"
                    )


# =====================================================================
#  MODULE 4: SSL STRIPPING DETECTOR
# =====================================================================

alerted_ssl_strip = set()

def detect_ssl_stripping(packet):
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return
    src_ip   = packet[IP].src
    dst_port = packet[TCP].dport
    src_port = packet[TCP].sport
    try:
        payload = bytes(packet[TCP].payload).decode("utf-8", errors="ignore")
    except Exception:
        return
    if not payload:
        return
    if dst_port in HTTP_PORTS or src_port in HTTP_PORTS:
        found = [kw for kw in SENSITIVE_DOMAINS if kw in payload.lower()]
        if found and src_ip not in alerted_ssl_strip:
            alerted_ssl_strip.add(src_ip)
            trigger_alert(
                "SSL STRIPPING SUSPECTED",
                f"Sensitive keywords {found} in plain HTTP from {src_ip} on port {dst_port}. Should be HTTPS!"
            )
    if ("301" in payload or "302" in payload) and "https" in payload.lower():
        if src_ip not in alerted_ssl_strip:
            alerted_ssl_strip.add(src_ip)
            trigger_alert(
                "SSL REDIRECT INTERCEPTED",
                f"HTTP to HTTPS redirect seen from {src_ip}. Possible SSL stripping!"
            )


# =====================================================================
#  MODULE 5: PACKET INSPECTION
# =====================================================================

SUSPICIOUS_PATTERNS = [
    ("union select",      "SQL INJECTION",     "UNION SELECT attack detected"),
    ("' or '1'='1",       "SQL INJECTION",     "Classic OR 1=1 SQL injection detected"),
    ("drop table",        "SQL INJECTION",     "DROP TABLE command detected"),
    ("insert into",       "SQL INJECTION",     "INSERT INTO command detected"),
    ("xp_cmdshell",       "SQL INJECTION",     "xp_cmdshell execution attempt detected"),
    ("; ls ",             "CMD INJECTION",     "ls command injection detected"),
    ("; cat /etc/passwd", "CMD INJECTION",     "Attempt to read /etc/passwd detected"),
    ("; whoami",          "CMD INJECTION",     "whoami command injection detected"),
    ("| nc ",             "CMD INJECTION",     "Netcat pipe - possible reverse shell"),
    ("bash -i",           "CMD INJECTION",     "Bash interactive shell attempt detected"),
    ("/bin/sh",           "CMD INJECTION",     "Shell execution attempt detected"),
    ("../../../",         "DIR TRAVERSAL",     "Directory traversal attack detected"),
    ("..%2f..%2f",        "DIR TRAVERSAL",     "URL encoded directory traversal detected"),
    ("/etc/passwd",       "DIR TRAVERSAL",     "Attempt to access /etc/passwd detected"),
    ("/etc/shadow",       "DIR TRAVERSAL",     "Attempt to access /etc/shadow detected"),
    ("nikto",             "SUSPICIOUS TOOL",   "Nikto web scanner detected"),
    ("sqlmap",            "SUSPICIOUS TOOL",   "SQLmap tool detected"),
    ("masscan",           "SUSPICIOUS TOOL",   "Masscan port scanner detected"),
    (".php?cmd=",         "WEBSHELL ATTEMPT",  "PHP webshell command execution detected"),
    ("eval(base64",       "WEBSHELL ATTEMPT",  "Base64 eval webshell detected"),
    ("<script>",          "XSS ATTACK",        "Cross-site scripting attempt detected"),
    ("javascript:",       "XSS ATTACK",        "JavaScript injection attempt detected"),
]

alerted_packet_inspection = {}

def inspect_packet(packet):
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return
    src_ip   = packet[IP].src
    dst_port = packet[TCP].dport
    try:
        payload = bytes(packet[TCP].payload).decode("utf-8", errors="ignore").lower()
    except Exception:
        return
    if not payload or len(payload) < 10:
        return
    for pattern, alert_name, description in SUSPICIOUS_PATTERNS:
        if pattern.lower() in payload:
            alert_key  = f"{src_ip}_{alert_name}"
            last_alert = alerted_packet_inspection.get(alert_key, 0)
            if time.time() - last_alert > 60:
                alerted_packet_inspection[alert_key] = time.time()
                idx     = payload.find(pattern.lower())
                snippet = payload[max(0, idx - 20):idx + 60].strip()
                trigger_alert(
                    alert_name,
                    f"From {src_ip} on port {dst_port}. {description}. Snippet: ...{snippet}..."
                )


# =====================================================================
#  MODULE 6: ALERT DASHBOARD
#  Uses string concatenation instead of .format() to avoid CSS conflicts
# =====================================================================

def get_badge(alert_type):
    t = alert_type.upper()
    if any(x in t for x in ["INJECTION", "SPOOF", "WEBSHELL", "XSS", "TRAVERSAL"]):
        color = "red"
    elif any(x in t for x in ["SCAN", "SSL", "STRIP", "SUSPICIOUS", "TOOL"]):
        color = "orange"
    elif "CONNECTION" in t:
        color = "blue"
    else:
        color = "green"
    return '<span class="badge ' + color + '">' + alert_type + '</span>'


def build_dashboard_html():
    """Builds the dashboard HTML using string concatenation to avoid CSS brace issues."""

    with alert_history_lock:
        alerts = list(reversed(alert_history))
        total  = len(alert_history)

    port_scan_count  = alert_counts.get("PORT SCAN DETECTED", 0)
    arp_count        = alert_counts.get("ARP SPOOFING DETECTED", 0)
    ssl_count        = sum(v for k, v in alert_counts.items() if "SSL" in k)
    injection_count  = sum(v for k, v in alert_counts.items() if any(x in k for x in ["INJECTION", "WEBSHELL", "XSS", "TRAVERSAL"]))
    connection_count = alert_counts.get("NEW CONNECTION", 0)
    last_updated     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build table rows
    if alerts:
        rows = ""
        for a in alerts:
            rows += (
                "<tr>"
                "<td class='time'>" + a["time"] + "</td>"
                "<td>" + get_badge(a["type"]) + "</td>"
                "<td class='details'>" + a["details"] + "</td>"
                "</tr>"
            )
    else:
        rows = "<tr><td colspan='3' class='no-alerts'>No alerts yet. Monitoring is active.</td></tr>"

    css = (
        "<style>"
        "* {margin:0;padding:0;box-sizing:border-box}"
        "body {background:#0d1117;color:#c9d1d9;font-family:monospace;padding:20px}"
        "h1 {color:#58a6ff;font-size:22px;margin-bottom:5px}"
        ".subtitle {color:#8b949e;font-size:13px;margin-bottom:20px}"
        ".stats {display:flex;gap:15px;flex-wrap:wrap;margin-bottom:25px}"
        ".stat-box {background:#161b22;border:1px solid #30363d;border-radius:8px;padding:15px 20px;min-width:160px}"
        ".count {font-size:28px;font-weight:bold;color:#f85149}"
        ".label {font-size:12px;color:#8b949e;margin-top:4px}"
        ".safe .count {color:#3fb950}"
        ".warn .count {color:#d29922}"
        ".alerts-title {color:#58a6ff;font-size:16px;margin-bottom:10px}"
        "table {width:100%;border-collapse:collapse;font-size:13px}"
        "th {background:#161b22;color:#8b949e;padding:10px 12px;text-align:left;border-bottom:1px solid #30363d}"
        "td {padding:10px 12px;border-bottom:1px solid #21262d;vertical-align:top}"
        ".badge {display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}"
        ".red {background:#3d1a1a;color:#f85149;border:1px solid #f85149}"
        ".orange {background:#2d1f0a;color:#d29922;border:1px solid #d29922}"
        ".blue {background:#0d2044;color:#58a6ff;border:1px solid #58a6ff}"
        ".green {background:#0d2818;color:#3fb950;border:1px solid #3fb950}"
        ".time {color:#8b949e;white-space:nowrap}"
        ".details {color:#c9d1d9;max-width:700px;word-break:break-word}"
        ".no-alerts {text-align:center;padding:40px;color:#8b949e}"
        ".refresh {color:#8b949e;font-size:12px;margin-bottom:15px}"
        "</style>"
    )

    html = (
        "<!DOCTYPE html><html><head>"
        "<title>Connection Monitor Dashboard</title>"
        "<meta http-equiv='refresh' content='10'>"
        + css +
        "</head><body>"
        "<h1>Connection Monitor Dashboard</h1>"
        "<p class='subtitle'>Ubuntu Server: 192.168.126.131 | Auto-refreshes every 10 seconds</p>"
        "<p class='refresh'>Last updated: " + last_updated + "</p>"
        "<div class='stats'>"
        "<div class='stat-box safe'><div class='count'>" + str(total) + "</div><div class='label'>Total Alerts</div></div>"
        "<div class='stat-box'><div class='count'>" + str(port_scan_count) + "</div><div class='label'>Port Scans</div></div>"
        "<div class='stat-box'><div class='count'>" + str(arp_count) + "</div><div class='label'>ARP Spoof</div></div>"
        "<div class='stat-box'><div class='count'>" + str(ssl_count) + "</div><div class='label'>SSL Strip</div></div>"
        "<div class='stat-box'><div class='count'>" + str(injection_count) + "</div><div class='label'>Injections</div></div>"
        "<div class='stat-box warn'><div class='count'>" + str(connection_count) + "</div><div class='label'>Connections</div></div>"
        "</div>"
        "<p class='alerts-title'>Recent Alerts (newest first)</p>"
        "<table><thead><tr><th>Time</th><th>Alert Type</th><th>Details</th></tr></thead>"
        "<tbody>" + rows + "</tbody></table>"
        "</body></html>"
    )
    return html


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ["/", "/dashboard"]:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(build_dashboard_html().encode())
        elif self.path == "/api/alerts":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            with alert_history_lock:
                self.wfile.write(json.dumps(list(reversed(alert_history))).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress HTTP server logs


def start_dashboard():
    try:
        server = HTTPServer(("0.0.0.0", DASHBOARD_PORT), DashboardHandler)
        logger.info(f"[DASHBOARD] Running at http://192.168.126.131:{DASHBOARD_PORT}")
        server.serve_forever()
    except Exception as e:
        logger.error(f"[DASHBOARD ERROR] {e}")


# =====================================================================
#  PACKET SNIFFER
# =====================================================================

def start_packet_sniffer():
    logger.info("[SNIFFER] Starting ARP, port scan, SSL strip, and packet inspection...")
    try:
        sniff(
            filter="arp or tcp",
            prn=lambda pkt: [
                detect_arp_spoof(pkt),
                detect_port_scan(pkt),
                detect_ssl_stripping(pkt),
                inspect_packet(pkt)
            ] and None,
            store=False
        )
    except PermissionError:
        logger.error("[SNIFFER] Run with sudo!")
    except Exception as e:
        logger.error(f"[SNIFFER ERROR] {e}")


# =====================================================================
#  MAIN
# =====================================================================

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("  CONNECTION MONITOR v5.0 STARTED")
    logger.info(f"  Log file       : {LOG_FILE}")
    logger.info(f"  Monitoring port: {MONITOR_PORT}")
    logger.info(f"  Port scan limit: {PORT_SCAN_THRESHOLD} ports in {PORT_SCAN_WINDOW}s")
    logger.info(f"  SSL watch ports: {HTTP_PORTS}")
    logger.info(f"  Attack patterns: {len(SUSPICIOUS_PATTERNS)}")
    logger.info(f"  Dashboard      : http://192.168.126.131:{DASHBOARD_PORT}")
    logger.info("=" * 60)
    logger.info("  Watching for:")
    logger.info("  [1] New server/client connections")
    logger.info("  [2] ARP spoofing (MitM attacks)")
    logger.info("  [3] Port scanning (attacker reconnaissance)")
    logger.info("  [4] SSL stripping (HTTPS downgrade to HTTP)")
    logger.info("  [5] SQL injection, command injection, XSS, webshells")
    logger.info("  [6] Dashboard live at http://192.168.126.131:9999")
    logger.info("  You will be alerted immediately if an attacker is detected.")
    logger.info("=" * 60)

    threads = [
        threading.Thread(target=monitor_port_connections, daemon=True, name="PortMonitor"),
        threading.Thread(target=start_packet_sniffer,     daemon=True, name="PacketSniffer"),
        threading.Thread(target=start_dashboard,          daemon=True, name="Dashboard"),
    ]

    for t in threads:
        t.start()
        logger.info(f"[STARTED] {t.name}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\n[STOPPED] Connection monitor shut down.")
