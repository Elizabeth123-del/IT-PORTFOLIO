# Connection Monitor
### A Python Based Network Intrusion Detection Tool

---

## Overview

Connection Monitor is a lightweight, real time network security monitoring tool built in Python. It runs on Ubuntu Server and detects common network attacks including Man-in-the-Middle interception, ARP spoofing, port scanning, SSL stripping, and packet level injection attacks. All alerts are displayed in a live web dashboard and delivered via email.

This project was built and deployed on a Ubuntu 24.04 virtual machine running Apache2 and osTicket, simulating a real world server environment.

---

## Features

| Feature | Description |
|---|---|
| Port Connection Monitor | Watches for new incoming and outgoing connections on a specified port |
| ARP Spoof Detection | Detects MAC address changes that indicate a Man-in-the-Middle attack |
| Port Scan Detection | Flags IPs that hit multiple ports rapidly, indicating reconnaissance |
| SSL Stripping Detection | Detects when HTTPS traffic is downgraded to HTTP by an attacker |
| Packet Inspection | Scans packet payloads for 22 attack signatures including SQL injection, command injection, XSS, directory traversal, and webshells |
| Live Web Dashboard | Real time browser based dashboard showing all alerts with colour coded severity |
| Email Alerts | Sends instant email notifications when an attack is detected |
| Log File | Saves all alerts permanently to a local log file |

---

## Technologies Used

- **Language:** Python 3
- **Libraries:** Scapy, Psutil, Plyer
- **Server:** Ubuntu Server 24.04 LTS
- **Web Server:** Apache2
- **Dashboard:** Python HTTP Server with custom HTML and CSS
- **Virtualization:** VMware Workstation
- **Testing:** Nmap and Zenmap

---

## Architecture

```
                    Ubuntu Server (192.168.126.131)
                    
  Incoming Traffic
        |
        v
  +---------------------+
  |  Packet Sniffer     |  Scapy captures ARP and TCP packets
  +---------------------+
        |
        v
  +---------------------+     +---------------------+
  |  ARP Spoof Detector |     |  Port Scan Detector  |
  +---------------------+     +---------------------+
        |                           |
        v                           v
  +---------------------+     +---------------------+
  |  SSL Strip Detector |     |  Packet Inspector    |
  +---------------------+     +---------------------+
        |                           |
        +----------+----------------+
                   |
                   v
           +---------------+
           | trigger_alert |
           +---------------+
          /       |        \
         v        v         v
   Terminal    Log File   Email
      +
   Dashboard (port 9999)
```

---

## Attack Signatures Detected

**SQL Injection**
- UNION SELECT attacks
- OR 1=1 injection
- DROP TABLE commands
- xp_cmdshell execution

**Command Injection**
- Shell command injection (ls, whoami, cat /etc/passwd)
- Reverse shell attempts (netcat, bash -i)
- Direct shell execution (/bin/sh)

**Directory Traversal**
- Path traversal (../../../)
- URL encoded traversal (..%2f..%2f)
- Sensitive file access (/etc/passwd, /etc/shadow)

**Web Attacks**
- PHP webshell detection (.php?cmd=)
- Base64 eval webshells
- Cross-site scripting (XSS)
- JavaScript injection

**Network Attacks**
- ARP spoofing and MAC address poisoning
- TCP SYN port scanning
- SSL stripping and HTTPS downgrade attacks
- Suspicious tool signatures (Nikto, SQLmap, Masscan)

---

## Installation

**Step 1 — Clone or download the script**
```bash
mkdir ~/connection_monitor
cd ~/connection_monitor
```

**Step 2 — Install required libraries**
```bash
sudo pip3 install scapy psutil plyer --break-system-packages
```

**Step 3 — Configure settings**

Open the script and update the configuration section at the top:
```python
MONITOR_PORT        = 80       # Port to monitor
PORT_SCAN_THRESHOLD = 5        # Ports hit before scan alert fires
EMAIL_ALERTS        = True     # Enable email alerts
EMAIL_SENDER        = "your_alert_email@gmail.com"
EMAIL_PASSWORD      = "your_app_password"
EMAIL_RECEIVER      = "your_main_email@gmail.com"
```

**Step 4 — Open firewall port for dashboard**
```bash
sudo ufw allow 9999
```

**Step 5 — Run the script**
```bash
sudo python3 connection_monitor.py
```

---

## Usage

Once running the script outputs a startup banner:

```
============================================================
  CONNECTION MONITOR v5.0 STARTED
  Log file       : connection_monitor.log
  Monitoring port: 80
  Port scan limit: 5 ports in 10s
  SSL watch ports: [80, 8080]
  Attack patterns: 22
  Dashboard      : http://192.168.126.131:9999
============================================================
  Watching for:
  [1] New server/client connections
  [2] ARP spoofing (MitM attacks)
  [3] Port scanning (attacker reconnaissance)
  [4] SSL stripping (HTTPS downgrade to HTTP)
  [5] SQL injection, command injection, XSS, webshells
  [6] Dashboard live at http://192.168.126.131:9999
  You will be alerted immediately if an attacker is detected.
============================================================
```

**View the dashboard** by opening a browser and navigating to:
```
http://YOUR_SERVER_IP:9999
```

**View the log file** at any time:
```bash
cat ~/connection_monitor/connection_monitor.log
```

**Stop the monitor:**
```bash
Ctrl + C
```

---

## Dashboard

The web dashboard provides a real time view of all alerts:

- **Stat boxes** at the top showing total counts for each alert type
- **Alert table** showing timestamp, alert type and full details
- **Colour coded badges** for quick severity identification
  - Red: Critical attacks (SQL injection, XSS, webshells)
  - Orange: Warnings (port scans, SSL stripping)
  - Blue: Informational (new connections)
- **Auto refreshes** every 10 seconds

---

## Alert Types

| Alert | Severity | Trigger |
|---|---|---|
| ARP SPOOFING DETECTED | Critical | MAC address changes for a known IP |
| PORT SCAN DETECTED | High | IP hits 5 or more ports in 10 seconds |
| SQL INJECTION | Critical | SQL attack pattern in packet payload |
| CMD INJECTION | Critical | Shell command in packet payload |
| DIR TRAVERSAL | High | Path traversal pattern detected |
| WEBSHELL ATTEMPT | Critical | PHP or eval webshell signature found |
| XSS ATTACK | High | Script injection in HTTP traffic |
| SSL STRIPPING SUSPECTED | High | Sensitive keywords in plain HTTP |
| SSL REDIRECT INTERCEPTED | High | HTTP to HTTPS redirect detected |
| NEW CONNECTION | Info | New connection on monitored port |

---

## Project Context

This tool was built as a hands on cybersecurity learning project while studying for the CompTIA Security+ certification. It was deployed on a VMware Ubuntu Server VM running a live osTicket helpdesk application, and tested using Nmap and Zenmap port scanners to simulate real attacks.

The project demonstrates practical knowledge of:
- Network protocols (TCP, IP, ARP)
- Common attack techniques (MitM, port scanning, injection attacks)
- Python network programming with Scapy
- Multi-threaded application design
- Linux server administration

---

## Author

**Lizzy Oluwakoya**
IT Support and Systems Administration
AWS Cloud Practitioner | CompTIA Security+ (In Progress)
Halifax, Nova Scotia

---

## Disclaimer

This tool is intended for use on networks and systems you own or have explicit permission to monitor. Unauthorized network monitoring may be illegal in your jurisdiction.
