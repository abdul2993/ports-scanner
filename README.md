# ports-scanner

# 🔎 Port Scanner Tool

A fast, multithreaded Python-based TCP port scanner built for ethical hacking, system audits, and network security assessments.

---

## 🚀 Features

- Scan single or multiple ports (e.g. 22,80,443 or 1-1024)
- Common ports shortcut
- Hostname resolution
- Verbose mode for detailed info
- Multithreaded for high-speed scanning
- Simple and clean CLI interface

---

## 📦 Installation

### Clone the repository

```bash
git clone https://github.com/<your-username>/portscanner.git
cd portscanner
chmod +x portscanner.py

----------------------------------------------------------------------------------------------------------------

usage
./portscanner.py <target> [options]

--------------------------------------------------------------------------------------------------------------------

==============================
       Port Scanner Tool
==============================

[*] Starting Port Scanner...

Scan Results:
--------------------------------------------------
Target: scanme.nmap.org
Scanned ports: 22
Open ports: 2
Scan duration: 0.86 seconds

Port 22/tcp is open - Service: ssh
Port 80/tcp is open - Service: http
--------------------------------------------------
