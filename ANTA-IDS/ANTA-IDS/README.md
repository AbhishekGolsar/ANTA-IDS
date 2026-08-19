# ANTA-IDS 🛡️
**Advanced Network Traffic Analyzer & Intrusion Detection System**

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![PySide6](https://img.shields.io/badge/GUI-PySide6-brightgreen)
![Scapy](https://img.shields.io/badge/Engine-Scapy-red)
![SQLite3](https://img.shields.io/badge/Database-SQLite3-lightgrey)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-orange)

**ANTA-IDS** is a multi-threaded, high-performance Network Traffic Analyzer and Intrusion Detection System built with Python. It captures live network packets, dissects protocols in real-time, and feeds data through a custom rules engine to detect volumetric attacks and malicious payloads—all visualized via a modern PySide6 graphical interface.

---

## ✨ Key Features
* **Real-Time Packet Sniffing:** Powered by `Scapy` to perform asynchronous live packet capture with multi-protocol parsing (TCP, UDP, ICMP, DNS).
* **Multi-Threaded GUI Bridge:** Engineered with explicit `QObject` signals to transfer background packet processing data safely to the PySide6 UI rendering loop without freezing the dashboard.
* **Live Intrusion Detection (IDS):** Detects TCP Port Scans, SYN Floods, ICMP Floods, and custom Regex Payload Signatures (e.g., SQL Injection) dynamically based on `rules.json`.
* **Stateful Cooldowns:** Intelligent alert suppression engine prevents log-spam during sustained volumetric attacks.
* **Persistent Database Storage:** Automatically commits parsed packets and security alerts into a local SQLite (`.db`) database.
* **Automated Audit Exports:** 1-click export of security alerts to time-stamped CSV files for digital forensics and reporting.
* **PyInstaller Ready:** Fully configured to compile into a single `.exe` executable for zero-dependency Windows deployments.

---

## 🏗️ Architecture & Directory Structure
The tool uses a strict modular architecture separating background I/O operations from UI rendering. 

```text
ANTA-IDS/
│
├── main.py                 # Core entry point & Thread Manager
├── config.py               # Global configuration & PyInstaller Pathing
├── requirements.txt        # Package dependencies
│
├── capture/                # Packet Ingestion Layer
│   ├── sniffer.py          # Scapy AsyncSniffer background thread
│   ├── interfaces.py       # Psutil OS network adapter mapping
│   └── parser.py           # Protocol decoding
│
├── ids/                    # Security Engine Layer
│   ├── detector.py         # Stateful traffic analysis
│   ├── rules.py            # Dynamic rules loading
│   └── rules.json          # Attack thresholds & Regex signatures
│
├── analyzer/               # Analytics Layer
│   ├── flow.py             # TCP/UDP connection tracking
│   ├── statistics.py       # Bandwidth & PPS calculations
│   └── protocol.py         # Deep packet inspection
│
├── gui/                    # Presentation Layer (PySide6)
│   ├── main_window.py      # Master QMainWindow
│   ├── dashboard.py        # Live metrics rendering
│   ├── packet_table.py     # Real-time QTableView
│   ├── alerts_tab.py       # Security alerts interface
│   └── dialogs.py          # Export & Prompt dialogs
│
├── database/               
│   └── database.py         # SQLite3 persistence layer
│
├── logs/                   # Daily rotating UTF-8 logs
├── reports/                # CSV export directory
└── docs/                   # Documentation