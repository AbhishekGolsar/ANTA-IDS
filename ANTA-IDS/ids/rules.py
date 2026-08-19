# =============================================================================
# File: ANTA-IDS/ids/rules.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Dynamic configuration for IDS detection thresholds.
#     Automatically reloads values if rules.json is modified.
# =============================================================================

import json
import threading
import time
from pathlib import Path
from utils.logger import Logger

logger = Logger.get_logger(__name__)

# Safely import the enterprise path mapping from config.py
try:
    from config import RULES_FILE
except ImportError:
    RULES_FILE = Path.cwd() / "rules" / "rules.json"


# =============================================================================
# Default Thresholds (Fallback)
# =============================================================================

PORT_SCAN_THRESHOLD: int = 10
PORT_SCAN_TIME_WINDOW: float = 5.0
PORT_SCAN_COOLDOWN: float = 10.0

SYN_FLOOD_THRESHOLD: int = 50
SYN_FLOOD_TIME_WINDOW: float = 5.0
SYN_FLOOD_COOLDOWN: float = 10.0

ICMP_FLOOD_THRESHOLD: int = 30
ICMP_FLOOD_TIME_WINDOW: float = 5.0
ICMP_FLOOD_COOLDOWN: float = 10.0

DNS_FLOOD_THRESHOLD: int = 30
DNS_FLOOD_TIME_WINDOW: float = 5.0
DNS_FLOOD_COOLDOWN: float = 10.0

ARP_SCAN_THRESHOLD: int = 20
ARP_SCAN_TIME_WINDOW: float = 5.0
ARP_SCAN_COOLDOWN: float = 10.0

BROADCAST_STORM_THRESHOLD: int = 50
BROADCAST_STORM_TIME_WINDOW: float = 5.0
BROADCAST_STORM_COOLDOWN: float = 10.0


_last_modified_time = 0.0

def load_rules() -> None:
    """
    Load thresholds from the rules.json file.
    """
    global PORT_SCAN_THRESHOLD, PORT_SCAN_TIME_WINDOW, PORT_SCAN_COOLDOWN
    global SYN_FLOOD_THRESHOLD, SYN_FLOOD_TIME_WINDOW, SYN_FLOOD_COOLDOWN
    global ICMP_FLOOD_THRESHOLD, ICMP_FLOOD_TIME_WINDOW, ICMP_FLOOD_COOLDOWN
    global DNS_FLOOD_THRESHOLD, DNS_FLOOD_TIME_WINDOW, DNS_FLOOD_COOLDOWN
    global ARP_SCAN_THRESHOLD, ARP_SCAN_TIME_WINDOW, ARP_SCAN_COOLDOWN
    global BROADCAST_STORM_THRESHOLD, BROADCAST_STORM_TIME_WINDOW, BROADCAST_STORM_COOLDOWN
    global _last_modified_time

    if not RULES_FILE.exists():
        return

    try:
        current_mtime = RULES_FILE.stat().st_mtime
        if current_mtime <= _last_modified_time:
            return

        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        PORT_SCAN_THRESHOLD = data.get("PORT_SCAN_THRESHOLD", PORT_SCAN_THRESHOLD)
        PORT_SCAN_TIME_WINDOW = data.get("PORT_SCAN_TIME_WINDOW", PORT_SCAN_TIME_WINDOW)
        PORT_SCAN_COOLDOWN = data.get("PORT_SCAN_COOLDOWN", PORT_SCAN_COOLDOWN)
        
        SYN_FLOOD_THRESHOLD = data.get("SYN_FLOOD_THRESHOLD", SYN_FLOOD_THRESHOLD)
        SYN_FLOOD_TIME_WINDOW = data.get("SYN_FLOOD_TIME_WINDOW", SYN_FLOOD_TIME_WINDOW)
        SYN_FLOOD_COOLDOWN = data.get("SYN_FLOOD_COOLDOWN", SYN_FLOOD_COOLDOWN)

        ICMP_FLOOD_THRESHOLD = data.get("ICMP_FLOOD_THRESHOLD", ICMP_FLOOD_THRESHOLD)
        ICMP_FLOOD_TIME_WINDOW = data.get("ICMP_FLOOD_TIME_WINDOW", ICMP_FLOOD_TIME_WINDOW)
        ICMP_FLOOD_COOLDOWN = data.get("ICMP_FLOOD_COOLDOWN", ICMP_FLOOD_COOLDOWN)

        DNS_FLOOD_THRESHOLD = data.get("DNS_FLOOD_THRESHOLD", DNS_FLOOD_THRESHOLD)
        DNS_FLOOD_TIME_WINDOW = data.get("DNS_FLOOD_TIME_WINDOW", DNS_FLOOD_TIME_WINDOW)
        DNS_FLOOD_COOLDOWN = data.get("DNS_FLOOD_COOLDOWN", DNS_FLOOD_COOLDOWN)

        ARP_SCAN_THRESHOLD = data.get("ARP_SCAN_THRESHOLD", ARP_SCAN_THRESHOLD)
        ARP_SCAN_TIME_WINDOW = data.get("ARP_SCAN_TIME_WINDOW", ARP_SCAN_TIME_WINDOW)
        ARP_SCAN_COOLDOWN = data.get("ARP_SCAN_COOLDOWN", ARP_SCAN_COOLDOWN)

        BROADCAST_STORM_THRESHOLD = data.get("BROADCAST_STORM_THRESHOLD", BROADCAST_STORM_THRESHOLD)
        BROADCAST_STORM_TIME_WINDOW = data.get("BROADCAST_STORM_TIME_WINDOW", BROADCAST_STORM_TIME_WINDOW)
        BROADCAST_STORM_COOLDOWN = data.get("BROADCAST_STORM_COOLDOWN", BROADCAST_STORM_COOLDOWN)

        _last_modified_time = current_mtime
        logger.info("IDS Rules dynamically reloaded from rules.json")

    except Exception:
        logger.exception("Failed to load rules.json, retaining current rules.")

def _rule_watcher():
    """Background thread to monitor configuration changes."""
    while True:
        time.sleep(5)
        load_rules()

# Initial load and start watcher
load_rules()
# daemon=True ensures this thread dies instantly when the main PySide6 window is closed
threading.Thread(target=_rule_watcher, daemon=True).start()