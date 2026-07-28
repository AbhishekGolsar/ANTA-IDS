# =============================================================================
# File: ANTA-IDS/ids/rules.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Central configuration for IDS detection thresholds, observation windows,
#     and alert cooldown periods.
#
# Notes:
#     - Thresholds are currently tuned for development/testing.
#     - All time values are expressed in seconds.
#     - Production thresholds should be tuned against baseline network traffic.
# =============================================================================

from __future__ import annotations


# =============================================================================
# TCP Port Scan Detection
# =============================================================================
#
# Trigger when one source contacts at least this many unique destination
# TCP ports during the configured observation window.
#
# Tracker:
#     source_ip -> unique destination ports
# =============================================================================

PORT_SCAN_THRESHOLD: int = 10
PORT_SCAN_TIME_WINDOW: float = 5.0
PORT_SCAN_COOLDOWN: float = 10.0


# =============================================================================
# TCP SYN Flood Detection
# =============================================================================
#
# Trigger when one source sends a high number of initial SYN packets to the
# same destination IP and destination port.
#
# Tracker:
#     (source_ip, destination_ip, destination_port) -> SYN count
# =============================================================================

SYN_FLOOD_THRESHOLD: int = 50
SYN_FLOOD_TIME_WINDOW: float = 5.0
SYN_FLOOD_COOLDOWN: float = 10.0


# =============================================================================
# ICMP Flood Detection
# =============================================================================
#
# Trigger when one source generates a high number of ICMP packets toward the
# same destination during the observation window.
#
# Tracker:
#     (source_ip, destination_ip) -> ICMP count
# =============================================================================

ICMP_FLOOD_THRESHOLD: int = 30
ICMP_FLOOD_TIME_WINDOW: float = 5.0
ICMP_FLOOD_COOLDOWN: float = 10.0


# =============================================================================
# DNS Flood Detection
# =============================================================================
#
# Trigger when one source sends a high number of UDP DNS queries to the same
# DNS server. Only packets whose destination port is 53 are counted by the
# current detector.
#
# Tracker:
#     (source_ip, destination_ip) -> DNS query count
# =============================================================================

DNS_FLOOD_THRESHOLD: int = 30
DNS_FLOOD_TIME_WINDOW: float = 5.0
DNS_FLOOD_COOLDOWN: float = 10.0


# =============================================================================
# ARP Scan Detection
# =============================================================================
#
# Trigger when one source MAC queries many unique IPv4 targets using ARP
# requests during the observation window.
#
# Tracker:
#     source_mac -> unique target IPv4 addresses
# =============================================================================

ARP_SCAN_THRESHOLD: int = 20
ARP_SCAN_TIME_WINDOW: float = 5.0
ARP_SCAN_COOLDOWN: float = 10.0


# =============================================================================
# Broadcast Storm Detection
# =============================================================================
#
# Trigger when one source generates a high number of broadcast packets.
#
# The current detector recognizes:
#     - Ethernet FF:FF:FF:FF:FF:FF
#     - IPv4 255.255.255.255
#
# ARP traffic is excluded by the detector because normal ARP requests use
# Ethernet broadcast and are handled separately by ARP Scan Detection.
#
# Tracker:
#     source_ip -> broadcast packet count
# =============================================================================

BROADCAST_STORM_THRESHOLD: int = 50
BROADCAST_STORM_TIME_WINDOW: float = 5.0
BROADCAST_STORM_COOLDOWN: float = 10.0


# =============================================================================
# Rule Validation
# =============================================================================

_RULES = (
    ("PORT_SCAN_THRESHOLD", PORT_SCAN_THRESHOLD),
    ("PORT_SCAN_TIME_WINDOW", PORT_SCAN_TIME_WINDOW),
    ("PORT_SCAN_COOLDOWN", PORT_SCAN_COOLDOWN),

    ("SYN_FLOOD_THRESHOLD", SYN_FLOOD_THRESHOLD),
    ("SYN_FLOOD_TIME_WINDOW", SYN_FLOOD_TIME_WINDOW),
    ("SYN_FLOOD_COOLDOWN", SYN_FLOOD_COOLDOWN),

    ("ICMP_FLOOD_THRESHOLD", ICMP_FLOOD_THRESHOLD),
    ("ICMP_FLOOD_TIME_WINDOW", ICMP_FLOOD_TIME_WINDOW),
    ("ICMP_FLOOD_COOLDOWN", ICMP_FLOOD_COOLDOWN),

    ("DNS_FLOOD_THRESHOLD", DNS_FLOOD_THRESHOLD),
    ("DNS_FLOOD_TIME_WINDOW", DNS_FLOOD_TIME_WINDOW),
    ("DNS_FLOOD_COOLDOWN", DNS_FLOOD_COOLDOWN),

    ("ARP_SCAN_THRESHOLD", ARP_SCAN_THRESHOLD),
    ("ARP_SCAN_TIME_WINDOW", ARP_SCAN_TIME_WINDOW),
    ("ARP_SCAN_COOLDOWN", ARP_SCAN_COOLDOWN),

    ("BROADCAST_STORM_THRESHOLD", BROADCAST_STORM_THRESHOLD),
    ("BROADCAST_STORM_TIME_WINDOW", BROADCAST_STORM_TIME_WINDOW),
    ("BROADCAST_STORM_COOLDOWN", BROADCAST_STORM_COOLDOWN),
)


def validate_rules() -> None:
    """
    Validate IDS rule configuration.

    Raises
    ------
    ValueError
        If any configured threshold, observation window, or cooldown
        is zero or negative.
    """

    invalid_rules = [
        name
        for name, value in _RULES
        if value <= 0
    ]

    if invalid_rules:
        names = ", ".join(invalid_rules)

        raise ValueError(
            f"IDS rule values must be greater than zero: {names}"
        )


# Validate configuration immediately when this module is imported.
validate_rules()

