# =============================================================================
# File: ANTA-IDS/ids/detector.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Stateful IDS detection engine (IPv6 + Payload Inspection enabled).
# =============================================================================

from __future__ import annotations
import time
import re
from collections import defaultdict, deque
from typing import Deque, Dict, Hashable, Set, Tuple

from capture.parser import PacketInfo
from ids.alerts import AlertManager
from ids import rules  # Dynamic module import
from utils.logger import Logger

logger = Logger.get_logger(__name__)
TimestampQueue = Deque[float]

# Known attack signatures for Payload Inspection
PAYLOAD_SIGNATURES = {
    "SQL Injection (Generic)": re.compile(b"union\\s+select|'\\s*OR\\s*1\\s*=\\s*1", re.IGNORECASE),
    "VSFTPD Backdoor (CVE-2011-2523)": re.compile(b"USER\\s+.*:\\)"),
    "Cross-Site Scripting (XSS)": re.compile(b"<script.*?>.*?</script>", re.IGNORECASE)
}

class IDSDetector:
    """
    Stateful intrusion detection engine for ANTA-IDS.
    """

    def __init__(self) -> None:
        self.alerts = AlertManager()

        self._port_scan_events: Dict[str, Deque[Tuple[float, str, int]]] = defaultdict(deque)
        self._port_scan_last_alert: Dict[str, float] = {}

        self._syn_flood_events: Dict[Tuple[str, str, int], TimestampQueue] = defaultdict(deque)
        self._syn_flood_last_alert: Dict[Tuple[str, str, int], float] = {}

        self._icmp_flood_events: Dict[Tuple[str, str], TimestampQueue] = defaultdict(deque)
        self._icmp_flood_last_alert: Dict[Tuple[str, str], float] = {}

        self._dns_flood_events: Dict[Tuple[str, str], TimestampQueue] = defaultdict(deque)
        self._dns_flood_last_alert: Dict[Tuple[str, str], float] = {}

        self._arp_scan_events: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self._arp_scan_last_alert: Dict[str, float] = {}

        self._broadcast_events: Dict[str, TimestampQueue] = defaultdict(deque)
        self._broadcast_last_alert: Dict[str, float] = {}

        self._payload_last_alert: Dict[Tuple[str, str], float] = {}

        logger.debug("IDSDetector initialized successfully.")

    def analyze(self, packet: PacketInfo) -> None:
        if packet is None: return
        now = time.monotonic()
        detectors = (
            self._detect_port_scan,
            self._detect_syn_flood,
            self._detect_icmp_flood,
            self._detect_dns_flood,
            self._detect_arp_scan,
            self._detect_broadcast_storm,
            self._detect_payload_signatures
        )
        for detector in detectors:
            try:
                detector(packet, now)
            except Exception:
                logger.exception(f"IDS detector failed: {detector.__name__}")

    @staticmethod
    def _trim_timestamp_queue(events: TimestampQueue, now: float, window: float) -> None:
        cutoff = now - window
        while events and events[0] < cutoff:
            events.popleft()

    @staticmethod
    def _cooldown_ready(last_alerts: Dict[Hashable, float], key: Hashable, now: float, cooldown: float) -> bool:
        last_alert = last_alerts.get(key)
        if last_alert is None: return True
        return (now - last_alert) >= cooldown

    @staticmethod
    def _mark_alert(last_alerts: Dict[Hashable, float], key: Hashable, now: float) -> None:
        last_alerts[key] = now

    def _emit_alert(self, *, severity: str, detector: str, source_ip: str, destination_ip: str, message: str) -> None:
        self.alerts.add_alert(severity=severity, detector=detector, source_ip=source_ip, destination_ip=destination_ip, message=message)

    # -------------------------------------------------------------------------
    # Payload Signature Detection
    # -------------------------------------------------------------------------
    def _detect_payload_signatures(self, packet: PacketInfo, now: float) -> None:
        if not getattr(packet, 'raw_payload', b""):
            return

        for attack_name, pattern in PAYLOAD_SIGNATURES.items():
            if pattern.search(packet.raw_payload):
                key = (packet.src_ip, attack_name)
                
                if not self._cooldown_ready(self._payload_last_alert, key, now, 10.0):
                    return

                self._emit_alert(
                    severity="CRITICAL",
                    detector="Payload Inspection",
                    source_ip=packet.src_ip,
                    destination_ip=packet.dst_ip,
                    message=f"Cleartext payload signature matched: {attack_name}. Possible exploitation attempt."
                )
                self._mark_alert(self._payload_last_alert, key, now)

    # -------------------------------------------------------------------------
    # Rule Upgrades
    # -------------------------------------------------------------------------
    def _detect_port_scan(self, packet: PacketInfo, now: float) -> None:
        if packet.protocol != "TCP" or not packet.src_ip or packet.dst_port is None: return
        flags = str(packet.tcp_flags or "").upper()
        if "S" not in flags or "A" in flags: return

        events = self._port_scan_events[packet.src_ip]
        events.append((now, packet.dst_ip, int(packet.dst_port)))
        
        # FIX: Manually trim the tuple queue
        cutoff = now - rules.PORT_SCAN_TIME_WINDOW
        while events and events[0][0] < cutoff:
            events.popleft()

        unique_ports = {port for _, _, port in events}
        if len(unique_ports) < rules.PORT_SCAN_THRESHOLD: return
        if not self._cooldown_ready(self._port_scan_last_alert, packet.src_ip, now, rules.PORT_SCAN_COOLDOWN): return

        self._emit_alert(
            severity="HIGH", detector="TCP Port Scan", source_ip=packet.src_ip, destination_ip=packet.dst_ip,
            message=f"Possible TCP SYN port scan. Contacted {len(unique_ports)} unique ports in {rules.PORT_SCAN_TIME_WINDOW}s."
        )
        self._mark_alert(self._port_scan_last_alert, packet.src_ip, now)

    def _detect_syn_flood(self, packet: PacketInfo, now: float) -> None:
        if packet.protocol != "TCP" or not packet.src_ip or packet.dst_port is None: return
        flags = str(packet.tcp_flags or "").upper()
        if "S" not in flags or "A" in flags: return

        key = (packet.src_ip, packet.dst_ip, int(packet.dst_port))
        events = self._syn_flood_events[key]
        events.append(now)
        self._trim_timestamp_queue(events, now, rules.SYN_FLOOD_TIME_WINDOW)

        if len(events) < rules.SYN_FLOOD_THRESHOLD: return
        if not self._cooldown_ready(self._syn_flood_last_alert, key, now, rules.SYN_FLOOD_COOLDOWN): return

        self._emit_alert(
            severity="CRITICAL", detector="TCP SYN Flood", source_ip=packet.src_ip, destination_ip=packet.dst_ip,
            message=f"TCP SYN flood detected. {len(events)} packets to port {packet.dst_port} in {rules.SYN_FLOOD_TIME_WINDOW}s."
        )
        self._mark_alert(self._syn_flood_last_alert, key, now)

    def _detect_icmp_flood(self, packet: PacketInfo, now: float) -> None:
        if packet.protocol != "ICMP" or not packet.src_ip: return
        key = (packet.src_ip, packet.dst_ip)
        events = self._icmp_flood_events[key]
        events.append(now)
        self._trim_timestamp_queue(events, now, rules.ICMP_FLOOD_TIME_WINDOW)

        if len(events) < rules.ICMP_FLOOD_THRESHOLD: return
        if not self._cooldown_ready(self._icmp_flood_last_alert, key, now, rules.ICMP_FLOOD_COOLDOWN): return

        self._emit_alert(
            severity="HIGH", detector="ICMP Flood", source_ip=packet.src_ip, destination_ip=packet.dst_ip,
            message=f"ICMP flood detected. {len(events)} packets in {rules.ICMP_FLOOD_TIME_WINDOW}s."
        )
        self._mark_alert(self._icmp_flood_last_alert, key, now)

    def _detect_dns_flood(self, packet: PacketInfo, now: float) -> None:
        if packet.protocol != "UDP" or packet.dst_port != 53 or not packet.src_ip: return
        key = (packet.src_ip, packet.dst_ip)
        events = self._dns_flood_events[key]
        events.append(now)
        self._trim_timestamp_queue(events, now, rules.DNS_FLOOD_TIME_WINDOW)

        if len(events) < rules.DNS_FLOOD_THRESHOLD: return
        if not self._cooldown_ready(self._dns_flood_last_alert, key, now, rules.DNS_FLOOD_COOLDOWN): return

        self._emit_alert(
            severity="HIGH", detector="DNS Flood", source_ip=packet.src_ip, destination_ip=packet.dst_ip,
            message=f"DNS query flood detected. {len(events)} queries to port 53 in {rules.DNS_FLOOD_TIME_WINDOW}s."
        )
        self._mark_alert(self._dns_flood_last_alert, key, now)

    def _detect_arp_scan(self, packet: PacketInfo, now: float) -> None:
        if packet.protocol != "ARP" or getattr(packet, "arp_operation", None) != 1: return
        source_mac = getattr(packet, "src_mac", None) or packet.src_ip
        if not source_mac or not packet.dst_ip: return

        events = self._arp_scan_events[source_mac]
        events.append((now, packet.dst_ip))
        
        # FIX: Manually trim the tuple queue
        cutoff = now - rules.ARP_SCAN_TIME_WINDOW
        while events and events[0][0] < cutoff:
            events.popleft()

        unique_targets = {target for _, target in events if target}
        if len(unique_targets) < rules.ARP_SCAN_THRESHOLD: return
        if not self._cooldown_ready(self._arp_scan_last_alert, source_mac, now, rules.ARP_SCAN_COOLDOWN): return

        source_ip = packet.src_ip or source_mac
        self._emit_alert(
            severity="HIGH", detector="ARP Scan", source_ip=source_ip, destination_ip=packet.dst_ip,
            message=f"ARP scan detected. {len(unique_targets)} unique IPs queried in {rules.ARP_SCAN_TIME_WINDOW}s."
        )
        self._mark_alert(self._arp_scan_last_alert, source_mac, now)

    def _detect_broadcast_storm(self, packet: PacketInfo, now: float) -> None:
        if packet.protocol == "ARP" or not packet.src_ip: return
        
        is_multicast_ipv6 = str(packet.dst_ip).lower().startswith("ff02:")
        is_ipv4_broadcast = (packet.dst_ip == "255.255.255.255")
        is_ethernet_broadcast = (str(getattr(packet, "dst_mac", "")).lower() == "ff:ff:ff:ff:ff:ff")

        if not (is_ipv4_broadcast or is_ethernet_broadcast or is_multicast_ipv6): return

        events = self._broadcast_events[packet.src_ip]
        events.append(now)
        self._trim_timestamp_queue(events, now, rules.BROADCAST_STORM_TIME_WINDOW)

        if len(events) < rules.BROADCAST_STORM_THRESHOLD: return
        if not self._cooldown_ready(self._broadcast_last_alert, packet.src_ip, now, rules.BROADCAST_STORM_COOLDOWN): return

        alert_destination = packet.dst_ip or getattr(packet, "dst_mac", "BROADCAST")
        self._emit_alert(
            severity="CRITICAL", detector="Broadcast Storm", source_ip=packet.src_ip, destination_ip=alert_destination,
            message=f"Broadcast storm detected. {len(events)} broadcast packets in {rules.BROADCAST_STORM_TIME_WINDOW}s."
        )
        self._mark_alert(self._broadcast_last_alert, packet.src_ip, now)

    # =========================================================================
    # State Management & Accessors (Restored)
    # =========================================================================

    def reset(self) -> None:
        self._port_scan_events.clear()
        self._port_scan_last_alert.clear()
        self._syn_flood_events.clear()
        self._syn_flood_last_alert.clear()
        self._icmp_flood_events.clear()
        self._icmp_flood_last_alert.clear()
        self._dns_flood_events.clear()
        self._dns_flood_last_alert.clear()
        self._arp_scan_events.clear()
        self._arp_scan_last_alert.clear()
        self._broadcast_events.clear()
        self._broadcast_last_alert.clear()
        self._payload_last_alert.clear()
        self.alerts.clear()
        logger.debug("IDS detector state reset.")

    def get_alerts(self):
        return self.alerts.get_alerts()

    def alert_count(self) -> int:
        return self.alerts.alert_count()

    def __len__(self) -> int:
        return self.alert_count()

    def __repr__(self) -> str:
        return (
            f"IDSDetector("
            f"alerts={self.alert_count()}, "
            f"port_scan_sources={len(self._port_scan_events)}, "
            f"syn_flood_flows={len(self._syn_flood_events)}, "
            f"icmp_flows={len(self._icmp_flood_events)}, "
            f"dns_flows={len(self._dns_flood_events)}, "
            f"arp_sources={len(self._arp_scan_events)}, "
            f"broadcast_sources={len(self._broadcast_events)}"
            f")"
        )