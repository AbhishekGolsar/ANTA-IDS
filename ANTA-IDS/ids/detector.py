# =============================================================================
# File: ANTA-IDS/ids/detector.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Stateful IDS detection engine.
#
# Detectors:
#     - TCP Port Scan
#     - TCP SYN Flood
#     - ICMP Flood
#     - DNS Flood
#     - ARP Scan
#     - Broadcast Storm
# =============================================================================

from __future__ import annotations

import time

from collections import defaultdict, deque
from typing import Deque, Dict, Hashable, Set, Tuple

from capture.parser import PacketInfo
from ids.alerts import AlertManager
from ids.rules import (
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_TIME_WINDOW,
    PORT_SCAN_COOLDOWN,
    SYN_FLOOD_THRESHOLD,
    SYN_FLOOD_TIME_WINDOW,
    SYN_FLOOD_COOLDOWN,
    ICMP_FLOOD_THRESHOLD,
    ICMP_FLOOD_TIME_WINDOW,
    ICMP_FLOOD_COOLDOWN,
    DNS_FLOOD_THRESHOLD,
    DNS_FLOOD_TIME_WINDOW,
    DNS_FLOOD_COOLDOWN,
    ARP_SCAN_THRESHOLD,
    ARP_SCAN_TIME_WINDOW,
    ARP_SCAN_COOLDOWN,
    BROADCAST_STORM_THRESHOLD,
    BROADCAST_STORM_TIME_WINDOW,
    BROADCAST_STORM_COOLDOWN,
)

from utils.logger import Logger


logger = Logger.get_logger(__name__)


TimestampQueue = Deque[float]


class IDSDetector:
    """
    Stateful intrusion detection engine for ANTA-IDS.

    Each incoming PacketInfo object is inspected by the enabled
    detection rules. Time-based queues are used so old observations
    are automatically removed from each detection window.
    """

    def __init__(self) -> None:

        # ---------------------------------------------------------------------
        # Alert management
        # ---------------------------------------------------------------------

        self.alerts = AlertManager()

        # ---------------------------------------------------------------------
        # TCP Port Scan
        #
        # source_ip ->
        #     deque[(timestamp, destination_ip, destination_port)]
        # ---------------------------------------------------------------------

        self._port_scan_events: Dict[
            str,
            Deque[Tuple[float, str, int]],
        ] = defaultdict(deque)

        self._port_scan_last_alert: Dict[str, float] = {}

        # ---------------------------------------------------------------------
        # TCP SYN Flood
        #
        # (source_ip, destination_ip, destination_port) ->
        #     deque[timestamp]
        # ---------------------------------------------------------------------

        self._syn_flood_events: Dict[
            Tuple[str, str, int],
            TimestampQueue,
        ] = defaultdict(deque)

        self._syn_flood_last_alert: Dict[
            Tuple[str, str, int],
            float,
        ] = {}

        # ---------------------------------------------------------------------
        # ICMP Flood
        #
        # (source_ip, destination_ip) ->
        #     deque[timestamp]
        # ---------------------------------------------------------------------

        self._icmp_flood_events: Dict[
            Tuple[str, str],
            TimestampQueue,
        ] = defaultdict(deque)

        self._icmp_flood_last_alert: Dict[
            Tuple[str, str],
            float,
        ] = {}

        # ---------------------------------------------------------------------
        # DNS Flood
        #
        # (source_ip, destination_ip) ->
        #     deque[timestamp]
        # ---------------------------------------------------------------------

        self._dns_flood_events: Dict[
            Tuple[str, str],
            TimestampQueue,
        ] = defaultdict(deque)

        self._dns_flood_last_alert: Dict[
            Tuple[str, str],
            float,
        ] = {}

        # ---------------------------------------------------------------------
        # ARP Scan
        #
        # source_mac ->
        #     deque[(timestamp, target_ip)]
        # ---------------------------------------------------------------------

        self._arp_scan_events: Dict[
            str,
            Deque[Tuple[float, str]],
        ] = defaultdict(deque)

        self._arp_scan_last_alert: Dict[str, float] = {}

        # ---------------------------------------------------------------------
        # Broadcast Storm
        #
        # source_ip ->
        #     deque[timestamp]
        # ---------------------------------------------------------------------

        self._broadcast_events: Dict[
            str,
            TimestampQueue,
        ] = defaultdict(deque)

        self._broadcast_last_alert: Dict[str, float] = {}

        logger.debug(
            "IDSDetector initialized successfully."
        )

    # =========================================================================
    # Public API
    # =========================================================================

    def analyze(self, packet: PacketInfo) -> None:
        """
        Analyze one parsed packet against all IDS rules.

        A failure in one detector must not prevent the remaining
        detectors from inspecting the packet.
        """

        if packet is None:
            return

        now = time.monotonic()

        detectors = (
            self._detect_port_scan,
            self._detect_syn_flood,
            self._detect_icmp_flood,
            self._detect_dns_flood,
            self._detect_arp_scan,
            self._detect_broadcast_storm,
        )

        for detector in detectors:

            try:
                detector(packet, now)

            except Exception:
                logger.exception(
                    "IDS detector failed: %s",
                    detector.__name__,
                )

    # =========================================================================
    # Generic Helpers
    # =========================================================================

    @staticmethod
    def _trim_timestamp_queue(
        events: TimestampQueue,
        now: float,
        window: float,
    ) -> None:
        """
        Remove timestamps outside the configured observation window.
        """

        cutoff = now - window

        while events and events[0] < cutoff:
            events.popleft()

    @staticmethod
    def _cooldown_ready(
        last_alerts: Dict[Hashable, float],
        key: Hashable,
        now: float,
        cooldown: float,
    ) -> bool:
        """
        Return True when an alert key is outside its cooldown period.
        """

        last_alert = last_alerts.get(key)

        if last_alert is None:
            return True

        return (now - last_alert) >= cooldown

    @staticmethod
    def _mark_alert(
        last_alerts: Dict[Hashable, float],
        key: Hashable,
        now: float,
    ) -> None:
        """
        Record the most recent alert time for a detector key.
        """

        last_alerts[key] = now

    def _emit_alert(
        self,
        *,
        severity: str,
        detector: str,
        source_ip: str,
        destination_ip: str,
        message: str,
    ) -> None:
        """
        Send an alert to AlertManager.

        AlertManager is responsible for storing, logging, and
        optionally displaying the alert.

        IMPORTANT:
        Do not call self.alerts.show_alert() here because the updated
        AlertManager already handles console presentation.
        """

        self.alerts.add_alert(
            severity=severity,
            detector=detector,
            source_ip=source_ip,
            destination_ip=destination_ip,
            message=message,
        )
    # =========================================================================
    # TCP Port Scan Detection
    # =========================================================================

    def _detect_port_scan(
        self,
        packet: PacketInfo,
        now: float,
    ) -> None:
        """
        Detect TCP port scanning.

        A scan is suspected when one source contacts a configured
        number of unique TCP destination ports within the observation
        window.
        """

        if packet.protocol != "TCP":
            return

        if not packet.src_ip or not packet.dst_ip:
            return

        if packet.dst_port is None:
            return

        # Only initial SYN packets should contribute to TCP scan detection.
        flags = str(packet.tcp_flags or "").upper()

        if "S" not in flags or "A" in flags:
            return

        source_ip = packet.src_ip

        events = self._port_scan_events[source_ip]

        events.append(
            (
                now,
                packet.dst_ip,
                int(packet.dst_port),
            )
        )

        cutoff = now - PORT_SCAN_TIME_WINDOW

        while events and events[0][0] < cutoff:
            events.popleft()

        # Determine unique destination ports observed in the window.
        unique_ports: Set[int] = {
            destination_port
            for _, _, destination_port in events
        }

        if len(unique_ports) < PORT_SCAN_THRESHOLD:
            return

        if not self._cooldown_ready(
            self._port_scan_last_alert,
            source_ip,
            now,
            PORT_SCAN_COOLDOWN,
        ):
            return

        # Track how many different hosts were contacted.
        destination_hosts = {
            destination_ip
            for _, destination_ip, _ in events
        }

        ports = sorted(unique_ports)

        destination_ip = packet.dst_ip

        self._emit_alert(
            severity="HIGH",
            detector="TCP Port Scan",
            source_ip=source_ip,
            destination_ip=destination_ip,
            message=(
                "Possible TCP SYN port scan detected. "
                f"Source contacted {len(unique_ports)} unique "
                f"destination ports across "
                f"{len(destination_hosts)} destination host(s) "
                f"within {PORT_SCAN_TIME_WINDOW:g} seconds. "
                f"Ports: {ports}"
            ),
        )

        self._mark_alert(
            self._port_scan_last_alert,
            source_ip,
            now,
        )

    # =========================================================================
    # TCP SYN Flood Detection
    # =========================================================================

    def _detect_syn_flood(
        self,
        packet: PacketInfo,
        now: float,
    ) -> None:
        """
        Detect a possible TCP SYN flood.

        Initial SYN packets are counted for each:

            source IP
            destination IP
            destination port

        SYN-ACK packets are excluded.
        """

        if packet.protocol != "TCP":
            return

        if not packet.src_ip or not packet.dst_ip:
            return

        if packet.dst_port is None:
            return

        flags = str(packet.tcp_flags or "").upper()

        # Count SYN packets only.
        if "S" not in flags:
            return

        # Ignore SYN-ACK responses.
        if "A" in flags:
            return

        destination_port = int(packet.dst_port)

        key = (
            packet.src_ip,
            packet.dst_ip,
            destination_port,
        )

        events = self._syn_flood_events[key]

        events.append(now)

        self._trim_timestamp_queue(
            events,
            now,
            SYN_FLOOD_TIME_WINDOW,
        )

        if len(events) < SYN_FLOOD_THRESHOLD:
            return

        if not self._cooldown_ready(
            self._syn_flood_last_alert,
            key,
            now,
            SYN_FLOOD_COOLDOWN,
        ):
            return

        self._emit_alert(
            severity="CRITICAL",
            detector="TCP SYN Flood",
            source_ip=packet.src_ip,
            destination_ip=packet.dst_ip,
            message=(
                "Possible TCP SYN flood detected. "
                f"Observed {len(events)} SYN packets from "
                f"{packet.src_ip} to "
                f"{packet.dst_ip}:{destination_port} "
                f"within {SYN_FLOOD_TIME_WINDOW:g} seconds."
            ),
        )

        self._mark_alert(
            self._syn_flood_last_alert,
            key,
            now,
        )

    # =========================================================================
    # ICMP Flood Detection
    # =========================================================================

    def _detect_icmp_flood(
        self,
        packet: PacketInfo,
        now: float,
    ) -> None:
        """
        Detect a possible ICMP flood.

        ICMP packets are tracked per source/destination pair.
        """

        if packet.protocol != "ICMP":
            return

        if not packet.src_ip or not packet.dst_ip:
            return

        key = (
            packet.src_ip,
            packet.dst_ip,
        )

        events = self._icmp_flood_events[key]

        events.append(now)

        self._trim_timestamp_queue(
            events,
            now,
            ICMP_FLOOD_TIME_WINDOW,
        )

        if len(events) < ICMP_FLOOD_THRESHOLD:
            return

        if not self._cooldown_ready(
            self._icmp_flood_last_alert,
            key,
            now,
            ICMP_FLOOD_COOLDOWN,
        ):
            return

        self._emit_alert(
            severity="HIGH",
            detector="ICMP Flood",
            source_ip=packet.src_ip,
            destination_ip=packet.dst_ip,
            message=(
                "Possible ICMP flood detected. "
                f"Observed {len(events)} ICMP packets from "
                f"{packet.src_ip} to {packet.dst_ip} "
                f"within {ICMP_FLOOD_TIME_WINDOW:g} seconds."
            ),
        )

        self._mark_alert(
            self._icmp_flood_last_alert,
            key,
            now,
        )
    # =========================================================================
    # DNS Flood Detection
    # =========================================================================

    def _detect_dns_flood(
        self,
        packet: PacketInfo,
        now: float,
    ) -> None:
        """
        Detect a possible DNS query flood.

        The current rule counts UDP packets sent to destination port 53,
        grouped by source and destination IP.
        """

        if packet.protocol != "UDP":
            return

        if not packet.src_ip or not packet.dst_ip:
            return

        if packet.dst_port != 53:
            return

        key = (
            packet.src_ip,
            packet.dst_ip,
        )

        events = self._dns_flood_events[key]

        events.append(now)

        self._trim_timestamp_queue(
            events,
            now,
            DNS_FLOOD_TIME_WINDOW,
        )

        if len(events) < DNS_FLOOD_THRESHOLD:
            return

        if not self._cooldown_ready(
            self._dns_flood_last_alert,
            key,
            now,
            DNS_FLOOD_COOLDOWN,
        ):
            return

        self._emit_alert(
            severity="HIGH",
            detector="DNS Flood",
            source_ip=packet.src_ip,
            destination_ip=packet.dst_ip,
            message=(
                "Possible DNS query flood detected. "
                f"Observed {len(events)} DNS queries from "
                f"{packet.src_ip} to {packet.dst_ip}:53 "
                f"within {DNS_FLOOD_TIME_WINDOW:g} seconds."
            ),
        )

        self._mark_alert(
            self._dns_flood_last_alert,
            key,
            now,
        )

    # =========================================================================
    # ARP Scan Detection
    # =========================================================================

    def _detect_arp_scan(
        self,
        packet: PacketInfo,
        now: float,
    ) -> None:
        """
        Detect possible ARP scanning.

        ARP requests are grouped by source MAC address. A scan is
        suspected when one source queries many unique IPv4 targets
        inside the configured observation window.
        """

        if packet.protocol != "ARP":
            return

        # Only ARP requests should contribute to scan detection.
        arp_operation = getattr(packet, "arp_operation", None)

        if arp_operation != 1:
            return

        source_mac = (
            getattr(packet, "src_mac", None)
            or packet.src_ip
        )

        target_ip = packet.dst_ip

        if not source_mac or not target_ip:
            return

        events = self._arp_scan_events[source_mac]

        events.append(
            (
                now,
                target_ip,
            )
        )

        cutoff = now - ARP_SCAN_TIME_WINDOW

        while events and events[0][0] < cutoff:
            events.popleft()

        unique_targets: Set[str] = {
            target
            for _, target in events
            if target
        }

        if len(unique_targets) < ARP_SCAN_THRESHOLD:
            return

        if not self._cooldown_ready(
            self._arp_scan_last_alert,
            source_mac,
            now,
            ARP_SCAN_COOLDOWN,
        ):
            return

        targets = sorted(unique_targets)

        source_ip = packet.src_ip or source_mac

        self._emit_alert(
            severity="HIGH",
            detector="ARP Scan",
            source_ip=source_ip,
            destination_ip=target_ip,
            message=(
                "Possible ARP scan detected. "
                f"Source {source_ip} ({source_mac}) queried "
                f"{len(unique_targets)} unique IP addresses "
                f"within {ARP_SCAN_TIME_WINDOW:g} seconds. "
                f"Targets: {targets}"
            ),
        )

        self._mark_alert(
            self._arp_scan_last_alert,
            source_mac,
            now,
        )

    # =========================================================================
    # Broadcast Storm Detection
    # =========================================================================

    def _detect_broadcast_storm(
        self,
        packet: PacketInfo,
        now: float,
    ) -> None:
        """
        Detect a possible broadcast storm.

        Recognized broadcast traffic:

            Ethernet:
                ff:ff:ff:ff:ff:ff

            IPv4:
                255.255.255.255

        ARP packets are excluded because ARP requests normally use
        Ethernet broadcast and are handled by ARP Scan Detection.
        """

        if packet.protocol == "ARP":
            return

        source_ip = packet.src_ip

        if not source_ip:
            return

        destination_ip = packet.dst_ip or ""

        destination_mac = (
            getattr(packet, "dst_mac", None)
            or ""
        ).lower()

        is_ipv4_broadcast = (
            destination_ip == "255.255.255.255"
        )

        is_ethernet_broadcast = (
            destination_mac == "ff:ff:ff:ff:ff:ff"
        )

        if not (
            is_ipv4_broadcast
            or is_ethernet_broadcast
        ):
            return

        events = self._broadcast_events[source_ip]

        events.append(now)

        self._trim_timestamp_queue(
            events,
            now,
            BROADCAST_STORM_TIME_WINDOW,
        )

        if len(events) < BROADCAST_STORM_THRESHOLD:
            return

        if not self._cooldown_ready(
            self._broadcast_last_alert,
            source_ip,
            now,
            BROADCAST_STORM_COOLDOWN,
        ):
            return

        alert_destination = (
            destination_ip
            or destination_mac
            or "BROADCAST"
        )

        self._emit_alert(
            severity="CRITICAL",
            detector="Broadcast Storm",
            source_ip=source_ip,
            destination_ip=alert_destination,
            message=(
                "Possible broadcast storm detected. "
                f"Observed {len(events)} broadcast packets "
                f"from {source_ip} within "
                f"{BROADCAST_STORM_TIME_WINDOW:g} seconds."
            ),
        )

        self._mark_alert(
            self._broadcast_last_alert,
            source_ip,
            now,
        )

    # =========================================================================
    # State Management
    # =========================================================================

    def reset(self) -> None:
        """
        Reset all IDS tracking state and stored alerts.

        Useful when restarting a capture session without creating
        a new IDSDetector instance.
        """

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

        self.alerts.clear()

        logger.debug(
            "IDS detector state reset."
        )

    # =========================================================================
    # Accessors
    # =========================================================================

    def get_alerts(self):
        """
        Return all alerts generated during the current session.
        """

        return self.alerts.get_alerts()

    def alert_count(self) -> int:
        """
        Return the total number of generated IDS alerts.
        """

        return self.alerts.alert_count()

    def __len__(self) -> int:
        """
        Return the number of generated alerts.
        """

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