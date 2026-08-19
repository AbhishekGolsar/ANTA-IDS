# =============================================================================
# File: ANTA-IDS/analyzer/statistics.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Real-time network traffic statistics and traffic-rate monitoring.
# =============================================================================

from __future__ import annotations

import time
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple, TypeAlias

from capture.parser import PacketInfo


# =============================================================================
# Type Definitions
# =============================================================================

Endpoint: TypeAlias = Tuple[str, Optional[int]]
FlowKey: TypeAlias = Tuple[str, Endpoint, Endpoint]
TopIPList: TypeAlias = List[Tuple[str, int]]


# =============================================================================
# Statistics Manager
# =============================================================================


class StatisticsManager:
    """
    Maintains real-time statistics for parsed network traffic.

    Statistics include:

        - Total packets
        - Total bytes
        - Unique bidirectional flows
        - Protocol distribution
        - Source IP distribution
        - Destination IP distribution
        - Packets per second
        - Bytes per second
        - Average packet size
    """

    def __init__(self) -> None:
        self._start_time: float = time.monotonic()

        self._packet_count: int = 0
        self._byte_count: int = 0

        self._protocols: Counter[str] = Counter()

        self._source_ips: Counter[str] = Counter()
        self._destination_ips: Counter[str] = Counter()

        self._flows: Set[FlowKey] = set()

    # =========================================================================
    # Update
    # =========================================================================

    def update(
        self,
        packet: PacketInfo,
    ) -> None:
        """
        Update statistics using a parsed packet.
        """

        # ---------------------------------------------------------------------
        # Packet Counters
        # ---------------------------------------------------------------------

        self._packet_count += 1

        packet_length = max(
            0,
            int(packet.packet_length or 0),
        )

        self._byte_count += packet_length

        # ---------------------------------------------------------------------
        # Protocol Distribution
        # ---------------------------------------------------------------------

        protocol = self._normalize_protocol(
            packet.protocol
        )

        self._protocols[protocol] += 1

        # ---------------------------------------------------------------------
        # IP Statistics
        # ---------------------------------------------------------------------

        if packet.src_ip:
            self._source_ips[packet.src_ip] += 1

        if packet.dst_ip:
            self._destination_ips[packet.dst_ip] += 1

        # ---------------------------------------------------------------------
        # Bidirectional Flow Statistics
        # ---------------------------------------------------------------------

        if packet.src_ip and packet.dst_ip:
            flow_key = self._create_flow_key(
                packet
            )

            self._flows.add(flow_key)

    # =========================================================================
    # Protocol Normalization
    # =========================================================================

    @staticmethod
    def _normalize_protocol(
        protocol: Optional[str],
    ) -> str:
        """
        Normalize protocol names for consistent statistics.
        """

        if not protocol:
            return "OTHER"

        normalized = str(protocol).strip().upper()

        return normalized or "OTHER"

    # =========================================================================
    # Flow Key Helpers
    # =========================================================================

    @staticmethod
    def _endpoint_sort_key(
        endpoint: Endpoint,
    ) -> Tuple[str, int]:
        """
        Create a deterministic comparison key for an endpoint.

        None ports are represented as -1 only for sorting purposes.
        """

        ip, port = endpoint

        normalized_port = (
            port
            if port is not None
            else -1
        )

        return (
            ip,
            normalized_port,
        )

    @classmethod
    def _create_flow_key(
        cls,
        packet: PacketInfo,
    ) -> FlowKey:
        """
        Create a canonical bidirectional flow key.

        A -> B and B -> A are counted as the same flow.
        """

        endpoint_a: Endpoint = (
            packet.src_ip or "",
            packet.src_port,
        )

        endpoint_b: Endpoint = (
            packet.dst_ip or "",
            packet.dst_port,
        )

        if (
            cls._endpoint_sort_key(endpoint_a)
            <= cls._endpoint_sort_key(endpoint_b)
        ):
            first = endpoint_a
            second = endpoint_b

        else:
            first = endpoint_b
            second = endpoint_a

        protocol = cls._normalize_protocol(
            packet.protocol
        )

        return (
            protocol,
            first,
            second,
        )

    # =========================================================================
    # Basic Counters
    # =========================================================================

    def packet_count(self) -> int:
        """
        Return total number of processed packets.
        """

        return self._packet_count

    def byte_count(self) -> int:
        """
        Return total number of processed bytes.
        """

        return self._byte_count

    def flow_count(self) -> int:
        """
        Return number of unique bidirectional flows.
        """

        return len(self._flows)

    # =========================================================================
    # Runtime
    # =========================================================================

    def elapsed_time(self) -> float:
        """
        Return elapsed monitoring time in seconds.
        """

        elapsed = (
            time.monotonic()
            - self._start_time
        )

        return max(
            elapsed,
            0.000001,
        )

    # =========================================================================
    # Traffic Rates
    # =========================================================================

    def packets_per_second(self) -> float:
        """
        Return average packets processed per second.
        """

        return (
            self._packet_count
            / self.elapsed_time()
        )

    def bytes_per_second(self) -> float:
        """
        Return average bytes processed per second.
        """

        return (
            self._byte_count
            / self.elapsed_time()
        )

    def bits_per_second(self) -> float:
        """
        Return average traffic rate in bits per second.
        """

        return (
            self.bytes_per_second()
            * 8
        )

    def average_packet_size(self) -> float:
        """
        Return average packet size in bytes.
        """

        if self._packet_count == 0:
            return 0.0

        return (
            self._byte_count
            / self._packet_count
        )

    # =========================================================================
    # Protocol Distribution
    # =========================================================================

    def protocol_distribution(
        self,
    ) -> Dict[str, int]:
        """
        Return packet counts grouped by protocol.
        """

        return dict(
            self._protocols
        )

    def protocol_count(
        self,
        protocol: str,
    ) -> int:
        """
        Return packet count for a specific protocol.
        """

        normalized = self._normalize_protocol(
            protocol
        )

        return self._protocols.get(
            normalized,
            0,
        )

    # =========================================================================
    # Source / Destination Statistics
    # =========================================================================

    def top_source_ips(
        self,
        limit: int = 5,
    ) -> TopIPList:
        """
        Return the most active source IP addresses.
        """

        if limit <= 0:
            return []

        return self._source_ips.most_common(
            limit
        )

    def top_destination_ips(
        self,
        limit: int = 5,
    ) -> TopIPList:
        """
        Return the most active destination IP addresses.
        """

        if limit <= 0:
            return []

        return self._destination_ips.most_common(
            limit
        )

    def source_ip_count(
        self,
        ip_address: str,
    ) -> int:
        """
        Return packet count for a source IP.
        """

        return self._source_ips.get(
            ip_address,
            0,
        )

    def destination_ip_count(
        self,
        ip_address: str,
    ) -> int:
        """
        Return packet count for a destination IP.
        """

        return self._destination_ips.get(
            ip_address,
            0,
        )

    # =========================================================================
    # Summary
    # =========================================================================

    def summary(self) -> dict:
        """
        Return a snapshot of statistics used by ConsoleDisplay
        and future GUI/dashboard components.

        Existing keys are preserved for compatibility.
        """

        elapsed = self.elapsed_time()

        pps = (
            self._packet_count
            / elapsed
        )

        bps = (
            self._byte_count
            / elapsed
        )

        avg_packet = (
            self._byte_count / self._packet_count
            if self._packet_count
            else 0.0
        )

        return {
            # Existing ConsoleDisplay keys
            "packets": self._packet_count,
            "flows": len(self._flows),
            "bytes": self._byte_count,

            "pps": round(
                pps,
                2,
            ),

            "bps": bps,

            "avg_packet": round(
                avg_packet,
                2,
            ),

            "protocols": dict(
                self._protocols
            ),

            "top_source_ips":
                self._source_ips.most_common(5),

            "top_destination_ips":
                self._destination_ips.most_common(5),

            # Additional metrics for future dashboard use
            "elapsed_time": round(
                elapsed,
                2,
            ),

            "bits_per_second": (
                bps * 8
            ),
        }

    # =========================================================================
    # Reset
    # =========================================================================

    def reset(self) -> None:
        """
        Reset all collected statistics and restart the monitoring timer.
        """

        self._start_time = time.monotonic()

        self._packet_count = 0
        self._byte_count = 0

        self._protocols.clear()

        self._source_ips.clear()
        self._destination_ips.clear()

        self._flows.clear()

    # =========================================================================
    # Representation
    # =========================================================================

    def __len__(self) -> int:
        """
        Return number of processed packets.
        """

        return self._packet_count

    def __repr__(self) -> str:
        return (
            "StatisticsManager("
            f"packets={self._packet_count}, "
            f"bytes={self._byte_count}, "
            f"flows={len(self._flows)}, "
            f"pps={self.packets_per_second():.2f}"
            ")"
        )