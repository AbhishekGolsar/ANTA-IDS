# =============================================================================
# File: ANTA-IDS/analyzer/flow.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Efficient bidirectional network flow tracking and management.
# =============================================================================

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, TypeAlias

from capture.parser import PacketInfo
from utils.logger import Logger


logger = Logger.get_logger(__name__)


# =============================================================================
# Type Definitions
# =============================================================================

Endpoint: TypeAlias = Tuple[str, Optional[int]]
FlowKey: TypeAlias = Tuple[str, Endpoint, Endpoint]


# =============================================================================
# Flow
# =============================================================================


@dataclass(slots=True)
class Flow:
    """
    Represents a bidirectional network flow.

    A flow contains traffic exchanged between two endpoints using
    the same network/transport protocol.

    The source and destination fields represent the direction of
    the first packet that created the flow.
    """

    src_ip: str
    dst_ip: str

    src_port: Optional[int]
    dst_port: Optional[int]

    protocol: str

    packet_count: int = 0
    byte_count: int = 0

    first_seen: float = 0.0
    last_seen: float = 0.0

    # Directional statistics
    forward_packets: int = 0
    reverse_packets: int = 0

    forward_bytes: int = 0
    reverse_bytes: int = 0

    # =========================================================================
    # Update
    # =========================================================================

    def update(
        self,
        packet: PacketInfo,
        timestamp: Optional[float] = None,
    ) -> None:
        """
        Update this flow using information from a packet.
        """

        current_time = (
            timestamp
            if timestamp is not None
            else time.time()
        )

        packet_length = max(
            0,
            int(packet.packet_length or 0),
        )

        # ---------------------------------------------------------------------
        # Timing
        # ---------------------------------------------------------------------

        if self.packet_count == 0:
            self.first_seen = current_time

        self.last_seen = current_time

        # ---------------------------------------------------------------------
        # Global Counters
        # ---------------------------------------------------------------------

        self.packet_count += 1
        self.byte_count += packet_length

        # ---------------------------------------------------------------------
        # Directional Counters
        # ---------------------------------------------------------------------

        if self._is_forward_packet(packet):
            self.forward_packets += 1
            self.forward_bytes += packet_length

        else:
            self.reverse_packets += 1
            self.reverse_bytes += packet_length

    # =========================================================================
    # Direction Detection
    # =========================================================================

    def _is_forward_packet(
        self,
        packet: PacketInfo,
    ) -> bool:
        """
        Return True when the packet travels in the same direction
        as the packet that originally created the flow.
        """

        return (
            packet.src_ip == self.src_ip
            and packet.dst_ip == self.dst_ip
            and packet.src_port == self.src_port
            and packet.dst_port == self.dst_port
        )

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def duration(self) -> float:
        """
        Return flow duration in seconds.
        """

        if self.packet_count == 0:
            return 0.0

        return max(
            0.0,
            self.last_seen - self.first_seen,
        )

    @property
    def packets_per_second(self) -> float:
        """
        Return the average packet rate for this flow.
        """

        duration = self.duration

        if duration <= 0.0:
            return 0.0

        return self.packet_count / duration

    @property
    def bytes_per_second(self) -> float:
        """
        Return the average byte rate for this flow.
        """

        duration = self.duration

        if duration <= 0.0:
            return 0.0

        return self.byte_count / duration

    @property
    def average_packet_size(self) -> float:
        """
        Return the average packet size in bytes.
        """

        if self.packet_count == 0:
            return 0.0

        return self.byte_count / self.packet_count

    # =========================================================================
    # Representation
    # =========================================================================

    def __repr__(self) -> str:
        return (
            "Flow("
            f"{self.src_ip}:{self.src_port} "
            "<-> "
            f"{self.dst_ip}:{self.dst_port}, "
            f"protocol={self.protocol!r}, "
            f"packets={self.packet_count}, "
            f"bytes={self.byte_count}, "
            f"duration={self.duration:.2f}s"
            ")"
        )


# =============================================================================
# Flow Manager
# =============================================================================


class FlowManager:
    """
    Tracks bidirectional network flows observed by ANTA-IDS.

    Reverse traffic is automatically mapped into the same flow.

    Example:

        10.0.0.1:50000 -> 8.8.8.8:443

    and:

        8.8.8.8:443 -> 10.0.0.1:50000

    are treated as one flow.
    """

    def __init__(self) -> None:
        self._flows: Dict[FlowKey, Flow] = {}

    # =========================================================================
    # Endpoint Normalization
    # =========================================================================

    @staticmethod
    def _endpoint_sort_key(
        endpoint: Endpoint,
    ) -> Tuple[str, int]:
        """
        Produce a deterministic sortable representation of an endpoint.

        Ports that are None are represented internally as -1 only for
        comparison purposes.
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

    # =========================================================================
    # Flow Key
    # =========================================================================

    @classmethod
    def _create_flow_key(
        cls,
        packet: PacketInfo,
    ) -> FlowKey:
        """
        Create a canonical bidirectional flow key.

        Both directions of the same conversation generate exactly
        the same key.
        """

        protocol = (
            packet.protocol
            or "UNKNOWN"
        ).upper()

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

        return (
            protocol,
            first,
            second,
        )

    # =========================================================================
    # Add Packet
    # =========================================================================

    def add_packet(
        self,
        packet: PacketInfo,
    ) -> Optional[Flow]:
        """
        Add a packet to its corresponding bidirectional flow.

        Returns the updated Flow instance, or None when the packet
        does not contain sufficient addressing information.
        """

        if not packet.src_ip or not packet.dst_ip:
            return None

        key = self._create_flow_key(packet)

        flow = self._flows.get(key)

        if flow is None:
            flow = Flow(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=(
                    packet.protocol
                    or "UNKNOWN"
                ).upper(),
            )

            self._flows[key] = flow

        flow.update(packet)

        return flow

    # =========================================================================
    # Flow Lookup
    # =========================================================================

    def get_flow(
        self,
        packet: PacketInfo,
    ) -> Optional[Flow]:
        """
        Return the flow associated with a packet without modifying it.
        """

        if not packet.src_ip or not packet.dst_ip:
            return None

        key = self._create_flow_key(packet)

        return self._flows.get(key)

    # =========================================================================
    # Accessors
    # =========================================================================

    def get_flows(self) -> List[Flow]:
        """
        Return a snapshot of all currently tracked flows.
        """

        return list(self._flows.values())

    def flow_count(self) -> int:
        """
        Return the number of currently tracked flows.
        """

        return len(self._flows)

    # =========================================================================
    # Flow Cleanup
    # =========================================================================

    def remove_expired_flows(
        self,
        max_idle_seconds: float,
        current_time: Optional[float] = None,
    ) -> int:
        """
        Remove flows that have been inactive longer than the specified
        timeout.

        Returns the number of flows removed.
        """

        if max_idle_seconds < 0:
            raise ValueError(
                "max_idle_seconds cannot be negative."
            )

        now = (
            current_time
            if current_time is not None
            else time.time()
        )

        expired_keys = [
            key
            for key, flow in self._flows.items()
            if (
                flow.last_seen > 0.0
                and now - flow.last_seen > max_idle_seconds
            )
        ]

        for key in expired_keys:
            del self._flows[key]

        removed_count = len(expired_keys)

        if removed_count:
            logger.debug(
                "Removed %d expired network flow(s).",
                removed_count,
            )

        return removed_count

    # =========================================================================
    # Clear
    # =========================================================================

    def clear(self) -> None:
        """
        Remove all tracked flows.
        """

        flow_count = len(self._flows)

        self._flows.clear()

        logger.info(
            "Flow table cleared. Removed %d flow(s).",
            flow_count,
        )

    # =========================================================================
    # Representation
    # =========================================================================

    def __len__(self) -> int:
        return self.flow_count()

    def __repr__(self) -> str:
        return (
            "FlowManager("
            f"flows={self.flow_count()}"
            ")"
        )