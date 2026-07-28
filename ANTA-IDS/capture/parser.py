# =============================================================================
# File: ANTA-IDS/capture/parser.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Converts raw Scapy packets into normalized PacketInfo objects.
# =============================================================================

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6ND_NS,
    ICMPv6ND_NA,
)
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from utils.logger import Logger


logger = Logger.get_logger(__name__)


# =============================================================================
# Packet Information Model
# =============================================================================


@dataclass(slots=True)
class PacketInfo:
    """
    Normalized packet representation used throughout ANTA-IDS.

    The parser converts Scapy-specific packet structures into this common
    representation so analyzer and IDS modules do not need to work directly
    with Scapy packets.
    """

    # -------------------------------------------------------------------------
    # General Information
    # -------------------------------------------------------------------------

    timestamp: str = ""
    packet_length: int = 0

    protocol: str = "OTHER"
    summary: str = ""

    # -------------------------------------------------------------------------
    # Network Addresses
    # -------------------------------------------------------------------------

    src_ip: str = ""
    dst_ip: str = ""

    src_mac: str = ""
    dst_mac: str = ""

    # -------------------------------------------------------------------------
    # Transport Information
    # -------------------------------------------------------------------------

    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    tcp_flags: str = ""

    # -------------------------------------------------------------------------
    # ICMP
    # -------------------------------------------------------------------------

    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    # -------------------------------------------------------------------------
    # DNS
    # -------------------------------------------------------------------------

    dns_query: str = ""
    dns_query_type: Optional[int] = None

    dns_is_response: bool = False
    dns_answer_count: int = 0

    # -------------------------------------------------------------------------
    # ARP
    # -------------------------------------------------------------------------

    arp_operation: Optional[int] = None

    # -------------------------------------------------------------------------
    # Protocol Flags
    # -------------------------------------------------------------------------

    is_ipv4: bool = False
    is_ipv6: bool = False

    is_tcp: bool = False
    is_udp: bool = False

    is_icmp: bool = False
    is_icmpv6: bool = False

    is_arp: bool = False
    is_dns: bool = False

    # =========================================================================
    # Convenience Properties
    # =========================================================================

    @property
    def has_ports(self) -> bool:
        """
        Return True when transport-layer port information is available.
        """

        return (
            self.src_port is not None
            or self.dst_port is not None
        )

    @property
    def is_ip(self) -> bool:
        """
        Return True for IPv4 or IPv6 packets.
        """

        return self.is_ipv4 or self.is_ipv6

    @property
    def is_broadcast(self) -> bool:
        """
        Return True for common Ethernet or IPv4 broadcast traffic.
        """

        return (
            self.dst_ip == "255.255.255.255"
            or self.dst_mac.lower() == "ff:ff:ff:ff:ff:ff"
        )

    @property
    def flow_tuple(
        self,
    ) -> tuple[str, str, Optional[int], str, Optional[int]]:
        """
        Return a simple directional flow tuple.

        Useful for future database and flow-analysis modules.
        """

        return (
            self.protocol,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
        )

    # =========================================================================
    # Representation
    # =========================================================================

    def __repr__(self) -> str:

        source = self.src_ip or self.src_mac or "?"

        destination = self.dst_ip or self.dst_mac or "?"

        return (
            "PacketInfo("
            f"protocol={self.protocol!r}, "
            f"source={source!r}, "
            f"destination={destination!r}, "
            f"length={self.packet_length}"
            ")"
        )


# =============================================================================
# Packet Parser
# =============================================================================


class PacketParser:
    """
    Converts raw Scapy packets into normalized PacketInfo objects.

    Supported protocols include:

        Ethernet
        ARP
        IPv4
        IPv6
        TCP
        UDP
        ICMP
        ICMPv6
        DNS
    """

    # =========================================================================
    # Public Parser
    # =========================================================================

    def parse(
        self,
        packet: Packet,
    ) -> Optional[PacketInfo]:
        """
        Parse a raw Scapy packet.

        Returns
        -------
        PacketInfo | None
            Parsed packet information, or None when the packet is unsupported
            or parsing fails.
        """

        if packet is None:
            return None

        try:

            info = PacketInfo(
                timestamp=self._timestamp(),
                packet_length=self._packet_length(packet),
            )

            # -----------------------------------------------------------------
            # Ethernet
            # -----------------------------------------------------------------

            self._parse_ethernet(
                packet,
                info,
            )

            # -----------------------------------------------------------------
            # ARP
            # -----------------------------------------------------------------
            #
            # ARP is handled separately because it does not contain an IP
            # transport layer.
            # -----------------------------------------------------------------

            if packet.haslayer(ARP):

                self._parse_arp(
                    packet,
                    info,
                )

                return info

            # -----------------------------------------------------------------
            # Network Layer
            # -----------------------------------------------------------------

            if packet.haslayer(IP):

                self._parse_ipv4(
                    packet,
                    info,
                )

            elif packet.haslayer(IPv6):

                self._parse_ipv6(
                    packet,
                    info,
                )

            else:

                # Ethernet frames that currently have no value to our
                # analyzer/IDS pipeline are ignored.
                return None

            # -----------------------------------------------------------------
            # Transport / Control Layer
            # -----------------------------------------------------------------

            if packet.haslayer(TCP):

                self._parse_tcp(
                    packet,
                    info,
                )

            elif packet.haslayer(UDP):

                self._parse_udp(
                    packet,
                    info,
                )

            elif packet.haslayer(ICMP):

                self._parse_icmp(
                    packet,
                    info,
                )

            elif self._has_icmpv6(packet):

                self._parse_icmpv6(
                    packet,
                    info,
                )

            else:

                self._parse_generic_ip(
                    info
                )

            # -----------------------------------------------------------------
            # Application Layer
            # -----------------------------------------------------------------

            if packet.haslayer(DNS):

                self._parse_dns(
                    packet,
                    info,
                )

            return info

        except Exception:

            logger.exception(
                "Failed to parse captured packet."
            )

            return None

    # =========================================================================
    # General Helpers
    # =========================================================================

    @staticmethod
    def _timestamp() -> str:
        """
        Generate the packet processing timestamp.
        """

        return datetime.now().strftime(
            "%H:%M:%S"
        )

    @staticmethod
    def _packet_length(
        packet: Packet,
    ) -> int:
        """
        Safely determine packet length.
        """

        try:
            return len(packet)

        except Exception:
            return 0

    @staticmethod
    def _safe_int(
        value,
    ) -> Optional[int]:
        """
        Safely convert a Scapy field into an integer.
        """

        if value is None:
            return None

        try:
            return int(value)

        except (
            TypeError,
            ValueError,
            OverflowError,
        ):
            return None

    @staticmethod
    def _decode_dns_name(
        value,
    ) -> str:
        """
        Convert a Scapy DNS name into a normalized string.
        """

        if value is None:
            return ""

        try:

            if isinstance(
                value,
                bytes,
            ):

                value = value.decode(
                    "utf-8",
                    errors="replace",
                )

            else:

                value = str(
                    value
                )

            return value.rstrip(
                "."
            )

        except Exception:

            return ""

    # =========================================================================
    # Ethernet
    # =========================================================================

    @staticmethod
    def _parse_ethernet(
        packet: Packet,
        info: PacketInfo,
    ) -> None:
        """
        Extract Ethernet source and destination MAC addresses.
        """

        if not packet.haslayer(Ether):
            return

        ethernet = packet[Ether]

        info.src_mac = str(
            getattr(
                ethernet,
                "src",
                "",
            )
            or ""
        )

        info.dst_mac = str(
            getattr(
                ethernet,
                "dst",
                "",
            )
            or ""
        )

    # =========================================================================
    # ARP
    # =========================================================================

    def _parse_arp(
        self,
        packet: Packet,
        info: PacketInfo,
    ) -> None:
        """
        Parse an ARP packet.
        """

        arp = packet[ARP]

        info.protocol = "ARP"
        info.is_arp = True

        info.src_ip = str(
            getattr(
                arp,
                "psrc",
                "",
            )
            or ""
        )

        info.dst_ip = str(
            getattr(
                arp,
                "pdst",
                "",
            )
            or ""
        )

        arp_src_mac = str(
            getattr(
                arp,
                "hwsrc",
                "",
            )
            or ""
        )

        arp_dst_mac = str(
            getattr(
                arp,
                "hwdst",
                "",
            )
            or ""
        )

        if arp_src_mac:
            info.src_mac = arp_src_mac

        if arp_dst_mac:
            info.dst_mac = arp_dst_mac

        info.arp_operation = self._safe_int(
            getattr(
                arp,
                "op",
                None,
            )
        )

        operation = self._arp_operation_name(
            info.arp_operation
        )

        info.summary = (
            f"ARP {operation} "
            f"{info.src_ip} -> {info.dst_ip}"
        )

    @staticmethod
    def _arp_operation_name(
        operation: Optional[int],
    ) -> str:
        """
        Convert an ARP operation number into a readable value.
        """

        if operation == 1:
            return "REQUEST"

        if operation == 2:
            return "REPLY"

        if operation is None:
            return "UNKNOWN"

        return f"OP={operation}"

    # =========================================================================
    # IPv4
    # =========================================================================

    @staticmethod
    def _parse_ipv4(
        packet: Packet,
        info: PacketInfo,
    ) -> None:
        """
        Parse IPv4 source and destination addresses.
        """

        ip = packet[IP]

        info.is_ipv4 = True

        info.src_ip = str(
            getattr(
                ip,
                "src",
                "",
            )
            or ""
        )

        info.dst_ip = str(
            getattr(
                ip,
                "dst",
                "",
            )
            or ""
        )

    # =========================================================================
    # IPv6
    # =========================================================================

    @staticmethod
    def _parse_ipv6(
        packet: Packet,
        info: PacketInfo,
    ) -> None:
        """
        Parse IPv6 source and destination addresses.
        """

        ipv6 = packet[IPv6]

        info.is_ipv6 = True

        info.src_ip = str(
            getattr(
                ipv6,
                "src",
                "",
            )
            or ""
        )

        info.dst_ip = str(
            getattr(
                ipv6,
                "dst",
                "",
            )
            or ""
        )

    # =========================================================================
    # TCP
    # =========================================================================

    def _parse_tcp(
        self,
        packet: Packet,
        info: PacketInfo,
    ) -> None:
        """
        Parse TCP metadata.
        """

        tcp = packet[TCP]

        info.protocol = "TCP"
        info.is_tcp = True

        info.src_port = self._safe_int(
            getattr(
                tcp,
                "sport",
                None,
            )
        )

        info.dst_port = self._safe_int(
            getattr(
                tcp,
                "dport",
                None,
            )
        )

        try:

            info.tcp_flags = str(
                tcp.flags
            )

        except Exception:

            info.tcp_flags = ""

        info.summary = (
            f"TCP "
            f"{self._format_endpoint(info.src_ip, info.src_port)} "
            f"-> "
            f"{self._format_endpoint(info.dst_ip, info.dst_port)}"
        )

        if info.tcp_flags:

            info.summary += (
                f" [{info.tcp_flags}]"
            )

    # =========================================================================
    # UDP
    # =========================================================================

    def _parse_udp(
        self,
        packet: Packet,
        info: PacketInfo,
    ) -> None:
        """
        Parse UDP metadata.
        """

        udp = packet[UDP]

        info.protocol = "UDP"
        info.is_udp = True

        info.src_port = self._safe_int(
            getattr(
                udp,
                "sport",
                None,
            )
        )

        info.dst_port = self._safe_int(
            getattr(
                udp,
                "dport",
                None,
            )
        )

        info.summary = (
            f"UDP "
            f"{self._format_endpoint(info.src_ip, info.src_port)} "
            f"-> "
            f"{self._format_endpoint(info.dst_ip, info.dst_port)}"
        )

    # =========================================================================
    # ICMP
    # =========================================================================

    def _parse_icmp(
        self,
        packet: Packet,
        info: PacketInfo,
    ) -> None:
        """
        Parse IPv4 ICMP metadata.
        """

        icmp = packet[ICMP]

        info.protocol = "ICMP"
        info.is_icmp = True

        info.icmp_type = self._safe_int(
            getattr(
                icmp,
                "type",
                None,
            )
        )

        info.icmp_code = self._safe_int(
            getattr(
                icmp,
                "code",
                None,
            )
        )

        info.summary = (
            f"ICMP "
            f"{info.src_ip} -> {info.dst_ip} "
            f"type={info.icmp_type} "
            f"code={info.icmp_code}"
        )

    # =========================================================================
    # ICMPv6
    # =========================================================================

    @staticmethod
    def _has_icmpv6(
        packet: Packet,
    ) -> bool:
        """
        Return True when a supported ICMPv6 layer exists.
        """

        return (
            packet.haslayer(ICMPv6EchoRequest)
            or packet.haslayer(ICMPv6EchoReply)
            or packet.haslayer(ICMPv6ND_NS)
            or packet.haslayer(ICMPv6ND_NA)
        )

    def _parse_icmpv6(
        self,
        packet: Packet,
        info: PacketInfo,
    ) -> None:
        """
        Parse common ICMPv6 messages.
        """

        info.protocol = "ICMPv6"
        info.is_icmp = True
        info.is_icmpv6 = True

        icmpv6 = None

        for layer in (
            ICMPv6EchoRequest,
            ICMPv6EchoReply,
            ICMPv6ND_NS,
            ICMPv6ND_NA,
        ):

            if packet.haslayer(layer):

                icmpv6 = packet[layer]
                break

        if icmpv6 is not None:

            info.icmp_type = self._safe_int(
                getattr(
                    icmpv6,
                    "type",
                    None,
                )
            )

            info.icmp_code = self._safe_int(
                getattr(
                    icmpv6,
                    "code",
                    None,
                )
            )

        info.summary = (
            f"ICMPv6 "
            f"{info.src_ip} -> {info.dst_ip}"
        )

        if info.icmp_type is not None:

            info.summary += (
                f" type={info.icmp_type}"
            )

        if info.icmp_code is not None:

            info.summary += (
                f" code={info.icmp_code}"
            )

    # =========================================================================
    # Generic IP
    # =========================================================================

    @staticmethod
    def _parse_generic_ip(
        info: PacketInfo,
    ) -> None:
        """
        Handle IP packets without a supported transport/control layer.
        """

        if info.is_ipv6:
            info.protocol = "IPv6"

        elif info.is_ipv4:
            info.protocol = "IP"

        else:
            info.protocol = "OTHER"

        info.summary = (
            f"{info.protocol} "
            f"{info.src_ip} -> {info.dst_ip}"
        )

    # =========================================================================
    # DNS
    # =========================================================================

    def _parse_dns(
        self,
        packet: Packet,
        info: PacketInfo,
    ) -> None:
        """
        Parse DNS query/response metadata.

        DNS does not replace TCP/UDP as the transport protocol.
        Instead, is_dns identifies the application protocol.
        """

        dns = packet[DNS]

        info.is_dns = True

        # ---------------------------------------------------------------------
        # Query / Response
        # ---------------------------------------------------------------------

        try:

            info.dns_is_response = bool(
                int(
                    getattr(
                        dns,
                        "qr",
                        0,
                    )
                    or 0
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            info.dns_is_response = False

        # ---------------------------------------------------------------------
        # Answer Count
        # ---------------------------------------------------------------------

        answer_count = self._safe_int(
            getattr(
                dns,
                "ancount",
                0,
            )
        )

        info.dns_answer_count = (
            answer_count
            if answer_count is not None
            else 0
        )

        # ---------------------------------------------------------------------
        # DNS Question
        # ---------------------------------------------------------------------

        if packet.haslayer(DNSQR):

            dns_query = packet[DNSQR]

            info.dns_query = self._decode_dns_name(
                getattr(
                    dns_query,
                    "qname",
                    "",
                )
            )

            info.dns_query_type = self._safe_int(
                getattr(
                    dns_query,
                    "qtype",
                    None,
                )
            )

        # ---------------------------------------------------------------------
        # Improve Summary
        # ---------------------------------------------------------------------

        if info.dns_query:

            dns_direction = (
                "response"
                if info.dns_is_response
                else "query"
            )

            info.summary += (
                f" DNS {dns_direction} "
                f"{info.dns_query}"
            )

    # =========================================================================
    # Endpoint Formatting
    # =========================================================================

    @staticmethod
    def _format_endpoint(
        ip_address: str,
        port: Optional[int],
    ) -> str:
        """
        Format an IPv4/IPv6 endpoint unambiguously.

        IPv4:
            192.168.1.10:443

        IPv6:
            [2001:db8::1]:443
        """

        address = (
            ip_address
            if ip_address
            else "?"
        )

        if ":" in address:

            address = (
                f"[{address}]"
            )

        if port is None:
            return address

        return (
            f"{address}:{port}"
        )

    # =========================================================================
    # Representation
    # =========================================================================

    def __repr__(
        self,
    ) -> str:
        return "PacketParser()"