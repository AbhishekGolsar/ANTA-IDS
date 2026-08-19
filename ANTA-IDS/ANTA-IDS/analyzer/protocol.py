# =============================================================================
# File: ANTA-IDS/analyzer/protocol.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Lightweight application-protocol identification using parsed packet
#     metadata and well-known TCP/UDP service ports.
# =============================================================================

from __future__ import annotations

from typing import Dict, Mapping, Optional

from capture.parser import PacketInfo


# =============================================================================
# Type Aliases
# =============================================================================

PortTable = Mapping[int, str]
AnalysisResult = Dict[str, str]


# =============================================================================
# Protocol Analyzer
# =============================================================================


class ProtocolAnalyzer:
    """
    Identifies common application protocols from PacketInfo metadata.

    Detection priority:

        1. Explicit packet metadata (ARP, ICMP, DNS)
        2. TCP service-port identification
        3. UDP service-port identification
        4. Transport/network protocol fallback

    This analyzer intentionally avoids deep payload inspection so that
    packet processing remains lightweight during live capture.
    """

    # =========================================================================
    # TCP Service Ports
    # =========================================================================

    TCP_PORTS: dict[int, str] = {
        # File transfer
        20: "FTP-DATA",
        21: "FTP",

        # Remote access
        22: "SSH",
        23: "TELNET",
        3389: "RDP",

        # Email
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        465: "SMTPS",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",

        # Name resolution
        53: "DNS",

        # Web
        80: "HTTP",
        443: "HTTPS",
        8000: "HTTP",
        8080: "HTTP",
        8443: "HTTPS",

        # Microsoft / Windows
        135: "MSRPC",
        139: "NETBIOS",
        445: "SMB",

        # Directory services
        389: "LDAP",
        636: "LDAPS",

        # Databases
        1433: "MSSQL",
        1521: "ORACLE",
        3306: "MYSQL",
        5432: "POSTGRESQL",
        6379: "REDIS",
        27017: "MONGODB",

        # Other common services
        1080: "SOCKS",
        3128: "HTTP-PROXY",
        5900: "VNC",
    }

    # =========================================================================
    # UDP Service Ports
    # =========================================================================

    UDP_PORTS: dict[int, str] = {
        # Name resolution
        53: "DNS",
        5353: "MDNS",

        # DHCP
        67: "DHCP",
        68: "DHCP",

        # File transfer
        69: "TFTP",

        # Time synchronization
        123: "NTP",

        # Windows / NetBIOS
        137: "NETBIOS-NS",
        138: "NETBIOS-DGM",

        # Network management
        161: "SNMP",
        162: "SNMP-TRAP",

        # VPN / IPsec
        500: "IKE",
        4500: "IPSEC-NAT-T",

        # Discovery
        1900: "SSDP",

        # Syslog
        514: "SYSLOG",

        # Directory services
        389: "LDAP",

        # Common real-time communication
        3478: "STUN",
        5349: "STUN-TLS",
    }

    # =========================================================================
    # Public Analysis API
    # =========================================================================

    def analyze(
        self,
        packet: PacketInfo,
    ) -> AnalysisResult:
        """
        Analyze a parsed packet and identify its likely application protocol.

        Parameters
        ----------
        packet:
            Parsed PacketInfo instance.

        Returns
        -------
        dict[str, str]
            Dictionary containing the network/transport protocol and
            identified application protocol.
        """

        protocol = self._normalize_protocol(
            packet.protocol
        )

        application = self._detect_application(
            packet
        )

        return {
            "protocol": protocol,
            "application": application,
        }

    # =========================================================================
    # Application Detection
    # =========================================================================

    def _detect_application(
        self,
        packet: PacketInfo,
    ) -> str:
        """
        Determine the most likely application protocol.
        """

        # ---------------------------------------------------------------------
        # Protocols Identified Directly by Parser Metadata
        # ---------------------------------------------------------------------

        if packet.is_arp:
            return "ARP"

        if packet.is_icmp:
            return "ICMP"

        # Prefer explicit DNS identification over generic port matching.
        if packet.is_dns:
            return "DNS"

        # ---------------------------------------------------------------------
        # TCP
        # ---------------------------------------------------------------------

        if packet.is_tcp:
            application = self._lookup_port(
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                port_table=self.TCP_PORTS,
            )

            if application is not None:
                return application

            return "TCP"

        # ---------------------------------------------------------------------
        # UDP
        # ---------------------------------------------------------------------

        if packet.is_udp:
            application = self._lookup_port(
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                port_table=self.UDP_PORTS,
            )

            if application is not None:
                return application

            return "UDP"

        # ---------------------------------------------------------------------
        # Fallback
        # ---------------------------------------------------------------------

        return self._normalize_protocol(
            packet.protocol
        )

    # =========================================================================
    # Port Lookup
    # =========================================================================

    @staticmethod
    def _lookup_port(
        src_port: Optional[int],
        dst_port: Optional[int],
        port_table: PortTable,
    ) -> Optional[str]:
        """
        Identify a service using source and destination ports.

        Destination port receives priority because it normally represents
        the service being contacted. Source-port matching handles response
        traffic travelling in the opposite direction.
        """

        if dst_port is not None:
            application = port_table.get(dst_port)

            if application is not None:
                return application

        if src_port is not None:
            application = port_table.get(src_port)

            if application is not None:
                return application

        return None

    # =========================================================================
    # Protocol Normalization
    # =========================================================================

    @staticmethod
    def _normalize_protocol(
        protocol: Optional[str],
    ) -> str:
        """
        Normalize protocol names returned by the parser.
        """

        if not protocol:
            return "OTHER"

        normalized = str(protocol).strip().upper()

        return normalized or "OTHER"

    # =========================================================================
    # Service Lookup
    # =========================================================================

    @classmethod
    def get_tcp_service(
        cls,
        port: Optional[int],
    ) -> Optional[str]:
        """
        Return the known TCP service for a port.
        """

        if port is None:
            return None

        return cls.TCP_PORTS.get(port)

    @classmethod
    def get_udp_service(
        cls,
        port: Optional[int],
    ) -> Optional[str]:
        """
        Return the known UDP service for a port.
        """

        if port is None:
            return None

        return cls.UDP_PORTS.get(port)

    # =========================================================================
    # Representation
    # =========================================================================

    def __repr__(self) -> str:
        return (
            "ProtocolAnalyzer("
            f"tcp_services={len(self.TCP_PORTS)}, "
            f"udp_services={len(self.UDP_PORTS)}"
            ")"
        )