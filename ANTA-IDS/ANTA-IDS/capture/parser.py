# =============================================================================
# File: ANTA-IDS/capture/parser.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Converts raw Scapy packets into normalized PacketInfo objects, now 
#     including raw payload extraction for deep packet inspection.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from utils.logger import Logger
logger = Logger.get_logger(__name__)

@dataclass(slots=True)
class PacketInfo:
    timestamp: str = ""
    packet_length: int = 0
    protocol: str = "OTHER"
    summary: str = ""
    
    src_ip: str = ""
    dst_ip: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: str = ""
    
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    
    dns_query: str = ""
    dns_query_type: Optional[int] = None
    dns_is_response: bool = False
    dns_answer_count: int = 0
    
    arp_operation: Optional[int] = None
    
    is_ipv4: bool = False
    is_ipv6: bool = False
    is_tcp: bool = False
    is_udp: bool = False
    is_icmp: bool = False
    is_icmpv6: bool = False
    is_arp: bool = False
    is_dns: bool = False

    # NEW: Raw payload for deep inspection
    raw_payload: bytes = b""

    @property
    def has_ports(self) -> bool:
        return self.src_port is not None or self.dst_port is not None

    @property
    def is_ip(self) -> bool:
        return self.is_ipv4 or self.is_ipv6

    @property
    def is_broadcast(self) -> bool:
        return (
            self.dst_ip == "255.255.255.255"
            or self.dst_mac.lower() == "ff:ff:ff:ff:ff:ff"
            or str(self.dst_ip).lower().startswith("ff02:") # IPv6 Multicast support
        )

    @property
    def flow_tuple(self):
        return (self.protocol, self.src_ip, self.src_port, self.dst_ip, self.dst_port)

class PacketParser:
    def parse(self, packet: Packet) -> Optional[PacketInfo]:
        if packet is None:
            return None

        try:
            info = PacketInfo(
                timestamp=self._timestamp(),
                packet_length=self._packet_length(packet),
            )

            # Extract Payload
            if packet.haslayer(Raw):
                info.raw_payload = bytes(packet[Raw].load)

            self._parse_ethernet(packet, info)

            if packet.haslayer(ARP):
                self._parse_arp(packet, info)
                return info

            if packet.haslayer(IP):
                self._parse_ipv4(packet, info)
            elif packet.haslayer(IPv6):
                self._parse_ipv6(packet, info)
            else:
                return None

            if packet.haslayer(TCP):
                self._parse_tcp(packet, info)
            elif packet.haslayer(UDP):
                self._parse_udp(packet, info)
            elif packet.haslayer(ICMP):
                self._parse_icmp(packet, info)
            elif self._has_icmpv6(packet):
                self._parse_icmpv6(packet, info)
            else:
                self._parse_generic_ip(info)

            if packet.haslayer(DNS):
                self._parse_dns(packet, info)

            return info

        except Exception:
            logger.exception("Failed to parse captured packet.")
            return None

    @staticmethod
    def _timestamp() -> str:
        return datetime.now().strftime("%H:%M:%S")

    @staticmethod
    def _packet_length(packet: Packet) -> int:
        try:
            return len(packet)
        except Exception:
            return 0

    @staticmethod
    def _safe_int(value) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return None

    @staticmethod
    def _decode_dns_name(value) -> str:
        if value is None:
            return ""
        try:
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            else:
                value = str(value)
            return value.rstrip(".")
        except Exception:
            return ""

    @staticmethod
    def _parse_ethernet(packet: Packet, info: PacketInfo) -> None:
        if not packet.haslayer(Ether):
            return
        ethernet = packet[Ether]
        info.src_mac = str(getattr(ethernet, "src", "") or "")
        info.dst_mac = str(getattr(ethernet, "dst", "") or "")

    def _parse_arp(self, packet: Packet, info: PacketInfo) -> None:
        arp = packet[ARP]
        info.protocol = "ARP"
        info.is_arp = True
        info.src_ip = str(getattr(arp, "psrc", "") or "")
        info.dst_ip = str(getattr(arp, "pdst", "") or "")
        
        arp_src_mac = str(getattr(arp, "hwsrc", "") or "")
        arp_dst_mac = str(getattr(arp, "hwdst", "") or "")
        if arp_src_mac: info.src_mac = arp_src_mac
        if arp_dst_mac: info.dst_mac = arp_dst_mac
        
        info.arp_operation = self._safe_int(getattr(arp, "op", None))
        operation = "REQUEST" if info.arp_operation == 1 else "REPLY" if info.arp_operation == 2 else "UNKNOWN"
        info.summary = f"ARP {operation} {info.src_ip} -> {info.dst_ip}"

    @staticmethod
    def _parse_ipv4(packet: Packet, info: PacketInfo) -> None:
        ip = packet[IP]
        info.is_ipv4 = True
        info.src_ip = str(getattr(ip, "src", "") or "")
        info.dst_ip = str(getattr(ip, "dst", "") or "")

    @staticmethod
    def _parse_ipv6(packet: Packet, info: PacketInfo) -> None:
        ipv6 = packet[IPv6]
        info.is_ipv6 = True
        info.src_ip = str(getattr(ipv6, "src", "") or "")
        info.dst_ip = str(getattr(ipv6, "dst", "") or "")

    def _parse_tcp(self, packet: Packet, info: PacketInfo) -> None:
        tcp = packet[TCP]
        info.protocol = "TCP"
        info.is_tcp = True
        info.src_port = self._safe_int(getattr(tcp, "sport", None))
        info.dst_port = self._safe_int(getattr(tcp, "dport", None))
        try:
            info.tcp_flags = str(tcp.flags)
        except Exception:
            info.tcp_flags = ""
        info.summary = f"TCP {info.src_ip}:{info.src_port} -> {info.dst_ip}:{info.dst_port} [{info.tcp_flags}]"

    def _parse_udp(self, packet: Packet, info: PacketInfo) -> None:
        udp = packet[UDP]
        info.protocol = "UDP"
        info.is_udp = True
        info.src_port = self._safe_int(getattr(udp, "sport", None))
        info.dst_port = self._safe_int(getattr(udp, "dport", None))
        info.summary = f"UDP {info.src_ip}:{info.src_port} -> {info.dst_ip}:{info.dst_port}"

    def _parse_icmp(self, packet: Packet, info: PacketInfo) -> None:
        icmp = packet[ICMP]
        info.protocol = "ICMP"
        info.is_icmp = True
        info.icmp_type = self._safe_int(getattr(icmp, "type", None))
        info.icmp_code = self._safe_int(getattr(icmp, "code", None))
        info.summary = f"ICMP {info.src_ip} -> {info.dst_ip} type={info.icmp_type} code={info.icmp_code}"

    @staticmethod
    def _has_icmpv6(packet: Packet) -> bool:
        return (packet.haslayer(ICMPv6EchoRequest) or packet.haslayer(ICMPv6EchoReply) or 
                packet.haslayer(ICMPv6ND_NS) or packet.haslayer(ICMPv6ND_NA))

    def _parse_icmpv6(self, packet: Packet, info: PacketInfo) -> None:
        info.protocol = "ICMPv6"
        info.is_icmp = True
        info.is_icmpv6 = True
        icmpv6 = None
        for layer in (ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA):
            if packet.haslayer(layer):
                icmpv6 = packet[layer]
                break
        if icmpv6 is not None:
            info.icmp_type = self._safe_int(getattr(icmpv6, "type", None))
            info.icmp_code = self._safe_int(getattr(icmpv6, "code", None))
        info.summary = f"ICMPv6 {info.src_ip} -> {info.dst_ip}"

    @staticmethod
    def _parse_generic_ip(info: PacketInfo) -> None:
        info.protocol = "IPv6" if info.is_ipv6 else "IP" if info.is_ipv4 else "OTHER"
        info.summary = f"{info.protocol} {info.src_ip} -> {info.dst_ip}"

    def _parse_dns(self, packet: Packet, info: PacketInfo) -> None:
        dns = packet[DNS]
        info.is_dns = True
        try:
            info.dns_is_response = bool(int(getattr(dns, "qr", 0) or 0))
        except (TypeError, ValueError):
            info.dns_is_response = False
        
        info.dns_answer_count = self._safe_int(getattr(dns, "ancount", 0)) or 0
        if packet.haslayer(DNSQR):
            dns_query = packet[DNSQR]
            info.dns_query = self._decode_dns_name(getattr(dns_query, "qname", ""))
            info.dns_query_type = self._safe_int(getattr(dns_query, "qtype", None))
        
        if info.dns_query:
            direction = "response" if info.dns_is_response else "query"
            info.summary += f" DNS {direction} {info.dns_query}"