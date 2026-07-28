# =============================================================================
# File: ANTA-IDS/gui/console.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Console-based live packet and statistics display.
# =============================================================================

from __future__ import annotations

from capture.parser import PacketInfo


class ConsoleDisplay:
    """
    Console interface used while ANTA-IDS is running without
    the graphical desktop interface.
    """

    def __init__(self) -> None:
        self._packet_number = 0
        self._header_interval = 30

    # =========================================================================
    # Banner
    # =========================================================================

    @staticmethod
    def show_banner() -> None:
        """
        Display the ANTA-IDS console banner.
        """

        print()
        print("=" * 118)
        print("ANTA-IDS - Advanced Network Traffic Analyzer")
        print("=" * 118)

    # =========================================================================
    # Packet Table Header
    # =========================================================================

    @staticmethod
    def _show_packet_header() -> None:

        print(
            f"{'No':<6}"
            f"{'Time':<12}"
            f"{'Source IP':<18}"
            f"{'Destination IP':<18}"
            f"{'Proto':<10}"
            f"{'App':<12}"
            f"{'Length':<10}"
            f"Information"
        )

        print("-" * 118)

    # =========================================================================
    # Packet Display
    # =========================================================================

    def show_packet(
        self,
        packet: PacketInfo,
        analysis: dict,
    ) -> None:
        """
        Display one parsed packet.
        """

        self._packet_number += 1

        # Print header initially and every 30 packets.
        if (
            self._packet_number == 1
            or
            (self._packet_number - 1)
            % self._header_interval == 0
        ):
            self._show_packet_header()

        application = analysis.get(
            "application",
            packet.protocol,
        )

        source_ip = packet.src_ip or "-"
        destination_ip = packet.dst_ip or "-"

        protocol = packet.protocol or "OTHER"

        information = packet.summary or "-"

        print(
            f"{self._packet_number:<6}"
            f"{packet.timestamp:<12}"
            f"{source_ip:<18}"
            f"{destination_ip:<18}"
            f"{protocol:<10}"
            f"{application:<12}"
            f"{packet.packet_length:<10}"
            f"{information}"
        )

    # =========================================================================
    # Statistics Display
    # =========================================================================

    @staticmethod
    def show_statistics(statistics) -> None:
        """
        Display live network statistics.
        """

        stats = statistics.summary()

        print("\n" + "=" * 80)
        print("Live Statistics")
        print("=" * 80)

        print(
            f"Packets          : "
            f"{stats['packets']}"
        )

        print(
            f"Flows            : "
            f"{stats['flows']}"
        )

        print(
            f"Bytes            : "
            f"{stats['bytes']}"
        )

        print(
            f"Packets/sec      : "
            f"{stats['pps']}"
        )

        print(
            f"Bytes/sec        : "
            f"{stats['bps']:.2f}"
        )

        print(
            f"Average Size     : "
            f"{stats['avg_packet']} Bytes"
        )

        # ---------------------------------------------------------------------
        # Protocol Distribution
        # ---------------------------------------------------------------------

        print("\nProtocol Distribution")

        protocols = stats.get(
            "protocols",
            {},
        )

        if protocols:

            for protocol, count in protocols.items():

                print(
                    f"  {protocol:<10}: {count}"
                )

        else:

            print("  No protocol data.")

        # ---------------------------------------------------------------------
        # Top Source IP Addresses
        # ---------------------------------------------------------------------

        print("\nTop Source IPs")

        top_sources = stats.get(
            "top_source_ips",
            [],
        )

        if top_sources:

            for ip, count in top_sources:

                print(
                    f"  {ip:<18} {count}"
                )

        else:

            print("  No source IP data.")

        # ---------------------------------------------------------------------
        # Top Destination IP Addresses
        # ---------------------------------------------------------------------

        print("\nTop Destination IPs")

        top_destinations = stats.get(
            "top_destination_ips",
            [],
        )

        if top_destinations:

            for ip, count in top_destinations:

                print(
                    f"  {ip:<18} {count}"
                )

        else:

            print("  No destination IP data.")

        print("=" * 80 + "\n")

    # =========================================================================
    # Packet Counter
    # =========================================================================

    def packet_count(self) -> int:
        return self._packet_number

    def reset(self) -> None:
        self._packet_number = 0

    def __repr__(self) -> str:
        return (
            f"ConsoleDisplay("
            f"packets={self._packet_number}"
            f")"
        )