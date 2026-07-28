# =============================================================================
# File: ANTA-IDS/capture/interfaces.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Network interface discovery, normalization, and Scapy/Npcap mapping.
# =============================================================================

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any, List, Optional

import psutil
from scapy.all import conf

from utils.logger import Logger


logger = Logger.get_logger(__name__)


# =============================================================================
# Network Interface Model
# =============================================================================


@dataclass(slots=True)
class NetworkInterface:
    """
    Represents a network interface available to ANTA-IDS.

    Attributes
    ----------
    name:
        Operating-system friendly interface name.

    ipv4:
        Primary IPv4 address when available.

    ipv6:
        Primary IPv6 address when available.

    mac:
        Interface MAC address when available.

    scapy_name:
        Exact interface identifier passed to Scapy.

        On Windows with Npcap this will normally be:

            \\Device\\NPF_{GUID}

    description:
        Human-readable adapter description supplied by Scapy/Npcap.

    is_up:
        Whether the operating system reports the interface as active.
    """

    name: str

    ipv4: str = ""
    ipv6: str = ""
    mac: str = ""

    scapy_name: str = ""
    description: str = ""

    is_up: bool = False

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def capture_name(self) -> str:
        """
        Return the interface identifier that should be passed to Scapy.
        """

        return self.scapy_name or self.name

    @property
    def has_ip(self) -> bool:
        """
        Return True when the interface has an IPv4 or IPv6 address.
        """

        return bool(
            self.ipv4
            or self.ipv6
        )

    # =========================================================================
    # Representation
    # =========================================================================

    def __repr__(self) -> str:
        return (
            "NetworkInterface("
            f"name={self.name!r}, "
            f"ipv4={self.ipv4!r}, "
            f"mac={self.mac!r}, "
            f"scapy_name={self.scapy_name!r}, "
            f"is_up={self.is_up}"
            ")"
        )


# =============================================================================
# Interface Manager
# =============================================================================


class InterfaceManager:
    """
    Discovers operating-system network interfaces and maps them to
    Scapy/Npcap capture interfaces.

    Mapping priority:

        1. Exact friendly-name match
        2. IPv4-address match
        3. MAC-address match
        4. Description/name fallback

    The exact Scapy/Npcap identifier is retained whenever available.
    """

    def __init__(self) -> None:
        self._interfaces: List[NetworkInterface] = []

        self.refresh()

    # =========================================================================
    # Normalization Helpers
    # =========================================================================

    @staticmethod
    def _normalize_name(
        value: Optional[str],
    ) -> str:
        """
        Normalize interface names for comparison.
        """

        if not value:
            return ""

        return str(value).strip().casefold()

    @staticmethod
    def _normalize_mac(
        value: Optional[str],
    ) -> str:
        """
        Normalize MAC addresses into a comparison-safe representation.
        """

        if not value:
            return ""

        return (
            str(value)
            .strip()
            .lower()
            .replace("-", ":")
        )

    @staticmethod
    def _normalize_ipv6(
        value: Optional[str],
    ) -> str:
        """
        Remove an IPv6 scope identifier when present.

        Example:

            fe80::1234%13

        becomes:

            fe80::1234
        """

        if not value:
            return ""

        value = str(value).strip()

        return value.split(
            "%",
            1,
        )[0]

    # =========================================================================
    # Scapy Interface Discovery
    # =========================================================================

    @staticmethod
    def _get_scapy_interfaces() -> List[Any]:
        """
        Return Scapy's currently known interfaces.

        An empty list is returned if Scapy interface enumeration fails.
        """

        try:
            return list(
                conf.ifaces.values()
            )

        except Exception:
            logger.exception(
                "Failed to enumerate Scapy/Npcap interfaces."
            )

            return []

    # =========================================================================
    # Scapy Interface Mapping
    # =========================================================================

    @classmethod
    def _find_scapy_interface(
        cls,
        name: str,
        ipv4: str,
        mac: str,
        scapy_interfaces: Optional[List[Any]] = None,
    ) -> Optional[Any]:
        """
        Find the Scapy interface corresponding to an OS interface.

        Matching priority:

            1. Exact friendly name
            2. IPv4 address
            3. MAC address
            4. Description/name fallback
        """

        if scapy_interfaces is None:
            scapy_interfaces = cls._get_scapy_interfaces()

        normalized_name = cls._normalize_name(
            name
        )

        normalized_mac = cls._normalize_mac(
            mac
        )

        # ---------------------------------------------------------------------
        # 1. Exact Friendly-Name Match
        # ---------------------------------------------------------------------

        if normalized_name:

            for iface in scapy_interfaces:

                iface_name = cls._normalize_name(
                    getattr(
                        iface,
                        "name",
                        "",
                    )
                )

                if (
                    iface_name
                    and iface_name == normalized_name
                ):
                    return iface

        # ---------------------------------------------------------------------
        # 2. IPv4 Match
        # ---------------------------------------------------------------------

        if ipv4:

            for iface in scapy_interfaces:

                iface_ip = str(
                    getattr(
                        iface,
                        "ip",
                        "",
                    )
                    or ""
                ).strip()

                if iface_ip == ipv4:
                    return iface

        # ---------------------------------------------------------------------
        # 3. MAC Match
        # ---------------------------------------------------------------------

        if normalized_mac:

            for iface in scapy_interfaces:

                iface_mac = cls._normalize_mac(
                    getattr(
                        iface,
                        "mac",
                        "",
                    )
                )

                if (
                    iface_mac
                    and iface_mac == normalized_mac
                ):
                    return iface

        # ---------------------------------------------------------------------
        # 4. Conservative Name / Description Fallback
        # ---------------------------------------------------------------------

        if normalized_name:

            for iface in scapy_interfaces:

                iface_name = cls._normalize_name(
                    getattr(
                        iface,
                        "name",
                        "",
                    )
                )

                iface_description = cls._normalize_name(
                    getattr(
                        iface,
                        "description",
                        "",
                    )
                )

                if normalized_name in {
                    iface_name,
                    iface_description,
                }:
                    return iface

        return None

    # =========================================================================
    # Address Extraction
    # =========================================================================

    @classmethod
    def _extract_addresses(
        cls,
        addr_list,
    ) -> tuple[str, str, str]:
        """
        Extract IPv4, IPv6, and MAC addresses from psutil data.
        """

        ipv4 = ""
        ipv6 = ""
        mac = ""

        for address in addr_list:

            family = address.family

            # -----------------------------------------------------------------
            # IPv4
            # -----------------------------------------------------------------

            if family == socket.AF_INET:

                if not ipv4:
                    ipv4 = (
                        address.address
                        or ""
                    )

                continue

            # -----------------------------------------------------------------
            # IPv6
            # -----------------------------------------------------------------

            if family == socket.AF_INET6:

                candidate = cls._normalize_ipv6(
                    address.address
                )

                if not candidate:
                    continue

                # Prefer a non-link-local address where possible.
                if not ipv6:
                    ipv6 = candidate

                elif (
                    ipv6.lower().startswith("fe80:")
                    and not candidate.lower().startswith("fe80:")
                ):
                    ipv6 = candidate

                continue

            # -----------------------------------------------------------------
            # MAC
            # -----------------------------------------------------------------

            family_string = str(
                family
            )

            if (
                "AF_LINK" in family_string
                or "AF_PACKET" in family_string
            ):

                candidate_mac = (
                    address.address
                    or ""
                )

                if candidate_mac:
                    mac = candidate_mac

        return (
            ipv4,
            ipv6,
            mac,
        )

    # =========================================================================
    # Interface Discovery
    # =========================================================================

    def refresh(self) -> None:
        """
        Refresh the available network-interface list.
        """

        self._interfaces.clear()

        try:
            addresses = psutil.net_if_addrs()

        except Exception:
            logger.exception(
                "Failed to enumerate operating-system network interfaces."
            )

            return

        try:
            interface_stats = psutil.net_if_stats()

        except Exception:
            logger.exception(
                "Failed to retrieve network interface status."
            )

            interface_stats = {}

        # Enumerate Scapy interfaces only once.
        #
        # This is more efficient than repeatedly reading conf.ifaces
        # for every psutil interface.
        scapy_interfaces = self._get_scapy_interfaces()

        for name, addr_list in addresses.items():

            try:

                # -----------------------------------------------------------------
                # Extract OS Addresses
                # -----------------------------------------------------------------

                ipv4, ipv6, mac = self._extract_addresses(
                    addr_list
                )

                # -----------------------------------------------------------------
                # Interface Status
                # -----------------------------------------------------------------

                stats = interface_stats.get(
                    name
                )

                is_up = bool(
                    stats.isup
                    if stats is not None
                    else False
                )

                # -----------------------------------------------------------------
                # Find Scapy / Npcap Mapping
                # -----------------------------------------------------------------

                scapy_iface = self._find_scapy_interface(
                    name=name,
                    ipv4=ipv4,
                    mac=mac,
                    scapy_interfaces=scapy_interfaces,
                )

                scapy_name = name
                description = ""

                if scapy_iface is not None:

                    description = str(
                        getattr(
                            scapy_iface,
                            "description",
                            "",
                        )
                        or ""
                    ).strip()

                    # -------------------------------------------------------------
                    # Windows / Npcap
                    # -------------------------------------------------------------
                    #
                    # Prefer network_name because this gives the exact:
                    #
                    #     \Device\NPF_{GUID}
                    #
                    # identifier that fixed our Windows capture mapping.
                    # -------------------------------------------------------------

                    network_name = str(
                        getattr(
                            scapy_iface,
                            "network_name",
                            "",
                        )
                        or ""
                    ).strip()

                    iface_name = str(
                        getattr(
                            scapy_iface,
                            "name",
                            "",
                        )
                        or ""
                    ).strip()

                    if network_name:
                        scapy_name = network_name

                    elif iface_name:
                        scapy_name = iface_name

                else:

                    logger.warning(
                        "Could not map interface '%s' "
                        "to a Scapy/Npcap device.",
                        name,
                    )

                # -----------------------------------------------------------------
                # Create Interface Object
                # -----------------------------------------------------------------

                interface = NetworkInterface(
                    name=name,
                    ipv4=ipv4,
                    ipv6=ipv6,
                    mac=mac,
                    scapy_name=scapy_name,
                    description=description,
                    is_up=is_up,
                )

                self._interfaces.append(
                    interface
                )

                logger.debug(
                    "Interface mapping | "
                    "Name: %s | "
                    "IPv4: %s | "
                    "Scapy: %s | "
                    "Status: %s",
                    name,
                    ipv4 or "-",
                    scapy_name,
                    "UP" if is_up else "DOWN",
                )

            except Exception:

                # A single unusual adapter should not prevent ANTA-IDS
                # from discovering every other usable interface.
                logger.exception(
                    "Failed to process network interface '%s'.",
                    name,
                )

        logger.info(
            "Detected %d network interfaces.",
            len(self._interfaces),
        )

    # =========================================================================
    # Accessors
    # =========================================================================

    def get_all(
        self,
    ) -> List[NetworkInterface]:
        """
        Return a snapshot of all detected interfaces.
        """

        return list(
            self._interfaces
        )

    def get_interface(
        self,
        selection: int,
    ) -> Optional[NetworkInterface]:
        """
        Return an interface using a 1-based menu selection.
        """

        if selection <= 0:
            return None

        index = selection - 1

        if index >= len(
            self._interfaces
        ):
            return None

        return self._interfaces[index]

    def get_by_name(
        self,
        name: str,
    ) -> Optional[NetworkInterface]:
        """
        Find an interface using its operating-system friendly name.
        """

        normalized_name = self._normalize_name(
            name
        )

        if not normalized_name:
            return None

        for interface in self._interfaces:

            if (
                self._normalize_name(
                    interface.name
                )
                == normalized_name
            ):
                return interface

        return None

    def get_by_ipv4(
        self,
        ipv4: str,
    ) -> Optional[NetworkInterface]:
        """
        Find an interface using its IPv4 address.
        """

        if not ipv4:
            return None

        for interface in self._interfaces:

            if interface.ipv4 == ipv4:
                return interface

        return None

    def get_active(
        self,
    ) -> List[NetworkInterface]:
        """
        Return interfaces currently reported as active.
        """

        return [
            interface
            for interface in self._interfaces
            if interface.is_up
        ]

    # =========================================================================
    # Console Display
    # =========================================================================

    def display_interfaces(
        self,
    ) -> None:
        """
        Display available interfaces in the console.
        """

        print(
            "\n"
            + "=" * 70
        )

        print(
            "AVAILABLE NETWORK INTERFACES"
        )

        print(
            "=" * 70
        )

        if not self._interfaces:

            print(
                "No network interfaces detected."
            )

            print(
                "=" * 70
            )

            return

        for index, interface in enumerate(
            self._interfaces,
            start=1,
        ):

            status = (
                "UP"
                if interface.is_up
                else "DOWN"
            )

            print(
                f"[{index}] "
                f"{interface.name} "
                f"[{status}]"
            )

            if interface.description:

                print(
                    f"     Adapter : "
                    f"{interface.description}"
                )

            if interface.ipv4:

                print(
                    f"     IPv4    : "
                    f"{interface.ipv4}"
                )

            if interface.ipv6:

                print(
                    f"     IPv6    : "
                    f"{interface.ipv6}"
                )

            if interface.mac:

                print(
                    f"     MAC     : "
                    f"{interface.mac}"
                )

            print()

        print(
            "=" * 70
        )

    # =========================================================================
    # Utility
    # =========================================================================

    def __len__(
        self,
    ) -> int:
        return len(
            self._interfaces
        )

    def __repr__(
        self,
    ) -> str:
        return (
            "InterfaceManager("
            f"interfaces={len(self._interfaces)}, "
            f"active={len(self.get_active())}"
            ")"
        )