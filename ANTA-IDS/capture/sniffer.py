# =============================================================================
# File: ANTA-IDS/capture/sniffer.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     High-performance asynchronous packet capture engine using Scapy.
#
# Features:
#     - Scapy AsyncSniffer
#     - Windows/Npcap interface support
#     - Safe asynchronous start/stop
#     - Immediate duplicate-packet suppression
#     - Bounded packet fingerprint cache
#     - Capture statistics
#     - Callback exception isolation
#     - Configurable promiscuous mode
#     - Configurable packet limit
# =============================================================================

from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from threading import Lock
from typing import Callable, Optional

from scapy.all import AsyncSniffer
from scapy.packet import Packet

from capture.interfaces import NetworkInterface
from utils.logger import Logger

try:
    from config import (
        CAPTURE_PACKET_LIMIT,
        PROMISCUOUS_MODE,
    )
except ImportError:
    # Safe fallback if configuration is temporarily unavailable.
    CAPTURE_PACKET_LIMIT = None
    PROMISCUOUS_MODE = False


logger = Logger.get_logger(__name__)


# =============================================================================
# Packet Callback Type
# =============================================================================

PacketCallback = Callable[[Packet], None]


# =============================================================================
# Packet Sniffer
# =============================================================================


class PacketSniffer:
    """
    High-performance asynchronous packet capture engine for ANTA-IDS.

    Captured traffic follows this pipeline:

        Network Interface
              ↓
        Scapy / Npcap
              ↓
        AsyncSniffer
              ↓
        Duplicate Suppression
              ↓
        Packet Callback
              ↓
        PacketParser
              ↓
        Analyzer / IDS Pipeline

    The duplicate suppression layer is primarily useful on capture
    environments where identical frames may occasionally be delivered
    multiple times by the capture path.
    """

    # =========================================================================
    # Duplicate Detection Configuration
    # =========================================================================

    # Packets with exactly the same fingerprint observed inside this interval
    # are considered immediate capture duplicates.
    #
    # 10 milliseconds is intentionally small. It suppresses capture-level
    # duplicates while reducing the chance of hiding legitimate TCP
    # retransmissions.
    DUPLICATE_WINDOW_NS: int = 10_000_000

    # Maximum number of packet fingerprints retained in memory.
    MAX_FINGERPRINTS: int = 8192

    # Remove expired fingerprints periodically instead of scanning the cache
    # for every packet.
    CACHE_CLEANUP_INTERVAL: int = 512

    # BLAKE2b digest size.
    FINGERPRINT_SIZE: int = 16

    # =========================================================================
    # Initialization
    # =========================================================================

    def __init__(
        self,
        interface: NetworkInterface,
        packet_callback: Optional[PacketCallback] = None,
    ) -> None:
        """
        Initialize the packet capture engine.

        Parameters
        ----------
        interface:
            Network interface selected by InterfaceManager.

        packet_callback:
            Function that receives each accepted Scapy packet.
        """

        if interface is None:
            raise ValueError(
                "A valid NetworkInterface is required."
            )

        self.interface = interface
        self.packet_callback = packet_callback

        # ---------------------------------------------------------------------
        # Scapy Sniffer
        # ---------------------------------------------------------------------

        self._sniffer: Optional[AsyncSniffer] = None

        self.is_running: bool = False

        # ---------------------------------------------------------------------
        # Duplicate Cache
        # ---------------------------------------------------------------------
        #
        # fingerprint -> most recent monotonic timestamp
        # ---------------------------------------------------------------------

        self._recent_packets: OrderedDict[
            bytes,
            int,
        ] = OrderedDict()

        # Protect mutable capture state because Scapy's callback executes from
        # its capture thread.
        self._state_lock = Lock()

        # ---------------------------------------------------------------------
        # Capture Statistics
        # ---------------------------------------------------------------------

        self._raw_packets: int = 0
        self._forwarded_packets: int = 0
        self._duplicate_packets: int = 0
        self._callback_errors: int = 0
        self._fingerprint_errors: int = 0

        # ---------------------------------------------------------------------
        # Capture Timing
        # ---------------------------------------------------------------------

        self._capture_started_ns: Optional[int] = None
        self._capture_stopped_ns: Optional[int] = None

    # =========================================================================
    # Interface Resolution
    # =========================================================================

    def _get_capture_interface(self) -> str:
        """
        Return the exact interface identifier used by Scapy.

        On Windows this will normally be an Npcap identifier such as:

            \\Device\\NPF_{GUID}

        When an exact Scapy identifier is unavailable, the friendly interface
        name is used as a fallback.
        """

        scapy_name = getattr(
            self.interface,
            "scapy_name",
            "",
        )

        if scapy_name:
            return scapy_name

        if self.interface.name:
            return self.interface.name

        raise RuntimeError(
            "Selected network interface has no usable capture identifier."
        )

    # =========================================================================
    # Packet Serialization
    # =========================================================================

    @staticmethod
    def _packet_bytes(
        packet: Packet,
    ) -> bytes:
        """
        Return the raw serialized representation of a Scapy packet.
        """

        return bytes(packet)

    # =========================================================================
    # Packet Fingerprinting
    # =========================================================================

    def _fingerprint(
        self,
        packet: Packet,
    ) -> bytes:
        """
        Generate a compact fingerprint from the complete packet.

        Hashing the complete captured frame is safer than fingerprinting only
        addresses and ports because packets in the same network flow may have
        identical endpoint information while carrying different data.
        """

        raw_packet = self._packet_bytes(
            packet
        )

        return hashlib.blake2b(
            raw_packet,
            digest_size=self.FINGERPRINT_SIZE,
        ).digest()

    # =========================================================================
    # Duplicate Cache Cleanup
    # =========================================================================

    def _cleanup_cache(
        self,
        now_ns: int,
    ) -> None:
        """
        Remove expired fingerprints and enforce the cache size limit.

        OrderedDict keeps fingerprints ordered by their most recent
        observation, allowing efficient removal from the oldest side.
        """

        expiry_ns = (
            now_ns
            - self.DUPLICATE_WINDOW_NS
        )

        while self._recent_packets:

            _, timestamp_ns = next(
                iter(
                    self._recent_packets.items()
                )
            )

            if timestamp_ns > expiry_ns:
                break

            self._recent_packets.popitem(
                last=False
            )

        # Defensive memory bound.
        while (
            len(self._recent_packets)
            > self.MAX_FINGERPRINTS
        ):

            self._recent_packets.popitem(
                last=False
            )

    # =========================================================================
    # Duplicate Detection
    # =========================================================================

    def _is_duplicate(
        self,
        packet: Packet,
    ) -> bool:
        """
        Determine whether a packet is an immediate capture duplicate.

        Returns
        -------
        bool
            True when an identical packet was observed inside the configured
            duplicate window.
        """

        now_ns = time.monotonic_ns()

        try:

            fingerprint = self._fingerprint(
                packet
            )

        except Exception:

            with self._state_lock:
                self._fingerprint_errors += 1

            logger.exception(
                "Unable to fingerprint captured packet."
            )

            # Fingerprint failure must never cause legitimate traffic to be
            # silently discarded.
            return False

        with self._state_lock:

            previous_ns = self._recent_packets.get(
                fingerprint
            )

            # Periodically remove expired entries.
            if (
                self._raw_packets
                % self.CACHE_CLEANUP_INTERVAL
                == 0
            ):
                self._cleanup_cache(
                    now_ns
                )

            # -----------------------------------------------------------------
            # First Observation
            # -----------------------------------------------------------------

            if previous_ns is None:

                self._recent_packets[
                    fingerprint
                ] = now_ns

                if (
                    len(self._recent_packets)
                    > self.MAX_FINGERPRINTS
                ):

                    self._recent_packets.popitem(
                        last=False
                    )

                return False

            # -----------------------------------------------------------------
            # Existing Fingerprint
            # -----------------------------------------------------------------

            elapsed_ns = (
                now_ns
                - previous_ns
            )

            # Refresh observation timestamp.
            self._recent_packets[
                fingerprint
            ] = now_ns

            self._recent_packets.move_to_end(
                fingerprint
            )

            return (
                elapsed_ns
                <= self.DUPLICATE_WINDOW_NS
            )
    # =========================================================================
    # Packet Handler
    # =========================================================================

    def _handle_packet(
        self,
        packet: Packet,
    ) -> None:
        """
        Handle a raw packet received from Scapy.

        Processing flow:

            Scapy packet
                ↓
            Raw packet counter
                ↓
            Duplicate detection
                ↓
            Packet callback
                ↓
            ANTA-IDS processing pipeline

        Callback failures are isolated so one malformed or problematic packet
        does not terminate the capture engine.
        """

        if packet is None:
            return

        # ---------------------------------------------------------------------
        # Raw Packet Counter
        # ---------------------------------------------------------------------

        with self._state_lock:
            self._raw_packets += 1

        # ---------------------------------------------------------------------
        # Duplicate Suppression
        # ---------------------------------------------------------------------

        try:

            if self._is_duplicate(packet):

                with self._state_lock:
                    self._duplicate_packets += 1

                logger.debug(
                    "Duplicate packet suppressed."
                )

                return

        except Exception:

            # Duplicate detection itself should never stop packet capture.
            logger.exception(
                "Unexpected duplicate-detection failure."
            )

        # ---------------------------------------------------------------------
        # Callback Check
        # ---------------------------------------------------------------------

        callback = self.packet_callback

        if callback is None:

            logger.debug(
                "Captured packet discarded because no callback is configured."
            )

            return

        # ---------------------------------------------------------------------
        # Forward Packet
        # ---------------------------------------------------------------------

        try:

            callback(packet)

            with self._state_lock:
                self._forwarded_packets += 1

        except Exception:

            with self._state_lock:
                self._callback_errors += 1

            logger.exception(
                "Error while processing captured packet."
            )

    # =========================================================================
    # Session Reset
    # =========================================================================

    def _reset_session(self) -> None:
        """
        Reset all session-specific state before a new capture starts.

        This allows a PacketSniffer instance to be reused without statistics
        from a previous capture leaking into the next session.
        """

        with self._state_lock:

            self._recent_packets.clear()

            self._raw_packets = 0
            self._forwarded_packets = 0
            self._duplicate_packets = 0
            self._callback_errors = 0
            self._fingerprint_errors = 0

            self._capture_started_ns = None
            self._capture_stopped_ns = None

    # =========================================================================
    # Sniffer State
    # =========================================================================

    def _scapy_sniffer_running(self) -> bool:
        """
        Return the underlying AsyncSniffer running state when available.
        """

        sniffer = self._sniffer

        if sniffer is None:
            return False

        try:

            return bool(
                getattr(
                    sniffer,
                    "running",
                    False,
                )
            )

        except Exception:

            return False

    # =========================================================================
    # Start Capture
    # =========================================================================

    def start(self) -> bool:
        """
        Start asynchronous packet capture.

        Returns
        -------
        bool
            True when packet capture starts successfully.
            False when capture is already running or startup fails.
        """

        # ---------------------------------------------------------------------
        # Prevent Multiple Capture Sessions
        # ---------------------------------------------------------------------

        if self.is_running:

            logger.warning(
                "Packet capture is already running."
            )

            return False

        # ---------------------------------------------------------------------
        # Reset Previous Session
        # ---------------------------------------------------------------------

        self._reset_session()

        try:

            # -----------------------------------------------------------------
            # Resolve Interface
            # -----------------------------------------------------------------

            interface_name = (
                self._get_capture_interface()
            )

            logger.info(
                "Starting capture on '%s'",
                self.interface.name,
            )

            logger.info(
                "Using Scapy interface '%s'",
                interface_name,
            )

            # -----------------------------------------------------------------
            # AsyncSniffer Configuration
            # -----------------------------------------------------------------

            sniffer_options = {
                "iface": interface_name,
                "prn": self._handle_packet,
                "store": False,
                "promisc": PROMISCUOUS_MODE,
            }

            # CAPTURE_PACKET_LIMIT=None means unlimited capture.
            if (
                CAPTURE_PACKET_LIMIT
                is not None
            ):

                try:

                    packet_limit = int(
                        CAPTURE_PACKET_LIMIT
                    )

                    if packet_limit > 0:

                        sniffer_options[
                            "count"
                        ] = packet_limit

                except (
                    TypeError,
                    ValueError,
                ):

                    logger.warning(
                        "Invalid CAPTURE_PACKET_LIMIT value: %r. "
                        "Using unlimited capture.",
                        CAPTURE_PACKET_LIMIT,
                    )

            # -----------------------------------------------------------------
            # Create AsyncSniffer
            # -----------------------------------------------------------------

            self._sniffer = AsyncSniffer(
                **sniffer_options
            )

            # Set timing immediately before starting the capture thread.
            start_ns = time.monotonic_ns()

            self._sniffer.start()

            self._capture_started_ns = start_ns
            self._capture_stopped_ns = None

            self.is_running = True

            logger.info(
                "Packet capture started."
            )

            logger.debug(
                "Capture configuration | "
                "Interface: %s | "
                "Promiscuous: %s | "
                "Packet limit: %s",
                interface_name,
                PROMISCUOUS_MODE,
                (
                    CAPTURE_PACKET_LIMIT
                    if CAPTURE_PACKET_LIMIT is not None
                    else "unlimited"
                ),
            )

            return True

        except PermissionError:

            self.is_running = False
            self._sniffer = None
            self._capture_started_ns = None
            self._capture_stopped_ns = None

            logger.exception(
                "Permission denied while starting packet capture on '%s'. "
                "Try running the terminal as Administrator.",
                self.interface.name,
            )

            return False

        except Exception:

            self.is_running = False
            self._sniffer = None
            self._capture_started_ns = None
            self._capture_stopped_ns = None

            logger.exception(
                "Failed to start packet capture on '%s'.",
                self.interface.name,
            )

            return False

    # =========================================================================
    # Stop Capture
    # =========================================================================

    def stop(self) -> None:
        """
        Stop packet capture safely.

        This method is intentionally idempotent. Calling stop() when capture
        has already stopped will not raise an exception.
        """

        sniffer = self._sniffer

        # ---------------------------------------------------------------------
        # Already Stopped
        # ---------------------------------------------------------------------

        if (
            not self.is_running
            and sniffer is None
        ):
            return

        try:

            if sniffer is not None:

                # AsyncSniffer.stop() may raise when its capture thread has
                # already terminated, so check its state first.
                if self._scapy_sniffer_running():

                    sniffer.stop()

        except Exception:

            logger.exception(
                "Error while stopping packet capture."
            )

        finally:

            self._capture_stopped_ns = (
                time.monotonic_ns()
            )

            self.is_running = False
            self._sniffer = None

            logger.info(
                "Packet capture stopped."
            )

            self._log_capture_statistics()

            # Fingerprints are no longer required once the session ends.
            with self._state_lock:
                self._recent_packets.clear()

    # =========================================================================
    # Capture Statistics Logging
    # =========================================================================

    def _log_capture_statistics(
        self,
    ) -> None:
        """
        Write final capture statistics to the ANTA-IDS log.
        """

        statistics = self.get_statistics()

        logger.info(
            "Capture statistics | "
            "Raw: %d | "
            "Forwarded: %d | "
            "Duplicates suppressed: %d | "
            "Callback errors: %d | "
            "Fingerprint errors: %d | "
            "Duration: %.2fs",
            statistics["raw_packets"],
            statistics["forwarded_packets"],
            statistics["duplicates_suppressed"],
            statistics["callback_errors"],
            statistics["fingerprint_errors"],
            statistics["capture_duration"],
        )
        # =========================================================================
    # Capture Duration
    # =========================================================================

    @property
    def capture_duration(self) -> float:
        """
        Return capture-session duration in seconds.

        While capture is running, duration is measured from the start time
        until the current monotonic time.

        After capture stops, the final stop timestamp is used so the reported
        duration remains stable.
        """

        start_ns = self._capture_started_ns

        if start_ns is None:
            return 0.0

        if self._capture_stopped_ns is not None:
            end_ns = self._capture_stopped_ns
        else:
            end_ns = time.monotonic_ns()

        elapsed_ns = max(
            0,
            end_ns - start_ns,
        )

        return (
            elapsed_ns
            / 1_000_000_000
        )

    # =========================================================================
    # Capture Counters
    # =========================================================================

    @property
    def captured_packets(self) -> int:
        """
        Return the total number of raw packets received from Scapy.
        """

        with self._state_lock:
            return self._raw_packets

    @property
    def forwarded_packets(self) -> int:
        """
        Return the number of packets forwarded into the ANTA-IDS pipeline.
        """

        with self._state_lock:
            return self._forwarded_packets

    @property
    def duplicate_packets(self) -> int:
        """
        Return the number of immediate duplicate packets suppressed.
        """

        with self._state_lock:
            return self._duplicate_packets

    @property
    def callback_errors(self) -> int:
        """
        Return the number of packet-callback failures.
        """

        with self._state_lock:
            return self._callback_errors

    @property
    def fingerprint_errors(self) -> int:
        """
        Return the number of packet-fingerprinting failures.
        """

        with self._state_lock:
            return self._fingerprint_errors

    # =========================================================================
    # Derived Capture Statistics
    # =========================================================================

    @property
    def packets_per_second(self) -> float:
        """
        Return the raw packet capture rate.
        """

        duration = self.capture_duration

        if duration <= 0:
            return 0.0

        return (
            self.captured_packets
            / duration
        )

    @property
    def forwarded_packets_per_second(self) -> float:
        """
        Return the rate of packets forwarded into ANTA-IDS.
        """

        duration = self.capture_duration

        if duration <= 0:
            return 0.0

        return (
            self.forwarded_packets
            / duration
        )

    @property
    def duplicate_percentage(self) -> float:
        """
        Return the percentage of raw packets suppressed as duplicates.
        """

        raw_packets = self.captured_packets

        if raw_packets == 0:
            return 0.0

        return (
            self.duplicate_packets
            / raw_packets
        ) * 100.0

    # =========================================================================
    # Public Statistics
    # =========================================================================

    def get_statistics(self) -> dict:
        """
        Return a snapshot of packet-capture statistics.

        A new dictionary is returned on every call so callers cannot modify
        the PacketSniffer's internal counters.
        """

        with self._state_lock:

            raw_packets = self._raw_packets
            forwarded_packets = self._forwarded_packets
            duplicate_packets = self._duplicate_packets
            callback_errors = self._callback_errors
            fingerprint_errors = self._fingerprint_errors
            fingerprint_cache_size = len(
                self._recent_packets
            )

        duration = self.capture_duration

        if duration > 0:

            raw_pps = (
                raw_packets
                / duration
            )

            forwarded_pps = (
                forwarded_packets
                / duration
            )

        else:

            raw_pps = 0.0
            forwarded_pps = 0.0

        if raw_packets > 0:

            duplicate_percentage = (
                duplicate_packets
                / raw_packets
            ) * 100.0

        else:

            duplicate_percentage = 0.0

        return {
            "running": self.is_running,

            "interface": self.interface.name,

            "raw_packets": raw_packets,

            "forwarded_packets":
                forwarded_packets,

            "duplicates_suppressed":
                duplicate_packets,

            "duplicate_percentage":
                duplicate_percentage,

            "callback_errors":
                callback_errors,

            "fingerprint_errors":
                fingerprint_errors,

            "fingerprint_cache_size":
                fingerprint_cache_size,

            "capture_duration":
                duration,

            "raw_packets_per_second":
                raw_pps,

            "forwarded_packets_per_second":
                forwarded_pps,
        }

    # =========================================================================
    # Callback Management
    # =========================================================================

    def set_packet_callback(
        self,
        callback: Optional[PacketCallback],
    ) -> None:
        """
        Replace the packet callback.

        This allows future GUI or pipeline components to attach a different
        consumer without recreating the PacketSniffer instance.
        """

        self.packet_callback = callback

    # =========================================================================
    # Cache Information
    # =========================================================================

    @property
    def fingerprint_cache_size(self) -> int:
        """
        Return the current number of fingerprints stored in the duplicate
        detection cache.
        """

        with self._state_lock:
            return len(
                self._recent_packets
            )

    # =========================================================================
    # Context Manager Support
    # =========================================================================

    def __enter__(
        self,
    ) -> "PacketSniffer":
        """
        Allow PacketSniffer to be used as a context manager.

        Example:

            with PacketSniffer(interface, callback) as sniffer:
                ...
        """

        if not self.start():

            raise RuntimeError(
                "Unable to start packet capture."
            )

        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> bool:
        """
        Stop packet capture automatically when leaving a context.
        """

        self.stop()

        # Do not suppress exceptions raised inside the context.
        return False

    # =========================================================================
    # Representation
    # =========================================================================

    def __repr__(
        self,
    ) -> str:
        """
        Return a concise debugging representation.
        """

        return (
            "PacketSniffer("
            f"interface={self.interface.name!r}, "
            f"running={self.is_running}, "
            f"raw={self.captured_packets}, "
            f"forwarded={self.forwarded_packets}, "
            f"duplicates={self.duplicate_packets}, "
            f"callback_errors={self.callback_errors}"
            ")"
        )