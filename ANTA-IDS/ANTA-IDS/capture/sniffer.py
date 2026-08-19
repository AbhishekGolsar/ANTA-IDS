# =============================================================================
# File: ANTA-IDS/capture/sniffer.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     High-performance asynchronous packet capture engine using Scapy.
#     Optimized with counter batching to eliminate lock contention.
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
    from config import CAPTURE_PACKET_LIMIT, PROMISCUOUS_MODE
except ImportError:
    CAPTURE_PACKET_LIMIT = None
    PROMISCUOUS_MODE = False

logger = Logger.get_logger(__name__)
PacketCallback = Callable[[Packet], None]

class PacketSniffer:
    DUPLICATE_WINDOW_NS: int = 10_000_000
    MAX_FINGERPRINTS: int = 8192
    CACHE_CLEANUP_INTERVAL: int = 512
    FINGERPRINT_SIZE: int = 16
    BATCH_LIMIT: int = 100  # Sync counters every 100 packets

    def __init__(self, interface: NetworkInterface, packet_callback: Optional[PacketCallback] = None) -> None:
        if interface is None: raise ValueError("A valid NetworkInterface is required.")
        self.interface = interface
        self.packet_callback = packet_callback
        self._sniffer: Optional[AsyncSniffer] = None
        self.is_running: bool = False
        
        self._recent_packets: OrderedDict[bytes, int] = OrderedDict()
        self._state_lock = Lock()

        # Global Counters
        self._raw_packets: int = 0
        self._forwarded_packets: int = 0
        self._duplicate_packets: int = 0
        self._callback_errors: int = 0
        self._fingerprint_errors: int = 0
        
        # Thread-Local Batched Counters
        self._local_raw: int = 0
        self._local_fwd: int = 0
        self._local_dup: int = 0
        self._local_err: int = 0

        self._capture_started_ns: Optional[int] = None
        self._capture_stopped_ns: Optional[int] = None

    def _get_capture_interface(self) -> str:
        scapy_name = getattr(self.interface, "scapy_name", "")
        if scapy_name: return scapy_name
        if self.interface.name: return self.interface.name
        raise RuntimeError("Selected network interface has no usable capture identifier.")

    @staticmethod
    def _packet_bytes(packet: Packet) -> bytes:
        return bytes(packet)

    def _fingerprint(self, packet: Packet) -> bytes:
        raw_packet = self._packet_bytes(packet)
        return hashlib.blake2b(raw_packet, digest_size=self.FINGERPRINT_SIZE).digest()

    def _cleanup_cache(self, now_ns: int) -> None:
        expiry_ns = now_ns - self.DUPLICATE_WINDOW_NS
        while self._recent_packets:
            _, timestamp_ns = next(iter(self._recent_packets.items()))
            if timestamp_ns > expiry_ns: break
            self._recent_packets.popitem(last=False)
        while len(self._recent_packets) > self.MAX_FINGERPRINTS:
            self._recent_packets.popitem(last=False)

    def _is_duplicate(self, packet: Packet) -> bool:
        now_ns = time.monotonic_ns()
        try:
            fingerprint = self._fingerprint(packet)
        except Exception:
            self._local_err += 1
            return False

        with self._state_lock:
            previous_ns = self._recent_packets.get(fingerprint)
            if self._raw_packets % self.CACHE_CLEANUP_INTERVAL == 0:
                self._cleanup_cache(now_ns)
            
            if previous_ns is None:
                self._recent_packets[fingerprint] = now_ns
                if len(self._recent_packets) > self.MAX_FINGERPRINTS:
                    self._recent_packets.popitem(last=False)
                return False

            elapsed_ns = now_ns - previous_ns
            self._recent_packets[fingerprint] = now_ns
            self._recent_packets.move_to_end(fingerprint)
            return elapsed_ns <= self.DUPLICATE_WINDOW_NS

    def _flush_counters(self) -> None:
        """Merge thread-local counters into the thread-safe global state."""
        with self._state_lock:
            self._raw_packets += self._local_raw
            self._forwarded_packets += self._local_fwd
            self._duplicate_packets += self._local_dup
            self._callback_errors += self._local_err
        
        self._local_raw = 0
        self._local_fwd = 0
        self._local_dup = 0
        self._local_err = 0

    def _handle_packet(self, packet: Packet) -> None:
        if packet is None: return
        self._local_raw += 1

        try:
            if self._is_duplicate(packet):
                self._local_dup += 1
                self._check_batch()
                return
        except Exception:
            pass

        callback = self.packet_callback
        if callback is None: return

        try:
            callback(packet)
            self._local_fwd += 1
        except Exception:
            self._local_err += 1
            logger.exception("Error while processing captured packet.")

        self._check_batch()

    def _check_batch(self):
        if self._local_raw >= self.BATCH_LIMIT:
            self._flush_counters()

    def _reset_session(self) -> None:
        self._flush_counters() # clear lingering locals
        with self._state_lock:
            self._recent_packets.clear()
            self._raw_packets = self._forwarded_packets = self._duplicate_packets = 0
            self._callback_errors = self._fingerprint_errors = 0
            self._capture_started_ns = self._capture_stopped_ns = None

    def _scapy_sniffer_running(self) -> bool:
        if self._sniffer is None: return False
        try: return bool(getattr(self._sniffer, "running", False))
        except Exception: return False

    def start(self) -> bool:
        if self.is_running: return False
        self._reset_session()
        try:
            interface_name = self._get_capture_interface()
            sniffer_options = {
                "iface": interface_name,
                "prn": self._handle_packet,
                "store": False,
                "promisc": PROMISCUOUS_MODE,
            }
            if CAPTURE_PACKET_LIMIT is not None:
                try: sniffer_options["count"] = int(CAPTURE_PACKET_LIMIT)
                except Exception: pass

            self._sniffer = AsyncSniffer(**sniffer_options)
            self._capture_started_ns = time.monotonic_ns()
            self._sniffer.start()
            self.is_running = True
            return True
        except Exception:
            self.is_running = False
            return False

    def stop(self) -> None:
        if not self.is_running and self._sniffer is None: return
        try:
            if self._sniffer is not None and self._scapy_sniffer_running():
                self._sniffer.stop()
        except Exception:
            pass
        finally:
            self._capture_stopped_ns = time.monotonic_ns()
            self._flush_counters() # Final merge of batched metrics
            self.is_running = False
            self._sniffer = None
            with self._state_lock:
                self._recent_packets.clear()

    @property
    def capture_duration(self) -> float:
        start_ns = self._capture_started_ns
        if start_ns is None: return 0.0
        end_ns = self._capture_stopped_ns if self._capture_stopped_ns is not None else time.monotonic_ns()
        return max(0, end_ns - start_ns) / 1_000_000_000

    @property
    def captured_packets(self) -> int:
        with self._state_lock: return self._raw_packets + self._local_raw

    @property
    def forwarded_packets(self) -> int:
        with self._state_lock: return self._forwarded_packets + self._local_fwd

    @property
    def duplicate_packets(self) -> int:
        with self._state_lock: return self._duplicate_packets + self._local_dup

    def get_statistics(self) -> dict:
        self._flush_counters()
        with self._state_lock:
            r = self._raw_packets
            f = self._forwarded_packets
            d = self._duplicate_packets
            e = self._callback_errors
        
        dur = self.capture_duration
        return {
            "running": self.is_running,
            "raw_packets": r,
            "forwarded_packets": f,
            "duplicates_suppressed": d,
            "callback_errors": e,
            "capture_duration": dur,
            "raw_packets_per_second": r / dur if dur > 0 else 0,
        }