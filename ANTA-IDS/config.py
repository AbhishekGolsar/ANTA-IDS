# =============================================================================
# File: ANTA-IDS/config.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Central application configuration for ANTA-IDS.
#
#     Contains:
#       - Application metadata
#       - Project paths
#       - Logging configuration
#       - Packet capture configuration
#       - Console configuration
#       - IDS global configuration
#
#     Individual IDS detection thresholds belong in:
#         ids/rules.py
# =============================================================================

from __future__ import annotations

import logging
from pathlib import Path
from typing import Final


# =============================================================================
# Application Metadata
# =============================================================================

APP_NAME: Final[str] = (
    "Advanced Network Traffic Analyzer & Intrusion Detection System"
)

APP_SHORT_NAME: Final[str] = "ANTA-IDS"

APP_VERSION: Final[str] = "1.0.0"


# =============================================================================
# Project Directories
# =============================================================================

BASE_DIR: Final[Path] = Path(__file__).resolve().parent

LOGS_DIR: Final[Path] = BASE_DIR / "logs"
CAPTURES_DIR: Final[Path] = BASE_DIR / "captures"
REPORTS_DIR: Final[Path] = BASE_DIR / "reports"
ASSETS_DIR: Final[Path] = BASE_DIR / "assets"
DOCS_DIR: Final[Path] = BASE_DIR / "docs"


# =============================================================================
# Runtime Files
# =============================================================================

LOG_FILE: Final[Path] = LOGS_DIR / "anta_ids.log"

ALERT_LOG_FILE: Final[Path] = LOGS_DIR / "alerts.log"


# =============================================================================
# Required Directories
# =============================================================================

REQUIRED_DIRECTORIES: Final[tuple[Path, ...]] = (
    LOGS_DIR,
    CAPTURES_DIR,
    REPORTS_DIR,
    ASSETS_DIR,
    DOCS_DIR,
)


def ensure_directories() -> None:
    """
    Ensure all required ANTA-IDS directories exist.

    The operation is safe to run multiple times.
    """

    for directory in REQUIRED_DIRECTORIES:
        directory.mkdir(
            parents=True,
            exist_ok=True,
        )


# Create required directories during application initialization/import.
ensure_directories()


# =============================================================================
# Logging Configuration
# =============================================================================

LOG_LEVEL: Final[int] = logging.INFO

LOG_FILE_FORMAT: Final[str] = (
    "[%(asctime)s] "
    "[%(levelname)s] "
    "[%(name)s] "
    "%(message)s"
)

LOG_DATE_FORMAT: Final[str] = "%H:%M:%S"

# Enable logging to console.
LOG_TO_CONSOLE: Final[bool] = True

# Enable persistent log files.
LOG_TO_FILE: Final[bool] = True

# File encoding used by log handlers.
LOG_ENCODING: Final[str] = "utf-8"

# Maximum size of one log file before rotation.
LOG_MAX_BYTES: Final[int] = 5 * 1024 * 1024  # 5 MB

# Number of rotated log files retained.
LOG_BACKUP_COUNT: Final[int] = 5


# =============================================================================
# Packet Capture Configuration
# =============================================================================

# None = unlimited packet capture.
CAPTURE_PACKET_LIMIT: Final[int | None] = None

# Capture packets visible to the selected interface without forcing
# promiscuous mode.
PROMISCUOUS_MODE: Final[bool] = False

# Do not keep raw Scapy packets in memory after processing.
STORE_PACKETS: Final[bool] = False

# Optional BPF capture filter.
#
# None:
#     Capture all traffic visible to the selected interface.
#
# Example:
#     "ip or ip6 or arp"
#
CAPTURE_FILTER: Final[str | None] = None

# Main-thread sleep interval while AsyncSniffer performs capture.
# Prevents a CPU-intensive busy loop.
MAIN_LOOP_SLEEP: Final[float] = 0.1


# =============================================================================
# Packet Processing Configuration
# =============================================================================

# Ignore packets that the parser cannot interpret.
DROP_UNPARSED_PACKETS: Final[bool] = True

# Maximum reasonable packet size used by higher-level validation.
MAX_PACKET_SIZE: Final[int] = 65_535


# =============================================================================
# Duplicate Packet Suppression
# =============================================================================

# Enable duplicate suppression inside the packet capture layer.
#
# Useful on Windows/Npcap where the same packet may occasionally be
# delivered more than once depending on the interface/capture path.
DUPLICATE_SUPPRESSION_ENABLED: Final[bool] = True

# Amount of time in seconds that identical packet fingerprints are
# considered duplicates.
#
# Keep this small so legitimate repeated packets are not discarded.
DUPLICATE_WINDOW: Final[float] = 0.05

# Periodically remove expired fingerprints from the duplicate cache.
DUPLICATE_CACHE_CLEANUP_INTERVAL: Final[float] = 5.0


# =============================================================================
# Console Configuration
# =============================================================================

# Display detailed statistics after this many processed packets.
STATISTICS_DISPLAY_INTERVAL: Final[int] = 50

# Display individual captured packets.
SHOW_PACKET_OUTPUT: Final[bool] = True

# Display IDS alerts.
SHOW_SECURITY_ALERTS: Final[bool] = True

# Display periodic traffic statistics.
SHOW_STATISTICS: Final[bool] = True

# Development/debug packet information.
DEBUG_PACKET_PIPELINE: Final[bool] = False


# =============================================================================
# Console Table Configuration
# =============================================================================

# IPv4 addresses fit easily in 15 characters, while IPv6 addresses may
# require up to 39 characters. These widths prevent IPv6 columns from
# colliding in console output.
CONSOLE_NUMBER_WIDTH: Final[int] = 6
CONSOLE_TIME_WIDTH: Final[int] = 10

CONSOLE_IP_WIDTH: Final[int] = 40

CONSOLE_PROTOCOL_WIDTH: Final[int] = 10
CONSOLE_APPLICATION_WIDTH: Final[int] = 12
CONSOLE_LENGTH_WIDTH: Final[int] = 10


# =============================================================================
# IDS Global Configuration
# =============================================================================

# Master IDS switch.
IDS_ENABLED: Final[bool] = True

# Enable alert cooldown handling to prevent alert spam.
IDS_ALERT_COOLDOWN_ENABLED: Final[bool] = True

# Keep detector state bounded by periodically removing expired entries.
IDS_STATE_CLEANUP_ENABLED: Final[bool] = True

# Interval between detector-state cleanup operations.
IDS_STATE_CLEANUP_INTERVAL: Final[float] = 30.0


# =============================================================================
# Alert Configuration
# =============================================================================

# Persist IDS alerts to the logging system.
ALERT_LOGGING_ENABLED: Final[bool] = True

# Supported severity names.
SEVERITY_INFO: Final[str] = "INFO"
SEVERITY_LOW: Final[str] = "LOW"
SEVERITY_MEDIUM: Final[str] = "MEDIUM"
SEVERITY_HIGH: Final[str] = "HIGH"
SEVERITY_CRITICAL: Final[str] = "CRITICAL"

VALID_SEVERITIES: Final[frozenset[str]] = frozenset(
    {
        SEVERITY_INFO,
        SEVERITY_LOW,
        SEVERITY_MEDIUM,
        SEVERITY_HIGH,
        SEVERITY_CRITICAL,
    }
)


# =============================================================================
# Development / Testing
# =============================================================================

DEBUG_MODE: Final[bool] = False

# Optional IP whose traffic can be highlighted while testing the IDS.
# None disables target-specific debugging.
DEBUG_TARGET_IP: Final[str | None] = None


# =============================================================================
# Configuration Validation
# =============================================================================


def validate_config() -> None:
    """
    Validate critical ANTA-IDS configuration values.

    Raises
    ------
    ValueError
        If a configuration value is invalid.
    """

    if STATISTICS_DISPLAY_INTERVAL <= 0:
        raise ValueError(
            "STATISTICS_DISPLAY_INTERVAL must be greater than 0."
        )

    if MAIN_LOOP_SLEEP <= 0:
        raise ValueError(
            "MAIN_LOOP_SLEEP must be greater than 0."
        )

    if DUPLICATE_WINDOW < 0:
        raise ValueError(
            "DUPLICATE_WINDOW cannot be negative."
        )

    if DUPLICATE_CACHE_CLEANUP_INTERVAL <= 0:
        raise ValueError(
            "DUPLICATE_CACHE_CLEANUP_INTERVAL must be greater than 0."
        )

    if IDS_STATE_CLEANUP_INTERVAL <= 0:
        raise ValueError(
            "IDS_STATE_CLEANUP_INTERVAL must be greater than 0."
        )

    if LOG_MAX_BYTES <= 0:
        raise ValueError(
            "LOG_MAX_BYTES must be greater than 0."
        )

    if LOG_BACKUP_COUNT < 0:
        raise ValueError(
            "LOG_BACKUP_COUNT cannot be negative."
        )

    if MAX_PACKET_SIZE <= 0:
        raise ValueError(
            "MAX_PACKET_SIZE must be greater than 0."
        )

    if CONSOLE_IP_WIDTH < 39:
        raise ValueError(
            "CONSOLE_IP_WIDTH must be at least 39 for IPv6 addresses."
        )


validate_config()