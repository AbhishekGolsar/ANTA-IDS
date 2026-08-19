# =============================================================================
# File: ANTA-IDS/config.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Central application configuration for ANTA-IDS.
#
#     Contains:
#       - Application metadata
#       - Project paths & Database location
#       - Logging configuration
#       - Packet capture configuration
#       - Console & GUI configuration
#       - IDS global configuration
#
#     Individual IDS detection thresholds belong in:
#         ids/rules.json (Dynamically loaded by ids/rules.py)
# =============================================================================

from __future__ import annotations

import logging
import sys
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
# Project Directories (PyInstaller Safe)
# =============================================================================

def get_app_dir() -> Path:
    """
    Returns the absolute path to the directory where the application is running.
    Crucial for PyInstaller compatibility to prevent saving databases in ephemeral 
    _MEIPASS temporary directories.
    """
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    else:
        return Path(__file__).resolve().parent

BASE_DIR: Final[Path] = get_app_dir()

LOGS_DIR: Final[Path] = BASE_DIR / "logs"
CAPTURES_DIR: Final[Path] = BASE_DIR / "captures"
REPORTS_DIR: Final[Path] = BASE_DIR / "reports"
ASSETS_DIR: Final[Path] = BASE_DIR / "assets"
DOCS_DIR: Final[Path] = BASE_DIR / "docs"
DATABASE_DIR: Final[Path] = BASE_DIR / "database"  # Updated to match your request


# =============================================================================
# Runtime Files
# =============================================================================

LOG_FILE: Final[Path] = LOGS_DIR / "anta_ids.log"
ALERT_LOG_FILE: Final[Path] = LOGS_DIR / "alerts.log"

DATABASE_FILE: Final[Path] = DATABASE_DIR / "anta_ids_data.db"
DYNAMIC_RULES_FILE: Final[Path] = BASE_DIR / "ids" / "rules.json"


# =============================================================================
# Required Directories
# =============================================================================

REQUIRED_DIRECTORIES: Final[tuple[Path, ...]] = (
    LOGS_DIR,
    CAPTURES_DIR,
    REPORTS_DIR,
    ASSETS_DIR,
    DOCS_DIR,
    DATABASE_DIR,
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

LOG_TO_CONSOLE: Final[bool] = True
LOG_TO_FILE: Final[bool] = True
LOG_ENCODING: Final[str] = "utf-8"
LOG_MAX_BYTES: Final[int] = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT: Final[int] = 5


# =============================================================================
# Packet Capture Configuration
# =============================================================================

CAPTURE_PACKET_LIMIT: Final[int | None] = None
PROMISCUOUS_MODE: Final[bool] = False
STORE_PACKETS: Final[bool] = False
CAPTURE_FILTER: Final[str | None] = None
MAIN_LOOP_SLEEP: Final[float] = 0.1


# =============================================================================
# Packet Processing Configuration
# =============================================================================

DROP_UNPARSED_PACKETS: Final[bool] = True
MAX_PACKET_SIZE: Final[int] = 65_535


# =============================================================================
# Duplicate Packet Suppression
# =============================================================================

DUPLICATE_SUPPRESSION_ENABLED: Final[bool] = True
DUPLICATE_WINDOW: Final[float] = 0.05
DUPLICATE_CACHE_CLEANUP_INTERVAL: Final[float] = 5.0


# =============================================================================
# Console Configuration
# =============================================================================

STATISTICS_DISPLAY_INTERVAL: Final[int] = 50
SHOW_PACKET_OUTPUT: Final[bool] = True
SHOW_SECURITY_ALERTS: Final[bool] = True
SHOW_STATISTICS: Final[bool] = True
DEBUG_PACKET_PIPELINE: Final[bool] = False


# =============================================================================
# GUI Configuration (PySide6)
# =============================================================================

GUI_REFRESH_RATE_MS: Final[int] = 1000
GUI_MAX_TABLE_ROWS: Final[int] = 10_000


# =============================================================================
# Console Table Configuration
# =============================================================================

CONSOLE_NUMBER_WIDTH: Final[int] = 6
CONSOLE_TIME_WIDTH: Final[int] = 10
CONSOLE_IP_WIDTH: Final[int] = 40
CONSOLE_PROTOCOL_WIDTH: Final[int] = 10
CONSOLE_APPLICATION_WIDTH: Final[int] = 12
CONSOLE_LENGTH_WIDTH: Final[int] = 10


# =============================================================================
# IDS Global Configuration
# =============================================================================

IDS_ENABLED: Final[bool] = True
IDS_ALERT_COOLDOWN_ENABLED: Final[bool] = True
IDS_STATE_CLEANUP_ENABLED: Final[bool] = True
IDS_STATE_CLEANUP_INTERVAL: Final[float] = 30.0


# =============================================================================
# Alert Configuration
# =============================================================================

ALERT_LOGGING_ENABLED: Final[bool] = True
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
DEBUG_TARGET_IP: Final[str | None] = None


# =============================================================================
# Configuration Validation
# =============================================================================

def validate_config() -> None:
    if STATISTICS_DISPLAY_INTERVAL <= 0:
        raise ValueError("STATISTICS_DISPLAY_INTERVAL must be greater than 0.")
    if MAIN_LOOP_SLEEP <= 0:
        raise ValueError("MAIN_LOOP_SLEEP must be greater than 0.")
    if DUPLICATE_WINDOW < 0:
        raise ValueError("DUPLICATE_WINDOW cannot be negative.")
    if DUPLICATE_CACHE_CLEANUP_INTERVAL <= 0:
        raise ValueError("DUPLICATE_CACHE_CLEANUP_INTERVAL must be greater than 0.")
    if IDS_STATE_CLEANUP_INTERVAL <= 0:
        raise ValueError("IDS_STATE_CLEANUP_INTERVAL must be greater than 0.")
    if LOG_MAX_BYTES <= 0:
        raise ValueError("LOG_MAX_BYTES must be greater than 0.")
    if LOG_BACKUP_COUNT < 0:
        raise ValueError("LOG_BACKUP_COUNT cannot be negative.")
    if MAX_PACKET_SIZE <= 0:
        raise ValueError("MAX_PACKET_SIZE must be greater than 0.")
    if CONSOLE_IP_WIDTH < 39:
        raise ValueError("CONSOLE_IP_WIDTH must be at least 39 for IPv6 addresses.")
    if GUI_REFRESH_RATE_MS <= 0:
        raise ValueError("GUI_REFRESH_RATE_MS must be greater than 0.")
    if GUI_MAX_TABLE_ROWS <= 0:
        raise ValueError("GUI_MAX_TABLE_ROWS must be greater than 0.")

validate_config()