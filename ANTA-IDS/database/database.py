# =============================================================================
# File: ANTA-IDS/database/database.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Thread-safe SQLite database manager for persisting network flows
#     and IDS alerts.
# =============================================================================

from __future__ import annotations
import sqlite3
from pathlib import Path
from threading import Lock
from typing import List, Tuple, Dict, Any

from config import BASE_DIR
from ids.alerts import Alert
from utils.logger import Logger

logger = Logger.get_logger(__name__)

# Assuming DATA_DIR from config, but falling back to BASE_DIR if needed
try:
    from config import DATABASE_FILE
    DB_PATH = DATABASE_FILE
except ImportError:
    DB_PATH: Path = BASE_DIR / "anta_ids_data.db"

class DatabaseManager:
    """
    Manages SQLite connections to store persistent data for ANTA-IDS.
    Uses a thread lock to prevent concurrent write collisions.
    """

    def __init__(self) -> None:
        self.db_path = str(DB_PATH)
        self._lock = Lock()
        self._initialize_tables()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a configured SQLite connection."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_tables(self) -> None:
        """Create database schema if it doesn't exist."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Alerts Table
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS alerts (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT NOT NULL,
                            severity TEXT NOT NULL,
                            detector TEXT NOT NULL,
                            source_ip TEXT NOT NULL,
                            destination_ip TEXT NOT NULL,
                            message TEXT NOT NULL
                        )
                    """)
                    
                    # Network Flows Table (for Top Talkers / Reports)
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS flow_stats (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            session_date TEXT NOT NULL,
                            source_ip TEXT NOT NULL,
                            destination_ip TEXT NOT NULL,
                            protocol TEXT NOT NULL,
                            total_bytes INTEGER DEFAULT 0,
                            total_packets INTEGER DEFAULT 0
                        )
                    """)
                    
                    conn.commit()
            except sqlite3.Error:
                logger.exception("Failed to initialize database tables.")

    # =========================================================================
    # Alerts Operations
    # =========================================================================

    def save_alert(self, alert: Alert) -> None:
        """Insert a newly generated alert into the database."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO alerts 
                        (timestamp, severity, detector, source_ip, destination_ip, message)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        alert.timestamp, 
                        alert.severity, 
                        alert.detector, 
                        alert.source_ip, 
                        alert.destination_ip, 
                        alert.message
                    ))
                    conn.commit()
            except sqlite3.Error:
                logger.exception("Failed to insert alert into database.")

    def get_recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve the most recent alerts for the Dashboard."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT * FROM alerts 
                        ORDER BY id DESC LIMIT ?
                    """, (limit,))
                    
                    return [dict(row) for row in cursor.fetchall()]
            except sqlite3.Error:
                logger.exception("Failed to retrieve alerts from database.")
                return []

    # =========================================================================
    # Data Management
    # =========================================================================

    def clear_all_data(self) -> None:
        """Wipes all persistent data from the database for a fresh session."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM alerts")
                    cursor.execute("DELETE FROM flow_stats")
                    # Reset the auto-increment counters
                    cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('alerts', 'flow_stats')")
                    conn.commit()
                    logger.info("Database tables cleared successfully.")
            except sqlite3.Error:
                logger.exception("Failed to clear database tables.")