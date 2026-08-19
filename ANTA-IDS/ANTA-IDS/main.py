"""
===============================================================================
ANTA-IDS
Advanced Network Traffic Analyzer & Intrusion Detection System

File:
    main.py

Description:
    Main application entry point. Initializes ANTA-IDS, selects the capture
    interface, starts the asynchronous packet capture, routes traffic through 
    the IDS pipeline, persists data to SQLite, and runs the PySide6 GUI.
===============================================================================
"""

from __future__ import annotations

import sys
import time
from typing import Any

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication

from analyzer.flow import FlowManager
from analyzer.protocol import ProtocolAnalyzer
from analyzer.statistics import StatisticsManager
from capture.interfaces import InterfaceManager, NetworkInterface
from capture.parser import PacketParser
from capture.sniffer import PacketSniffer
from database.database import DatabaseManager
from gui.main_window import MainWindow
from ids.detector import IDSDetector
from utils.logger import Logger

logger = Logger.get_logger(__name__)


# =============================================================================
# Development / Debug Configuration
# =============================================================================

DEBUG_KALI_TRAFFIC = False
KALI_IP = "10.23.81.115"


# =============================================================================
# Thread-Safe GUI Bridge
# =============================================================================

class GuiBridge(QObject):
    """
    Safely transfers data from the background capture thread to the
    main PySide6 GUI thread.
    """
    packet_processed = Signal(object, dict)


# =============================================================================
# Module Initialization
# =============================================================================

def initialize_modules() -> tuple[
    InterfaceManager,
    PacketParser,
    FlowManager,
    StatisticsManager,
    ProtocolAnalyzer,
    IDSDetector,
    DatabaseManager,
]:
    """
    Initialize all ANTA-IDS backend modules.
    """
    interface_manager = InterfaceManager()
    parser = PacketParser()
    flow_manager = FlowManager()
    statistics = StatisticsManager()
    protocol_analyzer = ProtocolAnalyzer()
    detector = IDSDetector()
    db_manager = DatabaseManager()

    return (
        interface_manager,
        parser,
        flow_manager,
        statistics,
        protocol_analyzer,
        detector,
        db_manager,
    )


# =============================================================================
# Interface Selection (Console Fallback for Startup)
# =============================================================================

def select_interface(
    interface_manager: InterfaceManager,
) -> NetworkInterface | None:
    """
    Display available interfaces in the terminal and allow the user to select one
    before launching the GUI.
    """
    interface_manager.display_interfaces()

    while True:
        try:
            raw_choice = input("\nSelect Interface: ").strip()

            if not raw_choice:
                print("Please enter an interface number.")
                continue

            choice = int(raw_choice)
            selected_interface = interface_manager.get_interface(choice)

            if selected_interface is None:
                print("Invalid selection. Please try again.")
                continue

            return selected_interface

        except ValueError:
            print("Please enter a valid interface number.")
        except (KeyboardInterrupt, EOFError):
            print("\nInterface selection cancelled.")
            return None


# =============================================================================
# Main Application
# =============================================================================

def main() -> None:
    """
    Start ANTA-IDS, initialize the PySide6 application, and process traffic.
    """
    logger.info("=" * 60)
    logger.info("Starting ANTA-IDS (GUI Mode)")

    try:
        (
            interface_manager,
            parser,
            flow_manager,
            statistics,
            protocol_analyzer,
            detector,
            db_manager,
        ) = initialize_modules()
    except Exception:
        logger.exception("Failed to initialize ANTA-IDS modules.")
        print("\nFailed to initialize ANTA-IDS.")
        return

    # 1. Select Interface via terminal before the GUI boots
    try:
        selected_interface = select_interface(interface_manager)
    except Exception:
        logger.exception("Unexpected error during interface selection.")
        return

    if selected_interface is None:
        return

    print(f"\nInitializing PySide6 GUI on interface: {selected_interface.name}...")

    # 2. Initialize PySide6 Application
    app = QApplication(sys.argv)
    
    main_window = MainWindow(statistics, detector, db_manager)
    gui_bridge = GuiBridge()

    # -------------------------------------------------------------------------
    # CRITICAL FIX: Actively connecting the background data to the Live Table
    # -------------------------------------------------------------------------
    gui_bridge.packet_processed.connect(main_window.packet_table.add_packet)

    # Track saved alerts to prevent database duplicates
    nonlocal_vars = {"last_saved_alert_count": 0}

    # 3. Define Packet Callback (Runs in Sniffer Thread)
    def packet_callback(packet: Any) -> None:
        try:
            packet_info = parser.parse(packet)
            if packet_info is None:
                return

            flow_manager.add_packet(packet_info)
            statistics.update(packet_info)
            analysis = protocol_analyzer.analyze(packet_info)
            
            # Intrusion Detection & Database Persistence
            detector.analyze(packet_info)
            
            current_alerts = detector.get_alerts()
            if len(current_alerts) > nonlocal_vars["last_saved_alert_count"]:
                new_alerts = current_alerts[nonlocal_vars["last_saved_alert_count"]:]
                for alert in new_alerts:
                    db_manager.save_alert(alert)
                nonlocal_vars["last_saved_alert_count"] = len(current_alerts)

            # Emit safely to the main GUI thread to populate the PacketTable
            gui_bridge.packet_processed.emit(packet_info, analysis)

        except Exception:
            logger.exception("Packet processing failed.")

    # 4. Initialize & Start Capture Engine
    try:
        sniffer = PacketSniffer(
            interface=selected_interface,
            packet_callback=packet_callback,
        )
        if not sniffer.start():
            print("\nFailed to start packet capture.")
            return
    except Exception:
        logger.exception("Failed to initialize PacketSniffer.")
        return

    # Wire the GUI Stop button to safely shut down the app
    def shutdown_application():
        print("\nStopping capture and exiting GUI...")
        sniffer.stop()
        app.quit()

    main_window.btn_stop.clicked.connect(shutdown_application)

    # 5. Execute GUI Loop
    main_window.show()
    try:
        # Blocks until the window is closed
        app.exec()
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
    finally:
        sniffer.stop()
        logger.info("ANTA-IDS stopped gracefully.")

if __name__ == "__main__":
    main()