# =============================================================================
# File: ANTA-IDS/gui/main_window.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Main graphical application window using PySide6.
# =============================================================================

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTabWidget, QLabel, QPushButton, QStatusBar
)

from gui.packet_table import PacketTable
from gui.dashboard import Dashboard
from gui.dialogs import DialogManager
from gui.alerts_tab import AlertsTab

from analyzer.statistics import StatisticsManager
from ids.detector import IDSDetector


class MainWindow(QMainWindow):
    def __init__(self, statistics: StatisticsManager, detector: IDSDetector, db_manager: object) -> None:
        super().__init__()
        
        self.statistics = statistics
        self.detector = detector
        self.db_manager = db_manager

        self.setWindowTitle("ANTA-IDS - Advanced Network Traffic Analyzer")
        self.resize(1200, 800)

        # Apply Global Dark Theme & Colors
        self._apply_stylesheet()

        self.dialogs = DialogManager(self)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(15, 15, 15, 15)
        self.main_layout.setSpacing(15)

        self._build_header()
        self._build_tabs()
        self._build_status_bar()

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self._update_gui)
        self.refresh_timer.start(1000)

    def _apply_stylesheet(self):
        """Injects a modern, colorful dark theme into the application."""
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #1e1e2e;
                color: #cdd6f4;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QLabel {
                font-size: 14px;
            }
            QTabWidget::pane {
                border: 1px solid #313244;
                border-radius: 8px;
                background-color: #181825;
            }
            QTabBar::tab {
                background-color: #313244;
                color: #a6adc8;
                padding: 10px 20px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                margin-right: 2px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #89b4fa;
                color: #11111b;
            }
            QPushButton {
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QStatusBar {
                background-color: #11111b;
                color: #a6adc8;
                font-weight: bold;
            }
        """)

    def _build_header(self) -> None:
        header_layout = QHBoxLayout()
        title = QLabel("ANTA-IDS Live Monitor")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #89b4fa; letter-spacing: 1px;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # --- CLEAR HISTORY BUTTON ---
        self.btn_clear = QPushButton(" CLEAR HISTORY ")
        self.btn_clear.setStyleSheet("""
            QPushButton {
                background-color: #fab387; 
                color: #11111b; 
                padding: 8px 16px;
                margin-right: 10px;
            }
            QPushButton:hover {
                background-color: #f9e2af;
            }
        """)
        self.btn_clear.clicked.connect(self._clear_history)
        header_layout.addWidget(self.btn_clear)
        
        # --- STOP CAPTURE BUTTON ---
        self.btn_stop = QPushButton(" STOP CAPTURE ")
        self.btn_stop.setStyleSheet("""
            QPushButton {
                background-color: #f38ba8; 
                color: #11111b; 
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #eba0ac;
            }
        """)
        header_layout.addWidget(self.btn_stop)
        
        self.main_layout.addLayout(header_layout)

    def _build_tabs(self) -> None:
        self.tabs = QTabWidget()
        
        self.dashboard = Dashboard()
        self.tabs.addTab(self.dashboard, "Dashboard")
        
        self.packet_table = PacketTable()
        self.tabs.addTab(self.packet_table, "Live Packets")
        
        self.alerts_tab = AlertsTab()
        self.tabs.addTab(self.alerts_tab, "Security Alerts")
        
        self.main_layout.addWidget(self.tabs)

    def _build_status_bar(self) -> None:
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status_label = QLabel("Initializing Capture Engine...")
        self.status.addWidget(self.status_label)

    def _update_gui(self) -> None:
        stats_data = self.statistics.summary()
        self.dashboard.update_stats(stats_data)
        
        alert_count = self.detector.alert_count()
        status_text = (
            f"  Processed: {stats_data.get('packets', 0)} packets  |  "
            f"Speed: {stats_data.get('pps', 0):.2f} pps  |  "
            f"Active Alerts: {alert_count}  "
        )
        self.status_label.setText(status_text)
        
        if alert_count > 0:
            self.status.setStyleSheet("background-color: #f38ba8; color: #11111b;")
            
        # Fetch and update alerts from SQLite
        recent_alerts = self.db_manager.get_recent_alerts(limit=100)
        self.alerts_tab.update_alerts(recent_alerts)

    def _clear_history(self) -> None:
        """Completely wipes the database, detector state, and GUI tables."""
        # 1. Wipe the SQLite Database
        self.db_manager.clear_all_data()
        
        # 2. Reset the IDS Detector internal cache
        self.detector.reset()
        
        # 3. Clear the Live Packets Table
        self.packet_table.table.setRowCount(0)
        self.packet_table.row_count = 0
        
        # 4. Clear the Alerts Table
        if hasattr(self, 'alerts_tab'):
            self.alerts_tab.table.setRowCount(0)
            self.alerts_tab._last_alert_count = 0
            self.alerts_tab._current_alerts = []
            
        # 5. Reset Status Bar color
        self.status.setStyleSheet("background-color: #11111b; color: #a6adc8;")
            
        self.dialogs.show_info("History Cleared", "All database records, active alerts, and live packets have been successfully wiped.")