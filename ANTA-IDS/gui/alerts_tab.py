# =============================================================================
# File: ANTA-IDS/gui/alerts_tab.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# =============================================================================

import csv
import time
from pathlib import Path
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, 
    QHeaderView, QPushButton, QFileDialog, QMessageBox, QHBoxLayout
)
from PySide6.QtGui import QColor
from PySide6.QtCore import Qt

# Import the reports directory path from our config
try:
    from config import REPORTS_DIR
except ImportError:
    REPORTS_DIR = Path.cwd() / "reports"
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class AlertsTab(QWidget):
    """Displays real-time security alerts and provides CSV export functionality."""
    
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # --- Top Control Bar ---
        control_layout = QHBoxLayout()
        control_layout.addStretch()
        
        self.btn_export = QPushButton(" Export Alerts to CSV ")
        self.btn_export.setStyleSheet("""
            QPushButton {
                background-color: #a6e3a1; 
                color: #11111b; 
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #94e2d5;
            }
        """)
        self.btn_export.clicked.connect(self.export_to_csv)
        control_layout.addWidget(self.btn_export)
        
        layout.addLayout(control_layout)
        
        # --- Alerts Table ---
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Timestamp", "Severity", "Detector", "Source IP", "Destination IP", "Message"]
        )
        
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e2e;
                color: #cdd6f4;
                gridline-color: #313244;
                border: none;
                font-family: 'Consolas', monospace;
                font-size: 13px;
            }
            QHeaderView::section {
                background-color: #181825;
                color: #a6adc8;
                padding: 5px;
                border: 1px solid #313244;
                font-weight: bold;
                font-size: 14px;
            }
        """)
        
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        
        layout.addWidget(self.table)
        self._last_alert_count = 0
        self._current_alerts = [] # Keep a reference for exporting

    def update_alerts(self, alerts_list: list) -> None:
        """Populates the table with recent alerts."""
        if len(alerts_list) == self._last_alert_count and self._last_alert_count != 0:
            return
            
        self._last_alert_count = len(alerts_list)
        self._current_alerts = alerts_list
        
        self.table.setRowCount(0)
        
        for alert in reversed(alerts_list):
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            items = [
                QTableWidgetItem(str(alert.get("timestamp", ""))),
                QTableWidgetItem(str(alert.get("severity", ""))),
                QTableWidgetItem(str(alert.get("detector", ""))),
                QTableWidgetItem(str(alert.get("source_ip", ""))),
                QTableWidgetItem(str(alert.get("destination_ip", ""))),
                QTableWidgetItem(str(alert.get("message", "")))
            ]
            
            severity = str(alert.get("severity", "")).upper()
            text_color = QColor("#cdd6f4")
            
            if severity == "CRITICAL":
                text_color = QColor("#f38ba8")
            elif severity == "HIGH":
                text_color = QColor("#fab387")
            elif severity == "MEDIUM":
                text_color = QColor("#f9e2af")
                
            for col, item in enumerate(items):
                item.setForeground(text_color)
                if col == 1:
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                self.table.setItem(row, col, item)

    def export_to_csv(self):
        """Dumps the currently loaded alerts into a CSV file in the reports folder."""
        if not self._current_alerts:
            QMessageBox.information(self, "Export", "No alerts available to export.")
            return

        # Generate a unique filename using a timestamp
        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        default_file_name = f"anta_ids_alerts_{timestamp_str}.csv"
        
        # Point the file dialog directly to the reports folder
        default_path = str(REPORTS_DIR / default_file_name)

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Alerts Report", default_path, "CSV Files (*.csv)"
        )

        if not file_path:
            return

        try:
            with open(file_path, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                # Write Headers
                writer.writerow(["Timestamp", "Severity", "Detector", "Source IP", "Destination IP", "Message"])
                
                # Write Data
                for alert in reversed(self._current_alerts):
                    writer.writerow([
                        alert.get("timestamp", ""),
                        alert.get("severity", ""),
                        alert.get("detector", ""),
                        alert.get("source_ip", ""),
                        alert.get("destination_ip", ""),
                        alert.get("message", "")
                    ])
                    
            QMessageBox.information(self, "Success", f"Alerts successfully exported to:\n{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to save CSV file:\n{str(e)}")