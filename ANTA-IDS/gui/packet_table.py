# =============================================================================
# File: ANTA-IDS/gui/packet_table.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# =============================================================================

from PySide6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView
from PySide6.QtCore import Slot
from PySide6.QtGui import QColor

try:
    from config import GUI_MAX_TABLE_ROWS
except ImportError:
    GUI_MAX_TABLE_ROWS = 10000

class PacketTable(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Time", "Protocol", "Source", "Destination", "Length", "Information"])
        
        # Table Styling
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
        
        # Alternating row colors for readability
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False) # Hide row numbers for cleaner look
        
        layout.addWidget(self.table)
        self.row_count = 0

    @Slot(object, dict)
    def add_packet(self, packet_info, analysis) -> None:
        if self.row_count >= GUI_MAX_TABLE_ROWS:
            self.table.removeRow(0)
        else:
            self.row_count += 1
            
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        src = f"{packet_info.src_ip}:{packet_info.src_port}" if packet_info.src_port else packet_info.src_ip
        dst = f"{packet_info.dst_ip}:{packet_info.dst_port}" if packet_info.dst_port else packet_info.dst_ip
        
        # Define the row data
        items = [
            QTableWidgetItem(packet_info.timestamp),
            QTableWidgetItem(packet_info.protocol),
            QTableWidgetItem(src),
            QTableWidgetItem(dst),
            QTableWidgetItem(str(packet_info.packet_length)),
            QTableWidgetItem(packet_info.summary)
        ]
        
        # Protocol Coloring Logic
        text_color = QColor("#cdd6f4") # Default White/Gray
        proto = packet_info.protocol.upper()
        
        if proto == "TCP":
            text_color = QColor("#89b4fa") # Blue
        elif proto == "UDP":
            text_color = QColor("#a6e3a1") # Green
        elif proto == "ICMP":
            text_color = QColor("#f9e2af") # Yellow
        elif proto == "ARP":
            text_color = QColor("#fab387") # Orange
            
        # Insert items and apply color
        for col, item in enumerate(items):
            item.setForeground(text_color)
            self.table.setItem(row, col, item)
            
        self.table.scrollToBottom()