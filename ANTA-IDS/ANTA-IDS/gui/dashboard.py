# =============================================================================
# File: ANTA-IDS/gui/dashboard.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# =============================================================================

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame
from PySide6.QtCore import Qt

class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Create a horizontal row for the metric cards
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(20)
        
        # Build colored cards
        self.lbl_packets = self._create_card(cards_layout, "Total Packets", "#89b4fa") # Blue
        self.lbl_flows = self._create_card(cards_layout, "Active Flows", "#a6e3a1")    # Green
        self.lbl_pps = self._create_card(cards_layout, "Packets / Sec", "#f9e2af")     # Yellow
        self.lbl_bps = self._create_card(cards_layout, "Bytes / Sec", "#cba6f7")       # Purple
        
        layout.addLayout(cards_layout)
        layout.addStretch()

    def _create_card(self, parent_layout: QHBoxLayout, title: str, color: str) -> QLabel:
        """Helper to create a beautiful, colored metric card."""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: #313244;
                border-top: 4px solid {color};
                border-radius: 8px;
            }}
        """)
        
        card_layout = QVBoxLayout(card)
        
        title_label = QLabel(title.upper())
        title_label.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 14px; letter-spacing: 1px;")
        title_label.setAlignment(Qt.AlignCenter)
        
        value_label = QLabel("0")
        value_label.setStyleSheet("color: #cdd6f4; font-weight: bold; font-size: 32px;")
        value_label.setAlignment(Qt.AlignCenter)
        
        card_layout.addWidget(title_label)
        card_layout.addWidget(value_label)
        
        parent_layout.addWidget(card)
        return value_label

    def update_stats(self, stats_data: dict) -> None:
        self.lbl_packets.setText(f"{stats_data.get('packets', 0):,}")
        self.lbl_flows.setText(f"{stats_data.get('flows', 0):,}")
        self.lbl_pps.setText(f"{stats_data.get('pps', 0):.1f}")
        
        # Format Bytes to KB or MB for cleaner visuals
        bps = stats_data.get('bps', 0)
        if bps > 1024 * 1024:
            self.lbl_bps.setText(f"{(bps / 1024 / 1024):.2f} MB")
        elif bps > 1024:
            self.lbl_bps.setText(f"{(bps / 1024):.2f} KB")
        else:
            self.lbl_bps.setText(f"{bps:.0f} B")