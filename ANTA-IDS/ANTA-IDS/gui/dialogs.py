# =============================================================================
# File: ANTA-IDS/gui/dialogs.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# =============================================================================

from PySide6.QtWidgets import QMessageBox

class DialogManager:
    """Manages popup dialogs and alerts for the GUI."""
    
    def __init__(self, parent=None):
        self.parent = parent

    def show_error(self, title: str, message: str) -> None:
        QMessageBox.critical(self.parent, title, message)

    def show_info(self, title: str, message: str) -> None:
        QMessageBox.information(self.parent, title, message)