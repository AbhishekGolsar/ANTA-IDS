# =============================================================================
# File: ANTA-IDS/utils/logger.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Centralized logging configuration for the entire application.
# =============================================================================

import logging
from datetime import datetime

from config import (
    LOGS_DIR,
    LOG_LEVEL,
    LOG_FILE_FORMAT,
    LOG_DATE_FORMAT,
)


class Logger:
    """
    Centralized logger used across the entire project.

    Example:
        from utils.logger import Logger

        logger = Logger.get_logger(__name__)
        logger.info("Application started")
    """

    LOG_FOLDER = LOGS_DIR

    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        """
        Create and return a configured logger.

        Parameters
        ----------
        name : str
            Logger name (typically __name__).

        Returns
        -------
        logging.Logger
            Configured logger instance.
        """

        # Ensure logs directory exists
        Logger.LOG_FOLDER.mkdir(
            parents=True,
            exist_ok=True,
        )

        # Daily log file
        log_file = Logger.LOG_FOLDER / (
            f"{datetime.now().strftime('%Y-%m-%d')}.log"
        )

        logger = logging.getLogger(name)

        # Avoid duplicate handlers
        if logger.handlers:
            return logger

        logger.setLevel(LOG_LEVEL)
        logger.propagate = False

        # ======================================================
        # Formatter
        # ======================================================

        formatter = logging.Formatter(
            fmt=LOG_FILE_FORMAT,
            datefmt=LOG_DATE_FORMAT,
        )

        # ======================================================
        # File Handler
        # ======================================================

        file_handler = logging.FileHandler(
            filename=log_file,
            encoding="utf-8",
        )

        file_handler.setFormatter(formatter)

        # ======================================================
        # Console Handler
        # ======================================================

        console_handler = logging.StreamHandler()

        console_handler.setFormatter(formatter)

        # ======================================================
        # Register Handlers
        # ======================================================

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        return logger