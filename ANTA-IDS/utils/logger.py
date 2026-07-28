# =============================================================================
# File: ANTA-IDS/utils/logger.py
# Project: Advanced Network Traffic Analyzer & Intrusion Detection System
# Author: Golsar Abhishek
# Description:
#     Centralized, thread-safe logging configuration for ANTA-IDS.
# =============================================================================

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import ClassVar

from config import (
    LOGS_DIR,
    LOG_LEVEL,
    LOG_FILE_FORMAT,
    LOG_DATE_FORMAT,
)


class Logger:
    """
    Centralized logging manager for ANTA-IDS.

    Provides:
        - Console logging
        - Daily file logging
        - UTF-8 log files
        - Duplicate-handler prevention
        - Thread-safe logger initialization
        - Graceful handler cleanup

    Example
    -------
        from utils.logger import Logger

        logger = Logger.get_logger(__name__)

        logger.info("Application started.")
        logger.warning("Suspicious activity detected.")
        logger.exception("Unexpected error.")
    """

    LOG_FOLDER: ClassVar[Path] = Path(LOGS_DIR)

    _lock: ClassVar[Lock] = Lock()
    _configured_loggers: ClassVar[set[str]] = set()

    # =========================================================================
    # Public Logger Factory
    # =========================================================================

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """
        Return a configured logger instance.

        Parameters
        ----------
        name:
            Logger name, normally ``__name__``.

        Returns
        -------
        logging.Logger
            Configured logger instance.
        """

        logger_name = str(name).strip() or "ANTA-IDS"

        logger = logging.getLogger(logger_name)

        # Fast path for loggers already configured by this class.
        if logger_name in cls._configured_loggers:
            return logger

        with cls._lock:

            # Check again after acquiring the lock because another
            # thread may have configured the logger already.
            if logger_name in cls._configured_loggers:
                return logger

            cls._configure_logger(
                logger=logger,
            )

            cls._configured_loggers.add(
                logger_name
            )

        return logger

    # =========================================================================
    # Logger Configuration
    # =========================================================================

    @classmethod
    def _configure_logger(
        cls,
        logger: logging.Logger,
    ) -> None:
        """
        Configure a logger with console and file handlers.
        """

        cls._ensure_log_directory()

        logger.setLevel(LOG_LEVEL)

        # Prevent messages from being duplicated by the root logger.
        logger.propagate = False

        # Remove only handlers previously created by this Logger class.
        #
        # This makes reconfiguration safer without interfering with
        # unrelated third-party handlers.
        cls._remove_managed_handlers(
            logger
        )

        formatter = cls._create_formatter()

        # ---------------------------------------------------------------------
        # File Handler
        # ---------------------------------------------------------------------

        file_handler = cls._create_file_handler(
            formatter
        )

        if file_handler is not None:
            logger.addHandler(
                file_handler
            )

        # ---------------------------------------------------------------------
        # Console Handler
        # ---------------------------------------------------------------------

        console_handler = cls._create_console_handler(
            formatter
        )

        logger.addHandler(
            console_handler
        )

    # =========================================================================
    # Formatter
    # =========================================================================

    @staticmethod
    def _create_formatter() -> logging.Formatter:
        """
        Create the common ANTA-IDS log formatter.
        """

        return logging.Formatter(
            fmt=LOG_FILE_FORMAT,
            datefmt=LOG_DATE_FORMAT,
        )

    # =========================================================================
    # File Handler
    # =========================================================================

    @classmethod
    def _create_file_handler(
        cls,
        formatter: logging.Formatter,
    ) -> logging.Handler | None:
        """
        Create the daily file logging handler.

        Returns None if the log file cannot be created. This allows
        ANTA-IDS to continue running with console logging instead of
        crashing solely because file logging failed.
        """

        try:

            log_file = cls._get_log_file()

            handler = logging.FileHandler(
                filename=log_file,
                mode="a",
                encoding="utf-8",
                delay=False,
            )

            handler.setLevel(
                LOG_LEVEL
            )

            handler.setFormatter(
                formatter
            )

            # Mark handler as managed by this class.
            setattr(
                handler,
                "_anta_ids_handler",
                True,
            )

            return handler

        except (OSError, PermissionError):

            # We intentionally avoid using the logger here because
            # logger initialization is still in progress.
            print(
                "[ANTA-IDS] WARNING: "
                "Unable to initialize file logging.",
                file=sys.stderr,
            )

            return None

    # =========================================================================
    # Console Handler
    # =========================================================================

    @staticmethod
    def _create_console_handler(
        formatter: logging.Formatter,
    ) -> logging.StreamHandler:
        """
        Create the console logging handler.
        """

        handler = logging.StreamHandler(
            stream=sys.stderr
        )

        handler.setLevel(
            LOG_LEVEL
        )

        handler.setFormatter(
            formatter
        )

        setattr(
            handler,
            "_anta_ids_handler",
            True,
        )

        return handler

    # =========================================================================
    # Log Directory
    # =========================================================================

    @classmethod
    def _ensure_log_directory(
        cls,
    ) -> None:
        """
        Ensure the log directory exists.
        """

        cls.LOG_FOLDER.mkdir(
            parents=True,
            exist_ok=True,
        )

    # =========================================================================
    # Daily Log File
    # =========================================================================

    @classmethod
    def _get_log_file(
        cls,
    ) -> Path:
        """
        Return today's ANTA-IDS log file path.
        """

        date_string = datetime.now().strftime(
            "%Y-%m-%d"
        )

        return (
            cls.LOG_FOLDER
            / f"{date_string}.log"
        )

    # =========================================================================
    # Handler Management
    # =========================================================================

    @staticmethod
    def _remove_managed_handlers(
        logger: logging.Logger,
    ) -> None:
        """
        Remove handlers previously created by ANTA-IDS.
        """

        for handler in logger.handlers[:]:

            if not getattr(
                handler,
                "_anta_ids_handler",
                False,
            ):
                continue

            logger.removeHandler(
                handler
            )

            try:
                handler.flush()

            except Exception:
                pass

            try:
                handler.close()

            except Exception:
                pass

    # =========================================================================
    # Shutdown
    # =========================================================================

    @classmethod
    def shutdown(cls) -> None:
        """
        Flush and close all handlers managed by ANTA-IDS.

        This can be called during application shutdown.
        """

        with cls._lock:

            for logger_name in list(
                cls._configured_loggers
            ):

                logger = logging.getLogger(
                    logger_name
                )

                cls._remove_managed_handlers(
                    logger
                )

            cls._configured_loggers.clear()

    # =========================================================================
    # Utility
    # =========================================================================

    @classmethod
    def get_log_file(cls) -> Path:
        """
        Return the path of the current daily log file.
        """

        return cls._get_log_file()

    # =========================================================================
    # Representation
    # =========================================================================

    def __repr__(self) -> str:
        return (
            f"Logger("
            f"log_folder={str(self.LOG_FOLDER)!r}, "
            f"level={logging.getLevelName(LOG_LEVEL)!r}"
            f")"
        )