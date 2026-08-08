import logging
import sys
from typing import Optional, Any


class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to log levels using Rich markup"""

    COLORS = {
        "DEBUG": "dim cyan",
        "INFO": "green",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "bold red",
    }

    def format(self, record):
        # Create a copy of the record to avoid modifying the original one permanently
        # as it might be used by multiple handlers
        record_copy = logging.makeLogRecord(record.__dict__)

        level_name = record_copy.levelname
        color = self.COLORS.get(level_name, "white")
        record_copy.levelname = f"[{color}]{level_name}[/]"
        return super().format(record_copy)


def setup_logger(
    name: Optional[str] = None,
    level: str = "info",
    log_format: str = "%(asctime)s %(levelname)s: %(message)s",
    log_file: Optional[str] = None,
    file_level: str = "debug",
    ui: Optional[Any] = None,
) -> logging.Logger:
    """
    Setup logger with given configuration

    Args:
        name: Logger name (None for root logger)
        level: Log level (debug, info, warning, error)
        log_format: Log message format
        log_file: Optional log file path (None for stdout)
        file_level: Log level for file (debug, info, warning, error)
        ui: Optional UI object for logging to UI

    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)

    # Convert string level to logging constant
    level_map = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
    }
    log_level = level_map.get(level.lower(), logging.INFO)
    f_level = level_map.get(file_level.lower(), logging.DEBUG)

    # Set logger level to the minimum of all required levels
    logger.setLevel(min(log_level, f_level))

    # Remove existing handlers
    logger.handlers.clear()

    # Create formatter
    # Default date format to only time
    date_fmt = "%H:%M:%S"

    # Use ColoredFormatter for UI and Console if it's going to be rendered by Rich
    # For file, we might want a plain formatter
    plain_formatter = logging.Formatter(log_format, datefmt=date_fmt)
    colored_formatter = ColoredFormatter(log_format, datefmt=date_fmt)

    # Setup handlers
    if ui:
        from ui import UILogHandler
        ui_handler = UILogHandler(ui)
        ui_handler.setLevel(log_level)
        ui_handler.setFormatter(colored_formatter)
        logger.addHandler(ui_handler)

    if log_file:
        import os
        # Ensure directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(f_level)
        file_handler.setFormatter(plain_formatter)
        logger.addHandler(file_handler)

    # Use stdout only if UI is not active to avoid conflicts with rich.live
    if not ui:
        # Use a simple StreamHandler with ColoredFormatter for stdout
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setLevel(log_level)
        stream_handler.setFormatter(colored_formatter)
        logger.addHandler(stream_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get logger by name"""
    return logging.getLogger(name)
