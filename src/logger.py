import logging
import sys
from typing import Optional, Any


def setup_logger(
    name: Optional[str] = None,
    level: str = "info",
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    log_file: Optional[str] = None,
    ui: Optional[Any] = None,
) -> logging.Logger:
    """
    Setup logger with given configuration

    Args:
        name: Logger name (None for root logger)
        level: Log level (debug, info, warning, error)
        log_format: Log message format
        log_file: Optional log file path (None for stdout)
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
    logger.setLevel(log_level)

    # Remove existing handlers
    logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter(log_format)

    # Setup handlers
    if ui:
        from ui import UILogHandler
        ui_handler = UILogHandler(ui)
        ui_handler.setLevel(log_level)
        ui_handler.setFormatter(formatter)
        logger.addHandler(ui_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # Use stdout only if UI is not active to avoid conflicts with rich.live
    if not ui:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setLevel(log_level)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get logger by name"""
    return logging.getLogger(name)
