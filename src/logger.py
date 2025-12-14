import logging
import sys
from typing import Optional


def setup_logger(
    name: str,
    level: str = "info",
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    log_file: Optional[str] = None,
) -> logging.Logger:
    """
    Setup logger with given configuration

    Args:
        name: Logger name
        level: Log level (debug, info, warning, error)
        log_format: Log message format
        log_file: Optional log file path (None for stdout)

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

    # Setup handler (file or stdout)
    if log_file:
        handler = logging.FileHandler(log_file, encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stdout)

    handler.setLevel(log_level)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get logger by name"""
    return logging.getLogger(name)
