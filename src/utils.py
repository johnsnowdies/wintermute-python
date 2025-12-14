import base64
import subprocess
from pathlib import Path
from typing import Optional

from logger import get_logger, setup_logger


def find_singbox() -> Optional[str]:
    """Find Sing-Box executable"""
    possible_paths = [
        "/usr/local/bin/sing-box",
        "/usr/bin/sing-box",
        Path.home() / "sing-box" / "sing-box",
        "./sing-box",
        "sing-box",
    ]

    for path in possible_paths:
        path_str = str(path) if isinstance(path, Path) else path
        try:
            result = subprocess.run(
                [path_str, "version"], capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                return path_str
        except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
            continue

    return None


def decode_b64_if_valid(s: str) -> Optional[str]:
    """Decodes base64 if possible"""
    try:
        missing_padding = len(s) % 4
        if missing_padding:
            s += "=" * (4 - missing_padding)
        return base64.b64decode(s).decode("utf-8")
    except Exception as e:
        setup_logger(__name__)
        logger = get_logger(__name__)
        logger.debug(f"_decode_b64_if_valid general error: {e}")
        return None
