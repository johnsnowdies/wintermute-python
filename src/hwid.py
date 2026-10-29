"""
HWID (Hardware ID) generation and management for Wintermute.

Modern VPN subscription providers (Happ, Throne, Remnawave, Lastdep, etc.)
require a unique device identifier (HWID) to be sent via HTTP headers when
fetching subscription data. Without it, the server returns a stub/dummy
response.

This module handles:
  - Generating a persistent, random HWID (UUID v4 format)
  - Loading/storing HWID from a JSON state file
  - Providing default device headers (User-Agent, X-Device-Model, etc.)
"""

import json
import os
import uuid
from pathlib import Path
from typing import Dict, Optional

from logger import get_logger

# Default state file location
_HWID_STATE_DIR = Path.home() / ".config" / "wintermute"
_HWID_STATE_FILE = _HWID_STATE_DIR / "hwid.json"

# Default headers mimicking a modern Happ/Throne client
_DEFAULT_DEVICE_HEADERS: Dict[str, str] = {
    "User-Agent": "Happ/3.13.0",
    "X-Device-Os": "Windows",
    "X-Device-Model": "PC",
    "X-Real-Ip": "",
    "X-Forwarded-For": "",
}


def _ensure_state_dir() -> None:
    """Ensure the state directory exists."""
    _HWID_STATE_DIR.mkdir(parents=True, exist_ok=True)


def _load_state() -> dict:
    """Load HWID state from disk."""
    try:
        if _HWID_STATE_FILE.exists():
            with open(_HWID_STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        get_logger(__name__).warning(f"Failed to load HWID state: {e}")
    return {}


def _save_state(state: dict) -> None:
    """Save HWID state to disk."""
    try:
        _ensure_state_dir()
        with open(_HWID_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
    except Exception as e:
        get_logger(__name__).warning(f"Failed to save HWID state: {e}")


def generate_hwid() -> str:
    """
    Generate a new random HWID.

    Happ/Throne ecosystem typically uses either:
      - UUID v4 format:  4998793c-3ce5-4ac9-9dfa-0ef5417b00fa
      - Hex string:      890877189e13ca8b

    We use UUID v4 as it's the most common format and guarantees uniqueness.
    """
    return str(uuid.uuid4())


def get_or_create_hwid() -> str:
    """
    Return the stored HWID, or generate + store a new one if none exists.

    Returns:
        The persistent HWID string.
    """
    state = _load_state()
    hwid = state.get("hwid")
    if not hwid:
        hwid = generate_hwid()
        state["hwid"] = hwid
        _save_state(state)
        get_logger(__name__).info(f"Generated new HWID: {hwid}")
    return hwid


def set_hwid(new_hwid: str) -> None:
    """
    Explicitly set a new HWID (e.g. user-provided or regenerated).

    Args:
        new_hwid: The new HWID string.
    """
    state = _load_state()
    state["hwid"] = new_hwid
    _save_state(state)
    get_logger(__name__).info(f"HWID set to: {new_hwid}")


def reset_hwid() -> str:
    """
    Generate a brand-new HWID, overwriting the old one.

    Returns:
        The new HWID string.
    """
    new_hwid = generate_hwid()
    set_hwid(new_hwid)
    return new_hwid


def get_hwid() -> Optional[str]:
    """
    Return the current stored HWID, or None if not yet generated.

    This is a read-only version of get_or_create_hwid() — it will NOT
    auto-generate a new one.
    """
    state = _load_state()
    return state.get("hwid")


def get_device_headers(
    hwid: Optional[str] = None,
    real_ip: Optional[str] = None,
) -> Dict[str, str]:
    """
    Build the HTTP headers map to send with subscription requests.

    Args:
        hwid: The HWID to use. If None, auto-loads from state.
        real_ip: Optional real IP for X-Real-Ip / X-Forwarded-For.

    Returns:
        A dict of HTTP headers.
    """
    if hwid is None:
        hwid = get_or_create_hwid()

    headers = dict(_DEFAULT_DEVICE_HEADERS)
    headers["X-Hwid"] = hwid

    if real_ip:
        headers["X-Real-Ip"] = real_ip
        headers["X-Forwarded-For"] = real_ip

    return headers