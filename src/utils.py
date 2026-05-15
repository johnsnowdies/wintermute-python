import base64
import json
import os
import subprocess
from pathlib import Path
from typing import Optional, List

from logger import get_logger


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


def get_removable_drives() -> List[str]:
    """Find removable USB drives using lsblk"""
    try:
        result = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,TRAN,MOUNTPOINT,TYPE"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            return []

        data = json.loads(result.stdout)
        drives = []

        def find_usb(devices):
            for dev in devices:
                # Check for USB transport and disk type
                if dev.get("tran") == "usb" and dev.get("type") == "disk":
                    drives.append(f"/dev/{dev['name']}")
                if "children" in dev:
                    find_usb(dev["children"])

        if "blockdevices" in data:
            find_usb(data["blockdevices"])

        return drives
    except Exception as e:
        get_logger(__name__).error(f"Error finding USB drives: {e}")
        return []


def mount_drive(device: str, mount_point: str) -> bool:
    """Mount device to mount_point"""
    try:
        if not os.path.exists(mount_point):
            os.makedirs(mount_point, exist_ok=True)

        result = subprocess.run(
            ["mount", device, mount_point],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return True

        # If already mounted, check if it's the same mount point
        if "already mounted" in result.stderr:
            return True

        get_logger(__name__).error(f"Mount failed: {result.stderr}")
        return False
    except Exception as e:
        get_logger(__name__).error(f"Error mounting drive: {e}")
        return False


def unmount_drive(mount_point: str) -> bool:
    """Unmount device from mount_point"""
    try:
        result = subprocess.run(
            ["umount", mount_point],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception as e:
        get_logger(__name__).error(f"Error unmounting drive: {e}")
        return False


def decode_b64_if_valid(s: str) -> Optional[str]:
    """Decodes base64 if possible"""
    try:
        missing_padding = len(s) % 4
        if missing_padding:
            s += "=" * (4 - missing_padding)
        return base64.b64decode(s).decode("utf-8")
    except Exception as e:
        logger = get_logger(__name__)
        logger.debug(f"_decode_b64_if_valid general error: {e}")
        return None

def find_xray() -> Optional[str]:
    """Find Xray executable"""
    possible_paths = [
        "/usr/local/bin/xray",
        "/usr/bin/xray",
        Path.home() / "xray" / "xray",
        "./xray",
        "xray",
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
