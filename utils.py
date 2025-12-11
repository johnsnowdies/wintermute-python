from typing import Dict, List, Optional, Tuple
from pathlib import Path
import subprocess

def find_singbox() -> Optional[str]:
    """Находит путь к sing-box"""
    possible_paths = [
        "/usr/local/bin/sing-box",
        "/usr/bin/sing-box",
        Path.home() / "sing-box" / "sing-box",
        "./sing-box",
        "sing-box"
    ]
    
    for path in possible_paths:
        path_str = str(path) if isinstance(path, Path) else path
        try:
            result = subprocess.run([path_str, "version"], 
                                  capture_output=True, text=True,
                                  timeout=2)
            if result.returncode == 0:
                return path_str
        except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
            continue
    
    return None