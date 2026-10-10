import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional, Any

from logger import get_logger


class BaseEngineManager:
    """Базовый класс для управления процессом прокси-движка (sing-box / xray)."""

    def __init__(self, engine_path: str, config_path: Path, label: str = "engine",
                 ui: Optional[Any] = None, log_file: Optional[str] = None, quiet: bool = False):
        self.logger = get_logger(__name__)
        self.engine_path = engine_path
        self.config_path = config_path
        self.label = label
        self.ui = ui
        self.log_file = log_file
        self.quiet = quiet
        self.process: Optional[subprocess.Popen] = None
        self._running = False
        self._log_thread: Optional[threading.Thread] = None

    def start(self):
        """Запуск процесса движка."""
        if self._running and self.process:
            self.logger.warning(f"{self.label}: already running")
            return False
        self.logger.debug(f"{self.label}: starting with config {self.config_path}")
        try:
            self.process = subprocess.Popen(
                [self.engine_path, "run", "-c", str(self.config_path)],
                stdout=subprocess.PIPE if not self.quiet else subprocess.DEVNULL,
                stderr=subprocess.STDOUT if not self.quiet else subprocess.DEVNULL,
                text=True, bufsize=1, universal_newlines=True,
            )
            self._running = True

            if not self.quiet:
                self._log_thread = threading.Thread(target=self._log_reader, daemon=True)
                self._log_thread.start()

            if self.process.poll() is not None:
                self.logger.error(f"{self.label}: startup failure")
                if self.process.stdout:
                    out = self.process.stdout.read()
                    if out:
                        self.logger.error(f"STDOUT:\n{out}")
                return False
            self.logger.debug(f"{self.label}: start OK")
            return True
        except Exception as e:
            self.logger.error(f"{self.label}: startup error: {e}")
            return False

    def stop(self):
        if not self._running or not self.process:
            return
        self.logger.debug(f"{self.label}: stopping")
        try:
            self.process.terminate()
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self._running = False
        self.process = None
        self.logger.debug(f"{self.label}: terminated")

    def restart(self):
        self.stop()
        time.sleep(1)
        return self.start()

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def _log_reader(self):
        if not self.process or not self.process.stdout:
            return
        log_f = None
        if self.log_file:
            try:
                log_f = open(self.log_file, "a", encoding="utf-8")
            except Exception as e:
                self.logger.error(f"{self.label}: log file error {e}")
        try:
            for line in iter(self.process.stdout.readline, ""):
                if not line:
                    break
                stripped = line.rstrip()
                if self.ui:
                    self.ui.add_core_log(f"[{self.label}] {stripped}")
                else:
                    print(f"[{self.label}] {stripped}")
                    sys.stdout.flush()
                if log_f:
                    log_f.write(line)
                    log_f.flush()
        except Exception as e:
            self.logger.error(f"{self.label}: log reader error: {e}")
        finally:
            if log_f:
                log_f.close()


class SingboxManager(BaseEngineManager):
    """Sing-Box process manager."""
    def __init__(self, singbox_path: str, config_path: Path,
                 ui: Optional[Any] = None, log_file: Optional[str] = None, quiet: bool = False):
        super().__init__(singbox_path, config_path, "sing-box", ui, log_file, quiet)


class XrayManager(BaseEngineManager):
    """Xray-core process manager."""
    def __init__(self, xray_path: str, config_path: Path,
                 ui: Optional[Any] = None, log_file: Optional[str] = None, quiet: bool = False):
        super().__init__(xray_path, config_path, "xray", ui, log_file, quiet)