from collections import deque
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Deque, Optional, Any

from logger import get_logger


class XrayManager:
    """Xray-core process manager class"""

    def __init__(self, xray_path: str, config_path: Path, ui: Optional[Any] = None, log_file: Optional[str] = None):
        self.logger = get_logger(__name__)
        self.xray_path = xray_path
        self.config_path = config_path
        self.ui = ui
        self.log_file = log_file
        self.process: Optional[subprocess.Popen] = None
        self._running = False
        self._log_thread: Optional[threading.Thread] = None
        self._error_timestamps: Deque[float] = deque()
        self._error_lock = threading.Lock()

    def _cleanup_error_events(self, now: Optional[float] = None, window_sec: int = 60):
        """Drop ERROR events outside the rolling window."""
        if now is None:
            now = time.time()
        threshold = now - window_sec
        while self._error_timestamps and self._error_timestamps[0] < threshold:
            self._error_timestamps.popleft()

    def _register_error_event(self):
        """Register xray ERROR line in stdout log stream."""
        now = time.time()
        with self._error_lock:
            self._error_timestamps.append(now)
            self._cleanup_error_events(now=now)

    def _log_reader(self):
        """Read and out Xray STDOUT/STDERR logs"""
        if not self.process or not self.process.stdout:
            return

        log_f = None
        if self.log_file:
            try:
                log_f = open(self.log_file, "a", encoding="utf-8")
            except Exception as e:
                self.logger.error(f"Failed to open xray log file {self.log_file}: {e}")

        try:
            for line in iter(self.process.stdout.readline, ""):
                if not line:
                    break

                stripped_line = line.rstrip()
                if self.ui:
                    self.ui.add_core_log(f"[xray] {stripped_line}")
                else:
                    print(f"[xray] {stripped_line}")
                    sys.stdout.flush()

                if log_f:
                    log_f.write(line)
                    log_f.flush()

                if "ERROR" in line.upper() or "FAILED" in line.upper():
                    self._register_error_event()
        except Exception as e:
            self.logger.error(f"Xray log reading error: {e}")
        finally:
            if log_f:
                log_f.close()

    def start(self):
        """Launching Xray"""
        if self._running and self.process:
            self.logger.error("XrayManager start failed: already running")
            return False

        self.logger.debug(f"Running Xray with config: {self.config_path}")

        try:
            with self._error_lock:
                self._error_timestamps.clear()

            self.process = subprocess.Popen(
                [self.xray_path, "run", "-c", str(self.config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )
            self._running = True

            # Launching log-reader thread
            self._log_thread = threading.Thread(target=self._log_reader, daemon=True)
            self._log_thread.start()

            # Check process is running
            if self.process.poll() is not None:
                self.logger.error("Xray startup failure")
                # Reading error from STDOUT
                if self.process.stdout:
                    output = self.process.stdout.read()
                    if output:
                        self.logger.error(f"STDOUT:\n{output}")
                return False

            self.logger.debug("XrayManager start OK")
            return True

        except Exception as e:
            self.logger.error(f"Xray Startup error: {e}")
            return False

    def stop(self):
        """Stoping Xray process"""
        if not self._running or not self.process:
            return

        self.logger.debug("Stopping Xray")

        try:
            self.process.terminate()
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

        self._running = False
        self.process = None
        with self._error_lock:
            self._error_timestamps.clear()
        self.logger.debug("Xray successfully terminated")

    def restart(self):
        """Restart Xray process"""
        self.logger.debug("Restarting xray")
        self.stop()
        time.sleep(1)
        return self.start()

    def is_running(self) -> bool:
        """Check Xray is running"""
        if not self.process:
            return False
        return self.process.poll() is None

    def get_error_count(self, window_sec: int = 60) -> int:
        """Returns count of stdout ERROR messages in the rolling window."""
        with self._error_lock:
            self._cleanup_error_events(window_sec=window_sec)
            return len(self._error_timestamps)

    def has_error_burst(self, threshold: int = 3, window_sec: int = 60) -> bool:
        """Returns True when stdout ERROR count is greater than threshold in window."""
        return self.get_error_count(window_sec=window_sec) > threshold
