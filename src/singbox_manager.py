import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from logger import get_logger, setup_logger


class SingboxManager:
    """Sing-Box process manager class"""

    def __init__(self, singbox_path: str, config_path: Path):
        setup_logger(__name__)
        self.logger = get_logger(__name__)
        self.singbox_path = singbox_path
        self.config_path = config_path
        self.process: Optional[subprocess.Popen] = None
        self._running = False
        self._log_thread: Optional[threading.Thread] = None

    def _log_reader(self):
        """Read and out Sing-Box STDOUT logs"""
        if not self.process or not self.process.stdout:
            return

        try:
            for line in iter(self.process.stdout.readline, ""):
                if not line:
                    break
                print(f"[sing-box] {line.rstrip()}")
                sys.stdout.flush()
        except Exception as e:
            self.logger.error(f"Sing-box log reading error: {e}")

    def start(self):
        """Launching Sing-Box"""
        if self._running and self.process:
            self.logger.warn("SingboxManager start failed: already running")
            return False

        self.logger.info(f"Running Sing-Box with config: {self.config_path}")

        try:
            self.process = subprocess.Popen(
                [self.singbox_path, "run", "-c", str(self.config_path)],
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
                self.logger.error("Sing-box startup failure")
                # Reading error from STDOUT
                if self.process.stdout:
                    output = self.process.stdout.read()
                    if output:
                        self.logger.error(f"STDOUT:\n{output}")
                return False

            self.logger.info("SingboxManager start OK")
            return True

        except Exception as e:
            self.logger.error(f"Sing-Box Startup error: {e}")
            return False

    def stop(self):
        """Stoping Sing-Box process"""
        if not self._running or not self.process:
            return

        self.logger.info("Stopping Sing-Box")

        try:
            self.process.terminate()
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

        self._running = False
        self.process = None
        self.logger.info("Sing-Box successfully terminated")

    def restart(self):
        """Restart Sing-Box process"""
        self.logger.info("Restarting sing-box")
        self.stop()
        time.sleep(1)
        return self.start()

    def is_running(self) -> bool:
        """Check Sing-Box is running"""
        if not self.process:
            return False
        return self.process.poll() is None
