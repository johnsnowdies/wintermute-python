import hashlib
import threading
import time
from typing import Callable, List, Optional

import requests
import urllib3

from logger import get_logger


# Disable cert warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HealthChecker:
    """
    Tunnel watchdog
    """

    def __init__(
        self,
        check_urls: List[str],
        check_interval: int = 30,
        timeout: int = 5,
        failure_threshold: int = 3,
        on_failure_callback: Optional[Callable] = None,
        external_fault_callback: Optional[Callable[[], bool]] = None,
        initial_delay: int = 10,
        content_url: str = "",
        content_md5: str = "",
    ):
        """
        Args:
            check_urls: List of URLs to check
            check_interval: in seconds
            timeout: request timeout
            failure_threshold: allowed failures per minute before callback
            on_failure_callback: callback function
            external_fault_callback: external fault signal callback
            initial_delay: delay before first attempt
            content_url: URL for content check
            content_md5: Expected MD5 hash for content
        """
        self.check_urls = check_urls
        self.check_interval = check_interval
        self.timeout = timeout
        self.failure_threshold = failure_threshold
        self.on_failure_callback = on_failure_callback
        self.external_fault_callback = external_fault_callback
        self.initial_delay = initial_delay
        self.content_url = content_url
        self.content_md5 = content_md5

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._failure_count = 0
        self._failure_window_start = time.monotonic()
        self._last_check_time = 0
        self._last_status = True
        self._first_check = True
        self.logger = get_logger(__name__)

    def start(self):
        """Запускает мониторинг в фоновом потоке"""
        if self._running:
            self.logger.warning("HealthChecker already running")
            return

        self._running = True
        self._failure_count = 0
        self._failure_window_start = time.monotonic()
        self._thread = threading.Thread(target=self._check_loop, daemon=True)
        self._thread.start()
        self.logger.info(
            f"HealthChecker running with interval: {self.check_interval}s, first check in {self.initial_delay}s)"
        )

    def stop(self):
        """Stop service"""
        if not self._running:
            return

        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("HealthChecker stopped")

    def is_running(self) -> bool:
        """Check watchdog is running"""
        return self._running

    def get_status(self) -> bool:
        """Current tunnel status"""
        return self._last_status

    def _check_loop(self):
        """Main Loop"""
        if self._first_check and self.initial_delay > 0:
            self.logger.info(f"{self.initial_delay}s before first check...")
            from ui import get_ui
            get_ui().set_health("WAITING", "yellow")
            time.sleep(self.initial_delay)
            self._first_check = False

        while self._running:
            try:
                now = time.monotonic()
                if now - self._failure_window_start >= 60:
                    self._failure_count = 0
                    self._failure_window_start = now

                from ui import get_ui
                ui = get_ui()

                old_mode = ui.mode
                ui.set_mode("HEALTHCHECK")

                try:
                    connection_ok = self._check_connection()
                    external_fault = False
                    if self.external_fault_callback:
                        try:
                            external_fault = self.external_fault_callback()
                        except Exception as e:
                            self.logger.error(f"External fault callback error: {e}")

                    is_ok = connection_ok and not external_fault
                    self._last_check_time = time.time()

                    if is_ok:
                        if not self._last_status:
                            self.logger.info("Tunnel recovered")
                            self._last_status = True
                        self._failure_count = 0
                        ui.set_health("OK", "green")
                        ui.set_mode("WORKING")
                    else:
                        if self._last_status:
                            self._failure_count += 1
                            reasons = []
                            if not connection_ok:
                                reasons.append("healthcheck")
                            if external_fault:
                                reasons.append("sing-box ERROR burst")
                            reasons_text = ", ".join(reasons) if reasons else "unknown"
                            self.logger.warning(
                                f"Detected fault ({self._failure_count} in current minute / allowed {self.failure_threshold}) [{reasons_text}]"
                            )

                            if self._failure_count <= self.failure_threshold:
                                ui.set_health(f"FAIL {self._failure_count}", "yellow")
                                ui.set_mode("WORKING")

                            if self._failure_count > self.failure_threshold:
                                ui.set_health("RECOVERING", "red")
                                self.logger.error(
                                    f"Tunnel failed after {self._failure_count} failures in the last minute!"
                                )
                                self._last_status = False

                                if self.on_failure_callback:
                                    try:
                                        # Callback usually sets mode to TESTING/WORKING
                                        self.on_failure_callback()
                                        self._failure_count = 0
                                    except Exception as e:
                                        self.logger.error(f"Callback error: {e}")
                        else:
                            ui.set_health("RECOVERING", "red")
                            self._failure_count = min(
                                self._failure_count, self.failure_threshold
                            )
                finally:
                    # If we didn't transition to TESTING (via callback) or stayed in HEALTHCHECK
                    if ui.mode == "HEALTHCHECK":
                        ui.set_mode(old_mode if old_mode != "HEALTHCHECK" else "WORKING")

            except Exception as e:
                self.logger.error(f"HealthChecker general error: {e}")

            # Wait for next check
            time.sleep(self.check_interval)

    def _check_connection(self) -> bool:
        """
        Checks the connection through the URL list
        Returns True if at least one URL is available.

        The check is performed directly (without a proxy), because in TUN mode
        all traffic already automatically goes through the tunnel.
        """
        if not self.content_url or not self.content_md5:
            # Fallback to simple URL checks if no content check is configured
            for url in self.check_urls:
                try:
                    response = requests.get(url, timeout=self.timeout, verify=False)
                    if response.status_code in [200, 204]:
                        return True
                except Exception:
                    continue
            return False

        for url in self.check_urls:
            try:
                # First check
                response = requests.get(url, timeout=self.timeout, verify=False)

                if response.status_code in [200, 204]:
                    # Second check
                    response = requests.get(
                        self.content_url,
                        timeout=self.timeout,
                        verify=False,
                    )
                    # check code
                    if response.status_code == 200:
                        response_content = response.text

                        content_md5 = hashlib.md5(
                            response_content.encode("utf-8")
                        ).hexdigest()

                        # check hashes
                        if content_md5 == self.content_md5:
                            return True

            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except Exception as e:
                self.logger.info(f"_check_connection error {e}")
                continue

        return False

    def force_check(self) -> bool:
        """
        Forced connection verification
        Returns True if the tunnel is working
        """
        return self._check_connection()
