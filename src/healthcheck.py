import threading
import time
import hashlib
from typing import Callable, List, Optional

import requests
import urllib3

from logger import get_logger, setup_logger


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
        initial_delay: int = 10,
    ):
        """
        Args:
            check_urls: List of URLs to check
            check_interval: in seconds
            timeout: request timeout
            failure_threshold: count of failures before callback
            on_failure_callback: callback function
            initial_delay: delay before first attempt
        """
        self.check_urls = check_urls
        self.check_interval = check_interval
        self.timeout = timeout
        self.failure_threshold = failure_threshold
        self.on_failure_callback = on_failure_callback
        self.initial_delay = initial_delay

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._failure_count = 0
        self._last_check_time = 0
        self._last_status = True
        self._first_check = True
        setup_logger(name=__name__)
        self.logger = get_logger(__name__)

    def start(self):
        """Запускает мониторинг в фоновом потоке"""
        if self._running:
            self.logger.warn("HealthChecker already running")
            return

        self._running = True
        self._failure_count = 0
        self._first_check = True
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
            time.sleep(self.initial_delay)
            self._first_check = False

        while self._running:
            try:
                is_ok = self._check_connection()
                self._last_check_time = time.time()

                if is_ok:
                    if not self._last_status:
                        self._last_status = True
                    self._failure_count = 0
                    if self._failure_count == 0:
                        self.logger.info("Tunnel healthy")
                else:
                    self._failure_count += 1
                    self.logger.warn(
                        f"Detected fault ({self._failure_count}/{self.failure_threshold})"
                    )

                    if (
                        self._failure_count >= self.failure_threshold
                        and self._last_status
                    ):
                        # Tunnel is down
                        self.logger.error(
                            f"Tunnel failed for {self._failure_count} times!"
                        )
                        self._last_status = False

                        # Вызываем callback
                        if self.on_failure_callback:
                            try:
                                self.on_failure_callback()
                            except Exception as e:
                                self.logger.error(f"Callback error: {e}")

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
        from wintermute import Wintermute

        client = Wintermute(test_mode=True)
        test_url = client.config.testing.healthcheck_content_url
        expected_md5 = client.config.testing.healthcheck_content_md5
        del client

        for url in self.check_urls:
            try:
                # First check
                response = requests.get(url, timeout=self.timeout, verify=True)

                if response.status_code in [200, 204]:
                    # Second check
                    response = requests.get(
                        test_url,
                        timeout=5,
                        verify=True,
                    )
                    # check code
                    if response.status_code == 200:
                        response_content = response.text

                        content_md5 = hashlib.md5(
                            response_content.encode("utf-8")
                        ).hexdigest()

                        # check hashes
                        if content_md5 == expected_md5:
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
