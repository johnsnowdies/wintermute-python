"""
Healthcheck — watchdog туннеля: базовая проверка по списку URL +
опциональная проверка контента (скачивание файла + сверка MD5).
"""

import hashlib
import random
import threading
import time
from typing import Callable, List, Optional

import requests
import urllib3

from logger import get_logger


# Браузерный User-Agent для healthcheck-запросов (против DPI по User-Agent)
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"


def _jitter(base: float, spread: float = 0.2) -> float:
    """base ± random % (default ±20%)"""
    return base * (1 + random.uniform(-spread, spread))

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HealthChecker:
    """
    Watchdog туннеля: periodic checks по списку URL + опциональная
    проверка контента (скачивание файла + сверка MD5).
    При превышении failure_threshold вызывает on_failure.
    """

    def __init__(
        self,
        check_urls: List[str],
        check_interval: int = 30,
        timeout: int = 5,
        failure_threshold: int = 3,
        on_failure_callback: Optional[Callable] = None,
        initial_delay: int = 10,
        verify_tls: bool = False,
        content_check_enabled: bool = False,
        content_check_url: str = "",
        content_check_md5: str = "",
    ):
        self.check_urls = check_urls
        self.check_interval = check_interval
        self.timeout = timeout
        self.failure_threshold = failure_threshold
        self.on_failure_callback = on_failure_callback
        self.initial_delay = initial_delay
        self.verify_tls = verify_tls
        self.content_check_enabled = content_check_enabled
        self.content_check_url = content_check_url
        self.content_check_md5 = content_check_md5

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._failure_count = 0
        self._last_status = True
        self._first_check = True
        self.logger = get_logger(__name__)

    def start(self):
        if self._running:
            return
        self._running = True
        self._failure_count = 0
        self._thread = threading.Thread(target=self._check_loop, daemon=True)
        self._thread.start()
        self.logger.info(f"HealthChecker: {self.check_interval}s interval, first check in {self.initial_delay}s")

    def stop(self):
        if not self._running:
            return
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("HealthChecker stopped")

    def is_running(self) -> bool:
        return self._running

    def get_status(self) -> bool:
        return self._last_status

    def _check_loop(self):
        if self._first_check and self.initial_delay > 0:
            delay = _jitter(self.initial_delay)
            self.logger.info(f"Waiting {delay:.0f}s before first check (jittered)...")
            time.sleep(delay)
            self._first_check = False

        while self._running:
            try:
                ok = self._check_connection()
                if ok:
                    if not self._last_status:
                        self.logger.info("Tunnel recovered")
                        self._last_status = True
                    self._failure_count = 0
                else:
                    self._failure_count += 1
                    self.logger.warning(f"Healthcheck failed ({self._failure_count}/{self.failure_threshold})")
                    if self._failure_count > self.failure_threshold and self.on_failure_callback:
                        self.logger.error("Failure threshold reached, calling callback")
                        self._last_status = False
                        try:
                            self.on_failure_callback()
                            self._failure_count = 0
                        except Exception as e:
                            self.logger.error(f"Failure callback error: {e}")
            except Exception as e:
                self.logger.error(f"HealthChecker error: {e}")
            time.sleep(_jitter(self.check_interval))

    def _check_connection(self) -> bool:
        """Проверка: хотя бы один URL отвечает 200/204 + опционально проверка контента (скачивание + MD5)."""
        for url in self.check_urls:
            try:
                resp = requests.get(url, timeout=self.timeout, verify=self.verify_tls, headers={"User-Agent": _UA})
                if resp.status_code in (200, 204):
                    # Базовая проверка пройдена — теперь проверка контента (если включена)
                    if self.content_check_enabled and self.content_check_url and self.content_check_md5:
                        return self._check_content()
                    return True
            except Exception:
                continue
        return False

    def _check_content(self) -> bool:
        """
        Скачивает файл по content_check_url, вычисляет MD5 и сверяет
        с ожидаемым хешем. Если не совпадает или ошибка — False.
        """
        try:
            self.logger.info(f"Content check: downloading {self.content_check_url}")
            resp = requests.get(
                self.content_check_url,
                timeout=self.timeout,
                verify=self.verify_tls,
                headers={"User-Agent": _UA},
            )
            if resp.status_code != 200:
                self.logger.warning(f"Content check: HTTP {resp.status_code}, expected 200")
                return False

            actual_md5 = hashlib.md5(resp.content).hexdigest()
            self.logger.info(f"Content check: MD5={actual_md5}, expected={self.content_check_md5}")

            if actual_md5 == self.content_check_md5:
                return True
            else:
                self.logger.warning(f"Content check: MD5 mismatch ({actual_md5} != {self.content_check_md5})")
                return False

        except Exception as e:
            self.logger.error(f"Content check error: {e}")
            return False

    def force_check(self) -> bool:
        return self._check_connection()