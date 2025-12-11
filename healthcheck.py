#!/usr/bin/env python3
"""
Модуль для мониторинга работы туннеля
"""
import requests
import time
import threading
from typing import List, Callable, Optional
import urllib3

# Отключаем предупреждения о неверифицированных сертификатах
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HealthChecker:
    """
    Мониторинг работы туннеля
    Проверяет доступность через список URL и вызывает callback при падении
    """

    def __init__(
        self,
        check_urls: List[str],
        check_interval: int = 30,
        timeout: int = 5,
        failure_threshold: int = 3,
        on_failure_callback: Optional[Callable] = None,
        initial_delay: int = 10
    ):
        """
        Args:
            check_urls: Список URL для проверки
            check_interval: Интервал проверки в секундах
            timeout: Таймаут запроса в секундах
            failure_threshold: Количество неудачных проверок подряд до вызова callback
            on_failure_callback: Функция, вызываемая при падении туннеля
            initial_delay: Задержка перед первой проверкой (секунды)
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
        self._last_status = True  # True = работает, False = не работает
        self._first_check = True  # Флаг первой проверки

    def start(self):
        """Запускает мониторинг в фоновом потоке"""
        if self._running:
            print("⚠ HealthChecker уже запущен")
            return

        self._running = True
        self._failure_count = 0
        self._first_check = True
        self._thread = threading.Thread(target=self._check_loop, daemon=True)
        self._thread.start()
        print(f"✓ HealthChecker запущен (интервал: {self.check_interval}s, первая проверка через {self.initial_delay}s)")

    def stop(self):
        """Останавливает мониторинг"""
        if not self._running:
            return

        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        print("✓ HealthChecker остановлен")

    def is_running(self) -> bool:
        """Проверяет, запущен ли мониторинг"""
        return self._running

    def get_status(self) -> bool:
        """Возвращает текущий статус туннеля"""
        return self._last_status

    def _check_loop(self):
        """Основной цикл проверки"""
        # Начальная задержка перед первой проверкой
        if self._first_check and self.initial_delay > 0:
            print(f"⏳ Ожидание {self.initial_delay}s перед первой проверкой туннеля...")
            time.sleep(self.initial_delay)
            self._first_check = False

        while self._running:
            try:
                is_ok = self._check_connection()
                self._last_check_time = time.time()

                if is_ok:
                    if not self._last_status:
                        # Туннель восстановился
                        print("✅ Туннель восстановлен")
                        self._last_status = True
                    self._failure_count = 0
                    # Выводим успешную проверку только иногда (не спамим)
                    #if self._failure_count == 0 and hasattr(self, '_verbose'):
                    print("✓ Проверка туннеля: OK")
                else:
                    self._failure_count += 1
                    print(f"⚠ Проверка туннеля не прошла ({self._failure_count}/{self.failure_threshold})")

                    if self._failure_count >= self.failure_threshold and self._last_status:
                        # Туннель упал
                        print(f"❌ Туннель недоступен после {self._failure_count} попыток!")
                        self._last_status = False

                        # Вызываем callback
                        if self.on_failure_callback:
                            try:
                                self.on_failure_callback()
                            except Exception as e:
                                print(f"❌ Ошибка в callback: {e}")

            except Exception as e:
                print(f"❌ Ошибка в HealthChecker: {e}")

            # Ждем до следующей проверки
            time.sleep(self.check_interval)

    def _check_connection(self) -> bool:
        """
        Проверяет соединение через список URL
        Возвращает True если хотя бы один URL доступен

        Проверка идет напрямую (без прокси), т.к. в TUN режиме
        весь трафик уже автоматически идет через туннель
        """
        for url in self.check_urls:
            try:
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False
                )

                if response.status_code in [200, 204]:
                    return True

            except requests.exceptions.Timeout:
                # Таймаут
                continue
            except requests.exceptions.ConnectionError:
                # Нет соединения
                continue
            except Exception as e:
                # Другие ошибки (игнорируем SSL ошибки и т.п.)
                continue

        return False

    def force_check(self) -> bool:
        """
        Принудительная проверка соединения
        Возвращает True если туннель работает
        """
        return self._check_connection()


class SimpleHealthChecker:
    """
    Упрощенный вариант healthcheck без использования прокси
    Проверяет доступность интернета напрямую (для диагностики)
    """

    @staticmethod
    def check_internet(urls: List[str], timeout: int = 5) -> bool:
        """
        Проверяет доступность интернета
        """
        for url in urls:
            try:
                response = requests.get(url, timeout=timeout, verify=False)
                if response.status_code in [200, 204]:
                    return True
            except:
                continue
        return False

    @staticmethod
    def check_proxy(proxy_url: str, test_url: str, timeout: int = 5) -> bool:
        """
        Проверяет работу конкретного прокси
        """
        try:
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            response = requests.get(test_url, timeout=timeout, proxies=proxies, verify=False)
            return response.status_code in [200, 204]
        except:
            return False
