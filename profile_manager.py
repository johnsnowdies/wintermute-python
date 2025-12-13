#!/usr/bin/env python3
"""
Модуль для загрузки, тестирования и выбора профилей
"""
import base64
import requests
import socket
import time
import threading
import json
import hashlib
import hashlib

from requests.exceptions import RequestException
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote
from dataclasses import dataclass, field
import urllib3

# Отключаем предупреждения о неверифицированных сертификатах
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class Profile:
    """Профиль прокси"""
    protocol: str
    host: str
    port: int
    comment: str
    raw_url: str
    # Дополнительные параметры (зависят от протокола)
    extra: Dict = field(default_factory=dict)
    # Результаты тестирования
    latency: Optional[int] = None
    last_tested: Optional[float] = None
    is_working: bool = False


def decode_b64_if_valid(s: str) -> Optional[str]:
    """Декодирует base64 если возможно"""
    try:
        missing_padding = len(s) % 4
        if missing_padding:
            s += '=' * (4 - missing_padding)
        return base64.b64decode(s).decode('utf-8')
    except:
        return None


class ProfileCache:
    """Кеш для профилей"""

    def __init__(self, cache_dir: str = None):
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / ".cache" / "wintermute" / "profiles"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, url: str) -> Path:
        """Генерирует путь к кешу для URL"""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return self.cache_dir / f"profiles_{url_hash}.json"

    def save(self, url: str, profiles: List[str]) -> bool:
        """Сохраняет профили в кеш"""
        try:
            cache_path = self._get_cache_path(url)
            cache_data = {
                'url': url,
                'timestamp': time.time(),
                'profiles': profiles
            }
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"   ⚠ Не удалось сохранить кеш: {e}")
            return False

    def load(self, url: str, max_age: int = None) -> Optional[List[str]]:
        """
        Загружает профили из кеша

        Args:
            url: URL источника
            max_age: Максимальный возраст кеша в секундах (None = любой возраст)
        """
        try:
            cache_path = self._get_cache_path(url)
            if not cache_path.exists():
                return None

            with open(cache_path, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)

            # Проверяем возраст кеша
            if max_age is not None:
                age = time.time() - cache_data.get('timestamp', 0)
                if age > max_age:
                    print(f"   ⚠ Кеш устарел (возраст: {int(age)}s)")
                    return None

            profiles = cache_data.get('profiles', [])
            cache_age = int(time.time() - cache_data.get('timestamp', 0))
            print(f"   ✓ Загружено из кеша: {len(profiles)} профилей (возраст: {cache_age}s)")
            return profiles

        except Exception as e:
            print(f"   ⚠ Ошибка чтения кеша: {e}")
            return None

    def get_age(self, url: str) -> Optional[int]:
        """Возвращает возраст кеша в секундах"""
        try:
            cache_path = self._get_cache_path(url)
            if not cache_path.exists():
                return None

            with open(cache_path, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)

            return int(time.time() - cache_data.get('timestamp', 0))
        except:
            return None


class ProfileLoader:
    """Загрузчик профилей из источников"""

    def __init__(self, cache_dir: str = None, use_cache: bool = True):
        self.cache = ProfileCache(cache_dir) if use_cache else None

    def load_from_url(self, url: str, profile_filter: str = "", use_cache_fallback: bool = True) -> List[str]:
        """
        Загружает профили из URL с поддержкой кеширования

        Args:
            url: URL источника
            profile_filter: Фильтр профилей
            use_cache_fallback: Использовать кеш при недоступности источника
        """
        print(f"📥 Загружаю профили из: {url}")

        profiles = []

        try:
            response = requests.get(url, timeout=10, verify=False)
            response.raise_for_status()
            content = response.text.strip()

            # Пытаемся декодировать base64
            decoded = decode_b64_if_valid(content)
            if decoded:
                print("   ✓ Декодировано из base64")
                content = decoded

            # Разделяем на строки
            raw_lines = content.split('\n')

            # Фильтруем профили
            for line in raw_lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Фильтр по умолчанию - профили с "Обход" в названии
                    if not profile_filter or profile_filter in line:
                        profiles.append(line)

            print(f"   ✓ Найдено профилей: {len(profiles)}")

            # Сохраняем в кеш
            if self.cache and profiles:
                self.cache.save(url, profiles)
                print(f"   ✓ Профили сохранены в кеш")

            return profiles

        except Exception as e:
            print(f"   ✗ Ошибка загрузки: {e}")

            # Fallback на кеш при ошибке
            if use_cache_fallback and self.cache:
                print(f"   🔄 Попытка загрузить из кеша...")
                cached = self.cache.load(url, max_age=None)  # Любой возраст при fallback
                if cached:
                    print(f"   ✅ Используем кешированные профили")
                    return cached

            return []


class ProfileParser:
    """Парсер профилей разных протоколов"""

    @staticmethod
    def parse_proxy_url(url: str) -> Optional[Profile]:
        """Определяет тип прокси и парсит ссылку"""
        if url.startswith('vless://'):
            return ProfileParser._parse_vless(url)
        elif url.startswith('ss://'):
            return ProfileParser._parse_shadowsocks(url)
        elif url.startswith('vmess://'):
            return ProfileParser._parse_vmess(url)
        else:
            return None

    @staticmethod
    def _parse_vless(url: str) -> Optional[Profile]:
        """Парсит VLESS ссылку"""
        if not url.startswith('vless://'):
            return None

        url = url[8:]

        try:
            if '@' not in url:
                return None

            uuid_part, rest = url.split('@', 1)

            server_part = rest
            query_str = ""
            fragment = ""

            if '?' in rest:
                server_part, query_part = rest.split('?', 1)
                if '#' in query_part:
                    query_str, fragment = query_part.split('#', 1)
                else:
                    query_str = query_part
            elif '#' in rest:
                server_part, fragment = rest.split('#', 1)

            # Хост и порт
            if ':' in server_part:
                host_port_part = server_part
                if '/' in host_port_part:
                    host_port_part = host_port_part.split('/')[0]
                host, port = host_port_part.split(':', 1)
                port = int(port)
            else:
                host = server_part
                port = 443

            params = parse_qs(query_str)

            extra = {
                'uuid': uuid_part,
                'type': params.get('type', ['tcp'])[0],
                'security': params.get('security', ['none'])[0],
                'flow': params.get('flow', [''])[0],
                'packet_encoding': params.get('packetEncoding', ['xudp'])[0]
            }

            # Параметры транспорта
            if extra['type'] == 'grpc':
                extra['service_name'] = params.get('serviceName', ['grpc'])[0]
                extra['mode'] = params.get('mode', ['gun'])[0]
            elif extra['type'] == 'ws':
                extra['path'] = params.get('path', ['/'])[0]
                extra['ws_host'] = params.get('host', [''])[0]
            elif extra['type'] == 'http':
                extra['path'] = params.get('path', ['/'])[0]
                extra['http_host'] = params.get('host', [''])[0]

            # Параметры TLS/Reality
            if extra['security'] in ['tls', 'reality']:
                extra['sni'] = params.get('sni', [''])[0]
                extra['fp'] = params.get('fp', ['chrome'])[0]

                if extra['security'] == 'reality':
                    extra['pbk'] = params.get('pbk', [''])[0]
                    extra['sid'] = params.get('sid', [''])[0]
                    extra['spx'] = params.get('spx', ['/'])[0]

            comment = unquote(fragment) if fragment else f"VLESS {host}:{port}"

            return Profile(
                protocol='vless',
                host=host,
                port=port,
                comment=comment,
                raw_url=f"vless://{uuid_part}@{host}:{port}",
                extra=extra
            )

        except Exception as e:
            print(f"⚠ Ошибка парсинга VLESS: {e}")
            return None

    @staticmethod
    def _parse_shadowsocks(url: str) -> Optional[Profile]:
        """Парсит Shadowsocks ссылку"""
        if not url.startswith('ss://'):
            return None

        url = url[5:]

        try:
            if '#' in url:
                url, fragment = url.split('#', 1)
                comment = unquote(fragment)
            else:
                comment = ""

            # Пытаемся декодировать base64
            if '@' in url:
                encoded, server = url.split('@', 1)
                decoded = decode_b64_if_valid(encoded)
                if decoded and ':' in decoded:
                    method, password = decoded.split(':', 1)
                else:
                    method, password = "chacha20-ietf-poly1305", "password"
            else:
                decoded = decode_b64_if_valid(url)
                if decoded and '@' in decoded:
                    auth, server = decoded.split('@', 1)
                    if ':' in auth:
                        method, password = auth.split(':', 1)
                    else:
                        method, password = "chacha20-ietf-poly1305", "password"
                else:
                    return None

            if ':' in server:
                host, port = server.split(':', 1)
                port = int(port)
            else:
                host, port = server, 8388

            return Profile(
                protocol='shadowsocks',
                host=host,
                port=port,
                comment=comment if comment else f"Shadowsocks {host}:{port}",
                raw_url=f"ss://***@{host}:{port}",
                extra={'method': method, 'password': password}
            )

        except Exception as e:
            print(f"⚠ Ошибка парсинга Shadowsocks: {e}")
            return None

    @staticmethod
    def _parse_vmess(url: str) -> Optional[Profile]:
        """Парсит VMESS ссылку (заглушка)"""
        return None


class ProfileTester:
    """Тестирование профилей"""

    @staticmethod
    def test_real_connection(profile: Profile, timeout: int = 1, instance = None, proxy_port: int = 3128) -> Tuple[bool, Optional[int]]:
        # Запускаем профиль
        instance.setup_singbox(profile, proxy_mode=True, proxy_port=proxy_port);
        
        success = False
        latency = None
        response_content = None
        
        try:
            # Получаем URL и MD5 хеш из конфигурации клиента
            test_url = instance.config.testing.healthcheck_content_url
            expected_md5 = instance.config.testing.healthcheck_content_md5
            
            if not test_url or not expected_md5:
                print("Ошибка: не указаны URL или MD5 для проверки в конфигурации")
                return False, None
            
            print(f"Тестирование соединения с URL: {test_url}")
            
            # Замеряем время выполнения запроса
            start_time = time.time()
            
            # Выполняем HTTPS запрос с таймаутом
            response = requests.get(
                test_url, 
                timeout=timeout,
                verify=True,
                proxies=dict(http='socks5://localhost:{proxy_port}')
            )
            
            # Рассчитываем latency (задержку)
            end_time = time.time()
            latency = round((end_time - start_time) * 1000)  # в миллисекундах
            
            print(f"HTTP статус: {response.status_code}")
            print(f"Latency: {latency} ms")
            
            # Проверяем статус код
            if response.status_code == 200:
                response_content = response.text
                
                # Вычисляем MD5 хеш полученного содержимого
                content_md5 = hashlib.md5(response_content.encode('utf-8')).hexdigest()
                print(f"Ожидаемый MD5: {expected_md5}")
                print(f"Полученный MD5: {content_md5}")
                
                # Сравниваем хеши
                if content_md5 == expected_md5:
                    success = True
                    print("Проверка пройдена: содержимое совпадает!")
                else:
                    print("Ошибка: содержимое не совпадает с ожидаемым!")
            else:
                print(f"Ошибка: HTTP статус {response.status_code}")
                
        except RequestException as e:
            print(f"Ошибка соединения: {str(e)}")
        except Exception as e:
            print(f"Неожиданная ошибка: {str(e)}")
        
        # Останавливаем профиль
        if instance.singbox_manager:
            instance.singbox_manager.stop()
        
        # Возвращаем результат и latency
        if success:
            print(f"Проверка успешно завершена. Latency: {latency} ms")
            return True, latency
        else:
            return False, latency

    @staticmethod
    def test_tcp_connection(profile: Profile, timeout: int = 1) -> Tuple[bool, Optional[int]]:
        """Простая проверка TCP подключения"""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((profile.host, profile.port))
            sock.close()

            latency = int((time.time() - start_time) * 1000)

            if result == 0:
                return True, latency
            else:
                return False, None

        except Exception:
            return False, None

    @staticmethod
    def test_profiles(profiles: List[Profile], max_test: int = 100, timeout: int = 1, test_real: bool = False, instance = None) -> List[Profile]:
        """
        Тестирует профили и возвращает отсортированные по латентности
        """
        print(f"\n🔍 Тестирую {min(len(profiles), max_test)} профилей...")

        tested_profiles = []

        for idx, profile in enumerate(profiles[:max_test]):
            print(f"  [{idx+1:2d}] {profile.host}:{profile.port} ({profile.protocol.upper()})...", end=" ", flush=True)

            # 1. Проверка TCP коннекта
            success, latency = ProfileTester.test_tcp_connection(profile, timeout)
            if success and test_real and instance:
                success, latency = ProfileTester.test_real_connection(profile, timeout, instance)

            profile.is_working = success
            profile.latency = latency
            profile.last_tested = time.time()

            if success:
                print(f"✓ {latency}ms")
                tested_profiles.append(profile)
            else:
                print(f"✗ недоступен")

            time.sleep(0.05)  # Минимальная пауза

        # Сортируем по латентности
        tested_profiles.sort(key=lambda p: p.latency or 9999)

        # Статистика
        print(f"\n📊 Результаты: {len(tested_profiles)}/{min(len(profiles), max_test)} доступны")

        return tested_profiles


class ProfileManager:
    """Менеджер профилей с автообновлением"""

    def __init__(self, cache_dir: str = None, use_cache: bool = True):
        self.profiles: List[Profile] = []
        self.working_profiles: List[Profile] = []
        self.selected_profile: Optional[Profile] = None
        self._lock = threading.Lock()
        self._loader = ProfileLoader(cache_dir, use_cache)
        self._refresh_thread: Optional[threading.Thread] = None
        self._running = False
        self._sources = []
        self._refresh_callback: Optional[callable] = None

    def load_profiles_from_sources(self, sources: List, use_cache_fallback: bool = True) -> int:
        """
        Загружает профили из источников с поддержкой кеша

        Args:
            sources: Список источников
            use_cache_fallback: Использовать кеш при недоступности источника
        """
        raw_profiles = []

        for source in sources:
            if not source.enabled:
                continue

            raw_urls = self._loader.load_from_url(
                source.url,
                source.filter,
                use_cache_fallback
            )
            raw_profiles.extend(raw_urls)

        # Парсим профили
        with self._lock:
            self.profiles.clear()
            for raw_url in raw_profiles:
                profile = ProfileParser.parse_proxy_url(raw_url)
                if profile:
                    self.profiles.append(profile)

        print(f"\n✓ Всего распарсено профилей: {len(self.profiles)}")
        return len(self.profiles)

    def start_auto_refresh(self, sources: List, refresh_interval: int, on_refresh_callback: callable = None):
        """
        Запускает автоматическое обновление профилей

        Args:
            sources: Список источников
            refresh_interval: Интервал обновления в секундах
            on_refresh_callback: Callback вызываемый после обновления
        """
        if self._running:
            print("⚠ Автообновление уже запущено")
            return

        self._sources = sources
        self._refresh_callback = on_refresh_callback
        self._running = True

        def refresh_loop():
            print(f"✓ Автообновление профилей запущено (интервал: {refresh_interval}s)")

            while self._running:
                time.sleep(refresh_interval)

                if not self._running:
                    break

                print("\n" + "="*80)
                print(f"🔄 АВТООБНОВЛЕНИЕ ПРОФИЛЕЙ")
                print("="*80)

                try:
                    # Загружаем свежие профили (без fallback на кеш)
                    count = self.load_profiles_from_sources(self._sources, use_cache_fallback=False)

                    if count > 0:
                        print(f"✅ Профили обновлены: {count} шт.")

                        # Вызываем callback если есть
                        if self._refresh_callback:
                            try:
                                self._refresh_callback()
                            except Exception as e:
                                print(f"⚠ Ошибка в callback обновления: {e}")
                    else:
                        print("⚠ Не удалось загрузить новые профили, используем старые")

                except Exception as e:
                    print(f"❌ Ошибка автообновления: {e}")

        self._refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
        self._refresh_thread.start()

    def stop_auto_refresh(self):
        """Останавливает автообновление"""
        self._running = False
        if self._refresh_thread:
            self._refresh_thread.join(timeout=5)
        print("✓ Автообновление профилей остановлено")

    def test_and_select_best(self, max_test: int = 100, timeout: int = 1, min_latency: int = 500, test_real: bool = False, instance = None) -> Optional[Profile]:
        """
        Тестирует профили и выбирает лучший
        """
        with self._lock:
            profiles_to_test = self.profiles.copy()

        self.working_profiles = ProfileTester.test_profiles(profiles_to_test, max_test, timeout, test_real, instance)

        if not self.working_profiles:
            print("❌ Нет рабочих профилей!")
            return None

        # Выбираем лучший профиль
        best = self.working_profiles[0]

        if best.latency and best.latency <= min_latency:
            print(f"\n✅ Выбран профиль: {best.comment}")
            print(f"   {best.protocol.upper()} {best.host}:{best.port} [{best.latency}ms]")
        else:
            print(f"\n⚠ Выбран профиль с высокой задержкой: {best.comment}")
            print(f"   {best.protocol.upper()} {best.host}:{best.port} [{best.latency}ms]")

        with self._lock:
            self.selected_profile = best

        return best

    def get_selected_profile(self) -> Optional[Profile]:
        """Возвращает текущий выбранный профиль"""
        with self._lock:
            return self.selected_profile

    def get_backup_profiles(self, count: int = 3) -> List[Profile]:
        """Возвращает резервные профили"""
        with self._lock:
            # Исключаем текущий выбранный профиль
            backups = [p for p in self.working_profiles if p != self.selected_profile]
            return backups[:count]
