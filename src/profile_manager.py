import asyncio
import hashlib
import json
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable
from urllib.parse import parse_qs, unquote

import requests
import urllib3
from requests.exceptions import RequestException

from logger import get_logger
from utils import decode_b64_if_valid


# Disabling warnings about unverified certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class Profile:
    """Proxy Profile"""

    protocol: str
    host: str
    port: int
    comment: str
    raw_url: str
    extra: Dict = field(default_factory=dict)
    # Test results
    latency: Optional[int] = None
    last_tested: Optional[float] = None
    is_working: bool = False


class ProfileCache:
    """Profile's cache"""

    def __init__(self, cache_dir: Optional[str] = None):
        self.logger = get_logger(__name__)
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / ".cache" / "wintermute" / "profiles"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, url: str) -> Path:
        """Generates the cache path for the URL"""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return self.cache_dir / f"profiles_{url_hash}.json"

    def save(self, url: str, profiles: List[str]) -> bool:
        """Saves profiles to the cache"""
        try:
            cache_path = self._get_cache_path(url)
            cache_data = {"url": url, "timestamp": time.time(), "profiles": profiles}
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"   unable to save profile's cache: {e}")
            return False

    def load(self, url: str, max_age: Optional[int] = None) -> Optional[List[str]]:
        """
        Loads profiles from the cache

        Args:
            url: The URL of the source
            max_age: The maximum age of the cache in seconds (None = any age)
        """
        try:
            cache_path = self._get_cache_path(url)
            if not cache_path.exists():
                return None

            with open(cache_path, "r", encoding="utf-8") as f:
                cache_data = json.load(f)

            # Проверяем возраст кеша
            if max_age is not None:
                age = time.time() - cache_data.get("timestamp", 0)
                if age > max_age:
                    self.logger.info(f"   Cache outdated: {int(age)}s)")
                    return None

            profiles = cache_data.get("profiles", [])
            cache_age = int(time.time() - cache_data.get("timestamp", 0))
            self.logger.info(
                f"   Loaded from cache: {len(profiles)} profiles (age: {cache_age}s)"
            )
            return profiles

        except Exception as e:
            self.logger.error(f"   Cache read error: {e}")
            return None

    def get_age(self, url: str) -> Optional[int]:
        """Returns the age of the cache in seconds"""
        ts = self.get_timestamp(url)
        if ts is None:
            return None
        return int(time.time() - ts)

    def get_timestamp(self, url: str) -> Optional[float]:
        """Returns the timestamp of the cache"""
        try:
            cache_path = self._get_cache_path(url)
            if not cache_path.exists():
                return None

            with open(cache_path, "r", encoding="utf-8") as f:
                cache_data = json.load(f)

            return cache_data.get("timestamp")
        except Exception as e:
            self.logger.warning(f"get_timestamp general error: {e}")
            return None


class ProfileLoader:
    """Loader of profiles from sources"""

    def __init__(self, cache_dir: Optional[str] = None, use_cache: bool = True):
        self.cache = ProfileCache(cache_dir) if use_cache else None
        self.logger = get_logger(__name__)

    def load_from_url(
        self, url: str, profile_filter: str = "", use_cache_fallback: bool = True
    ) -> List[str]:
        """
        Loads profiles from URLs with caching support

        Args:
             url: The URL of the source
             profile_filter: Profile filter
             use_cache_fallback: Use the cache when the source is unavailable
        """
        self.logger.debug(f"Loading profiles from: {url}")

        profiles = []

        try:
            response = requests.get(url, timeout=10, verify=False)
            response.raise_for_status()
            content = response.text.strip()

            # Trying to decode base64
            decoded = decode_b64_if_valid(content)
            if decoded:
                self.logger.debug("  decoded from base64")
                content = decoded

            # Split into lines
            raw_lines = content.split("\n")

            # Filtering profiles
            for line in raw_lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Default filter - profiles with "Bypass" in the name
                    if not profile_filter or profile_filter in line:
                        profiles.append(line)

            self.logger.debug(f"URL: {url}:")
            self.logger.debug(f"   Profiles found: {len(profiles)}")

            # Save cache
            if self.cache and profiles:
                self.cache.save(url, profiles)
                self.logger.debug("   Profiles saved into cache")

            return profiles

        except Exception as e:
            self.logger.error(f"   Profile loading failure, fallback to cache: {e}")

            # Fallback на кеш при ошибке
            if use_cache_fallback and self.cache:
                cached = self.cache.load(
                    url, max_age=None
                )  # Любой возраст при fallback
                if cached:
                    self.logger.info("   Using cached profiles")
                    return cached

            return []


class ProfileParser:
    """Parser profiles of different protocols"""

    @staticmethod
    def parse_proxy_url(url: str) -> Optional[Profile]:
        """Defines the proxy type and parses the link"""
        if url.startswith("vless://"):
            return ProfileParser._parse_vless(url)
        elif url.startswith("ss://"):
            return ProfileParser._parse_shadowsocks(url)
        elif url.startswith("vmess://"):
            return ProfileParser._parse_vmess(url)
        else:
            return None

    @staticmethod
    def _parse_vless(url: str) -> Optional[Profile]:
        """VLESS"""
        if not url.startswith("vless://"):
            return None

        url = url[8:]

        try:
            if "@" not in url:
                return None

            uuid_part, rest = url.split("@", 1)

            server_part = rest
            query_str = ""
            fragment = ""

            if "?" in rest:
                server_part, query_part = rest.split("?", 1)
                if "#" in query_part:
                    query_str, fragment = query_part.split("#", 1)
                else:
                    query_str = query_part
            elif "#" in rest:
                server_part, fragment = rest.split("#", 1)

            if ":" in server_part:
                host_port_part = server_part
                if "/" in host_port_part:
                    host_port_part = host_port_part.split("/")[0]
                host, port = host_port_part.split(":", 1)
                port = int(port)
            else:
                host = server_part
                port = 443

            params = parse_qs(query_str)

            extra = {
                "uuid": uuid_part,
                "type": params.get("type", ["tcp"])[0],
                "security": params.get("security", ["none"])[0],
                "flow": params.get("flow", [""])[0],
                "packet_encoding": params.get("packetEncoding", ["xudp"])[0],
            }

            # Transport parameters
            if extra["type"] == "grpc":
                extra["service_name"] = params.get("serviceName", ["grpc"])[0]
                extra["mode"] = params.get("mode", ["gun"])[0]
            elif extra["type"] == "ws":
                extra["path"] = params.get("path", ["/"])[0]
                extra["ws_host"] = params.get("host", [""])[0]
            elif extra["type"] == "http":
                extra["path"] = params.get("path", ["/"])[0]
                extra["http_host"] = params.get("host", [""])[0]
            elif extra["type"] == "xhttp":
                extra["path"] = params.get("path", ["/"])[0]
                extra["host"] = params.get("host", [""])[0]
                extra["mode"] = params.get("mode", ["auto"])[0]
                extra["extra"] = params.get("extra", [""])[0]

            # TLS/Reality
            if extra["security"] in ["tls", "reality"]:
                extra["sni"] = params.get("sni", [""])[0]
                extra["fp"] = params.get("fp", ["chrome"])[0]

                if extra["security"] == "reality":
                    extra["pbk"] = params.get("pbk", [""])[0]
                    extra["sid"] = params.get("sid", [""])[0]
                    extra["spx"] = params.get("spx", ["/"])[0]

            comment = unquote(fragment) if fragment else f"VLESS {host}:{port}"

            return Profile(
                protocol="vless",
                host=host,
                port=port,
                comment=comment,
                raw_url=f"vless://{uuid_part}@{host}:{port}",
                extra=extra,
            )

        except Exception as e:
            logger = get_logger(__name__)
            logger.error(f"VLESS profile parse error: {e}")
            return None

    @staticmethod
    def _parse_shadowsocks(url: str) -> Optional[Profile]:
        """Parses the Shadowsocks link"""
        if not url.startswith("ss://"):
            return None

        url = url[5:]

        try:
            if "#" in url:
                url, fragment = url.split("#", 1)
                comment = unquote(fragment)
            else:
                comment = ""

            # Decode base64
            if "@" in url:
                encoded, server = url.split("@", 1)
                decoded = decode_b64_if_valid(encoded)
                if decoded and ":" in decoded:
                    method, password = decoded.split(":", 1)
                else:
                    method, password = "chacha20-ietf-poly1305", "password"
            else:
                decoded = decode_b64_if_valid(url)
                if decoded and "@" in decoded:
                    auth, server = decoded.split("@", 1)
                    if ":" in auth:
                        method, password = auth.split(":", 1)
                    else:
                        method, password = "chacha20-ietf-poly1305", "password"
                else:
                    return None

            if ":" in server:
                host, port = server.split(":", 1)
                port = int(port)
            else:
                host, port = server, 8388

            return Profile(
                protocol="shadowsocks",
                host=host,
                port=port,
                comment=comment if comment else f"Shadowsocks {host}:{port}",
                raw_url=f"ss://***@{host}:{port}",
                extra={"method": method, "password": password},
            )

        except Exception as e:
            logger = get_logger(__name__)
            logger.error(f"ShadowSocks profile parse error: {e}")
            return None

    @staticmethod
    def _parse_vmess(url: str) -> Optional[Profile]:
        """Parses VMESS link (stub)"""
        return None


class ProfileTester:
    """Testing profiles"""

    STARTING_PORT = 30000

    @staticmethod
    def test_real_connection(
        profile: Profile,
        timeout: int = 1,
        proxy_port: int = 3128,
        config: str = "config.yaml",
    ) -> Tuple[bool, Optional[int]]:
        from wintermute import Wintermute

        logger = get_logger(__name__)

        client = Wintermute(test_mode=True, config_path=config)
        client.setup_singbox(profile, proxy_mode=True, proxy_port=proxy_port)

        # Wait for sing-box to start (setup_singbox already has 2s sleep)
        time.sleep(1)

        success = False
        latency = None
        response_content = None

        try:
            test_url = client.config.testing.healthcheck_content_url
            expected_md5 = client.config.testing.healthcheck_content_md5

            if not test_url or not expected_md5:
                logger.error("Configuration error: no URL or MD5")
                return False, None

            logger.debug(f"Test connection for profile {profile.comment}")

            start_time = time.time()

            # Run HTTP request with timeout
            response = requests.get(
                test_url,
                timeout=timeout,
                verify=True,
                headers={"User-Agent": "Mozilla/5.0"},
                proxies=dict(
                    http=f"socks5h://127.0.0.1:{proxy_port}",
                    https=f"socks5h://127.0.0.1:{proxy_port}",
                ),
            )

            # Calculate latency
            end_time = time.time()
            latency = round((end_time - start_time) * 1000)  # ms

            logger.debug(f"HTTP статус: {response.status_code}")
            logger.debug(f"Latency: {latency} ms")

            # check code
            if response.status_code == 200:
                response_content = response.text

                content_md5 = hashlib.md5(response_content.encode("utf-8")).hexdigest()

                # check hashes
                if content_md5 == expected_md5:
                    success = True
                    logger.debug("SUCCESS: Hash matches")
                else:
                    logger.debug("FAILURE: Hash mismatches")
            else:
                logger.debug(f"HTTP code {response.status_code}")

        except RequestException as e:
            logger.debug(f"Connection error: {str(e)}")
        except Exception as e:
            logger.debug(f"Unexpected error: {str(e)}")

        # Stop Sing-Box
        if client.singbox_manager:
            client.singbox_manager.stop()
            del client

        # Return result and latency
        if success:
            return True, latency
        else:
            return False, latency

    @staticmethod
    def test_tcp_connection(
        profile: Profile, timeout: int = 1
    ) -> Tuple[bool, Optional[int]]:
        """Simple TCP connection check"""
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
    async def _test_single_profile(
        profile: Profile,
        idx: int,
        timeout: int,
        test_real: bool,
        proxy_port: int,
        config: str = "config.yaml",
    ) -> Optional[Profile]:
        """Asynchronous testing of a single profile"""
        logger = get_logger(__name__)
        logger.debug(
            f"[{idx+1:2d}] {profile.host}:{profile.port} ({profile.protocol.upper()})..."
        )

        # Running blocking operations in executor
        loop = asyncio.get_event_loop()

        # 1. Checking the TCP connection
        success, latency = await loop.run_in_executor(
            None, ProfileTester.test_tcp_connection, profile, timeout
        )

        # 2. If TCP has passed and a real check is needed
        if success and test_real:
            success, latency = await loop.run_in_executor(
                None,
                ProfileTester.test_real_connection,
                profile,
                timeout,
                proxy_port,
                config,
            )

        profile.is_working = success
        profile.latency = latency
        profile.last_tested = time.time()

        if success:
            logger.debug(f"Profile {profile.comment} result is {latency}ms")
            return profile
        else:
            logger.debug(f"Profile {profile.comment} not available")
            return None

    @staticmethod
    async def _test_profiles_async(
        profiles: List[Profile],
        max_test: int,
        timeout: int,
        test_real: bool,
        config: str = "config.yaml",
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> List[Profile]:
        """Asynchronous profile testing"""
        logger = get_logger(__name__)
        total_to_test = min(len(profiles), max_test)
        logger.info(f"Testing {total_to_test} profiles...")

        # Creating tasks for parallel testing
        tasks = []
        for idx, profile in enumerate(profiles[:max_test]):
            proxy_port = ProfileTester.STARTING_PORT + idx
            task = ProfileTester._test_single_profile(
                profile, idx, timeout, test_real, proxy_port, config
            )
            tasks.append(task)

        # Running tasks and reporting progress
        results = []
        completed = 0

        if on_progress:
            on_progress(0, total_to_test)

        for coro in asyncio.as_completed(tasks):
            res = await coro
            results.append(res)
            completed += 1
            if res:
                logger.info(f"   [{completed}/{total_to_test}] Profile {res.comment or res.host} ({res.host}) OK ({res.latency}ms)")
            else:
                logger.debug(f"   [{completed}/{total_to_test}] Profile test failed")

            if on_progress:
                on_progress(completed, total_to_test)

        # Filtering successful profiles
        tested_profiles = [p for p in results if p is not None]

        # Sort by latency
        tested_profiles.sort(key=lambda p: p.latency or 9999)

        # Statistic
        logger.info(
            f"Test results: {len(tested_profiles)}/{min(len(profiles), max_test)} profiles available"
        )

        return tested_profiles

    @staticmethod
    def test_profiles(
        profiles: List[Profile],
        max_test: int = 100,
        timeout: int = 1,
        test_real: bool = False,
        config: str = "config.yaml",
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> List[Profile]:
        """
        Tests profiles and returns sorted by latency
        Wrapper for asynchronous testing
        """
        return asyncio.run(
            ProfileTester._test_profiles_async(
                profiles, max_test, timeout, test_real, config, on_progress
            )
        )


class ProfileManager:
    """Profile Manager with auto-update"""

    def __init__(
        self, cache_dir: str, use_cache: bool = True, config: str = "config.yaml"
    ):
        self.profiles: List[Profile] = []
        self.working_profiles: List[Profile] = []
        self.selected_profile: Optional[Profile] = None
        self._lock = threading.Lock()
        self._loader = ProfileLoader(cache_dir, use_cache)
        self._refresh_thread: Optional[threading.Thread] = None
        self._running = False
        self._sources = []
        self._refresh_callback: Optional[Callable] = None
        self.config = config
        self.logger = get_logger(__name__)

    def load_profiles_from_sources(
        self, sources: List, use_cache_fallback: bool = True
    ) -> int:
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
                source.url, source.filter, use_cache_fallback
            )
            raw_profiles.extend(raw_urls)

        # Parse profiles
        with self._lock:
            self.profiles.clear()
            for raw_url in raw_profiles:
                profile = ProfileParser.parse_proxy_url(raw_url)
                if profile:
                    self.profiles.append(profile)

        self.logger.info(f"Loaded {len(self.profiles)} profiles total")
        return len(self.profiles)

    def start_auto_refresh(
        self, sources: List, refresh_interval: int, on_refresh_callback: callable = None
    ):
        """
        Запускает автоматическое обновление профилей

        Args:
            sources: Список источников
            refresh_interval: Интервал обновления в секундах
            on_refresh_callback: Callback вызываемый после обновления
        """
        if self._running:
            self.logger.warning("Auto refresh already running")
            return

        self._sources = sources
        self._refresh_callback = on_refresh_callback
        self._running = True

        def refresh_loop():
            self.logger.info(
                f"Profile auto refresh started (interval: {refresh_interval})"
            )

            while self._running:
                time.sleep(refresh_interval)

                if not self._running:
                    break

                try:
                    count = self.load_profiles_from_sources(
                        self._sources, use_cache_fallback=False
                    )

                    if count > 0:
                        self.logger.info(f"Updated {count} profiles")

                        # Run callback
                        if self._refresh_callback:
                            try:
                                self._refresh_callback()
                            except Exception as e:
                                self.logger.error(f"Callback error: {e}")
                    else:
                        self.logger.warning("Unable to load profiles")

                except Exception as e:
                    self.logger.error(f"Auto update error: {e}")

        self._refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
        self._refresh_thread.start()

    def stop_auto_refresh(self):
        """Stops auto-updating"""
        self._running = False
        if self._refresh_thread:
            self._refresh_thread.join(timeout=5)
        self.logger.debug("Auto update stopped")

    def get_last_update_time(self, url: str) -> Optional[float]:
        """Returns last update timestamp for URL"""
        if self._loader.cache:
            return self._loader.cache.get_timestamp(url)
        return None

    def test_and_select_best(
        self,
        max_test: int = 100,
        timeout: int = 1,
        min_latency: int = 500,
        test_real: bool = False,
        prefer_xray: bool = False,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> Optional[Profile]:
        """
        Tests profiles and selects the best one
        """
        with self._lock:
            profiles_to_test = self.profiles.copy()

        self.working_profiles = ProfileTester.test_profiles(
            profiles_to_test, max_test, timeout, test_real, self.config, on_progress
        )

        if not self.working_profiles:
            self.logger.error("NO WORKING PROFILES FOUND")
            return None

        # Pick the best one
        # self.working_profiles is already sorted by latency from ProfileTester.test_profiles
        best = self.working_profiles[0]

        if prefer_xray:
            # Look for first xray-compatible profile (type=xhttp)
            for p in self.working_profiles:
                if p.extra.get("type") == "xhttp":
                    best = p
                    break


        if best.latency and best.latency <= min_latency:
            self.logger.info("Profile picked")
            self.logger.info(f"   {best.comment}")
            self.logger.info(
                f"   {best.protocol.upper()} {best.host}:{best.port} [{best.latency}ms]"
            )
        else:
            self.logger.warning("High latency profile selected (still the best one):")
            self.logger.info(f"   {best.comment}")
            self.logger.info(
                f"   {best.protocol.upper()} {best.host}:{best.port} [{best.latency}ms]"
            )

        with self._lock:
            self.selected_profile = best

        return best

    def get_selected_profile(self) -> Optional[Profile]:
        """Returns the currently selected profile"""
        with self._lock:
            return self.selected_profile

    def get_backup_profiles(self, count: int = 3) -> List[Profile]:
        """Returns backup profiles"""
        with self._lock:
            # Exclude the currently selected profile
            backups = [p for p in self.working_profiles if p != self.selected_profile]
            return backups[:count]
