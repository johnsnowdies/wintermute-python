import asyncio
import hashlib
import json
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable, Set
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

            # Check cache age
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

    # ── hpwnr helpers ────────────────────────────────────────────────────

    @staticmethod
    def _find_hpwnr() -> Optional[str]:
        import shutil
        return shutil.which("hpwnr")

    def _decrypt_happ(self, url: str) -> Optional[str]:
        """Decrypt a happ://crypt* link via hpwnr → plaintext."""
        hpwnr_bin = self._find_hpwnr()
        if not hpwnr_bin:
            self.logger.warning(
                "hpwnr not found — install: cargo install hpwnr"
            )
            return None
        try:
            result = subprocess.run(
                [hpwnr_bin, url],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                self.logger.error(f"hpwnr exited {result.returncode}: {result.stderr.strip()}")
                return None
            out = result.stdout.strip()
            return out if out else None
        except Exception as e:
            self.logger.error(f"hpwnr error for {url[:60]}…: {e}")
            return None

    def _convert_json_to_uris(self, content: str) -> Optional[str]:
        """
        If content looks like a JSON array of Xray configs, pipe it through
        hpwnr uri to convert each outbound to a vless:// URI.
        """
        text = content.strip()
        if not text.startswith("["):
            # Maybe it's base64-wrapped JSON
            decoded = decode_b64_if_valid(text)
            if decoded and decoded.strip().startswith("["):
                text = decoded
            else:
                return None

        hpwnr_bin = self._find_hpwnr()
        if not hpwnr_bin:
            return None

        try:
            result = subprocess.run(
                [hpwnr_bin, "uri"],
                input=text,
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                self.logger.warning(f"hpwnr uri conversion failed: {result.stderr.strip()}")
                return None
            out = result.stdout.strip()
            return out if out else None
        except Exception as e:
            self.logger.error(f"hpwnr uri conversion error: {e}")
            return None

    def _fetch_url(self, url: str) -> Optional[str]:
        """Fetch a plain HTTP(S) subscription URL, base64-decode if needed."""
        try:
            response = requests.get(url, timeout=10, verify=False)
            response.raise_for_status()
            content = response.text.strip()
            decoded = decode_b64_if_valid(content)
            if decoded:
                content = decoded
            return content
        except Exception as e:
            self.logger.error(f"  Fetch failed for {url}: {e}")
            return None

    def load_from_url(
        self, url: str, profile_filter: str = "", use_cache_fallback: bool = True
    ) -> List[str]:
        """
        Loads profiles from URLs with caching support.

        Supports:
          - https:// … plain / base64 subscription (existing)
          - happ://crypt* … decrypted via hpwnr, follows nesting,
                             converts Xray JSON to VLESS URIs

        Args:
             url: The URL of the source
             profile_filter: Profile filter
             use_cache_fallback: Use the cache when the source is unavailable
        """
        self.logger.debug(f"Loading profiles from: {url}")

        # ── Resolve content ──────────────────────────────────────────────
        content: Optional[str] = None
        is_happ_source = url.startswith("happ://")

        if is_happ_source:
            self.logger.info("  Detected Happ-encrypted source, decrypting…")
            plain = self._decrypt_happ(url)
            if plain:
                # Happ links often decrypt to a nested HTTPS subscription URL
                if plain.startswith("http://") or plain.startswith("https://"):
                    self.logger.info(f"  ↳ nested subscription: {plain[:80]}…")
                    fetched = self._fetch_url(plain)
                    if fetched:
                        # Maybe JSON → convert to VLESS URIs
                        converted = self._convert_json_to_uris(fetched)
                        content = converted or fetched
                    else:
                        content = plain
                else:
                    content = plain
            else:
                self.logger.error("  Happ decryption failed")
        else:
            # Regular URL: fetch + base64-decode
            fetched = self._fetch_url(url)
            if fetched:
                # Also try JSON conversion for non-Happ sources that serve JSON
                converted = self._convert_json_to_uris(fetched)
                content = converted or fetched

        if content is None:
            # Fallback to cache
            if use_cache_fallback and self.cache:
                cached = self.cache.load(url, max_age=None)
                if cached:
                    self.logger.info("   Using cached profiles")
                    return cached
            return []

        # ── Parse lines (decrypt happ:// lines, pass through vless:// etc.) ──
        profiles: List[str] = []
        raw_lines = content.split("\n")
        for line in raw_lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if profile_filter and profile_filter not in line:
                continue

            if line.startswith("happ://"):
                # Decrypt Happ-encrypted profile line via hpwnr
                self.logger.info(f"  Decrypting inline Happ URL: {line[:60]}…")
                decrypted = self._decrypt_happ(line)
                if decrypted:
                    # decrypted might be a nested subscription URL or vless:// directly
                    if decrypted.startswith("http://") or decrypted.startswith("https://"):
                        self.logger.info(f"    ↳ nested URL, fetching …")
                        nested = self._fetch_url(decrypted)
                        if nested:
                            # Try JSON conversion or use as-is
                            converted = self._convert_json_to_uris(nested)
                            final = converted or nested
                            for subline in final.split("\n"):
                                subline = subline.strip()
                                if subline and not subline.startswith("#"):
                                    profiles.append(subline)
                    else:
                        # vless:// URI(s) directly
                        for subline in decrypted.split("\n"):
                            subline = subline.strip()
                            if subline:
                                profiles.append(subline)
                else:
                    self.logger.warning(f"    hpwnr failed for {line[:60]}…")
            else:
                # Regular vless://, ss://, trojan:// etc.
                profiles.append(line)

        self.logger.debug(f"   Profiles found: {len(profiles)}")

        # Save cache
        if self.cache and profiles:
            self.cache.save(url, profiles)
            self.logger.debug("   Profiles saved into cache")

        return profiles


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
    MAX_CONCURRENT = 20  # Limit concurrent TCP/proxy tests to avoid FD exhaustion

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
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> Optional[Profile]:
        """Asynchronous testing of a single profile"""
        if semaphore:
            async with semaphore:
                return await ProfileTester._do_test_profile(
                    profile, idx, timeout, test_real, proxy_port, config
                )
        return await ProfileTester._do_test_profile(
            profile, idx, timeout, test_real, proxy_port, config
        )

    @staticmethod
    async def _do_test_profile(
        profile: Profile,
        idx: int,
        timeout: int,
        test_real: bool,
        proxy_port: int,
        config: str = "config.yaml",
    ) -> Optional[Profile]:
        """Internal: run a single profile test (no semaphore)."""
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

        semaphore = asyncio.Semaphore(ProfileTester.MAX_CONCURRENT)

        # Creating tasks for parallel testing
        tasks = []
        for idx, profile in enumerate(profiles[:max_test]):
            proxy_port = ProfileTester.STARTING_PORT + idx
            task = ProfileTester._test_single_profile(
                profile, idx, timeout, test_real, proxy_port, config, semaphore
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
                protocol_char = "X" if res.extra.get("type") == "xhttp" else "S"
                logger.info(f"   [{completed}/{total_to_test}] {protocol_char} Profile {res.comment or res.host} ({res.host}) OK ({res.latency}ms)")
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
        self.broken_profiles: Set[str] = set()  # Store raw_url of broken profiles
        self._lock = threading.Lock()
        self._loader = ProfileLoader(cache_dir, use_cache)
        self._refresh_thread: Optional[threading.Thread] = None
        self._running = False
        self._sources = []
        self._refresh_callback: Optional[Callable] = None
        self.config = config
        self.logger = get_logger(__name__)
        # Track if any loaded source was Happ-encrypted (for badge H)
        self._happ_source_seen: bool = False

    def load_profiles_from_sources(
        self, sources: List, use_cache_fallback: bool = True
    ) -> int:
        """
        Load profiles from sources with cache support

        Args:
            sources: List of source configurations
            use_cache_fallback: Use cache when source is unavailable
        """
        raw_profiles = []
        self._happ_source_seen = False

        for source in sources:
            if not source.enabled:
                continue

            if source.url.startswith("happ://"):
                self._happ_source_seen = True

            raw_urls = self._loader.load_from_url(
                source.url, source.filter, use_cache_fallback
            )
            raw_profiles.extend(raw_urls)

        count = self.set_profiles_from_raw(raw_profiles)

        # Mark profiles from Happ sources with badge H
        if self._happ_source_seen:
            with self._lock:
                for p in self.profiles:
                    p.extra["source"] = "happ"

        return count

    def set_profiles_from_raw(self, raw_urls: List[str]) -> int:
        """Parse and set profiles from raw URLs"""
        with self._lock:
            self.profiles.clear()
            for raw_url in raw_urls:
                profile = ProfileParser.parse_proxy_url(raw_url)
                if profile:
                    self.profiles.append(profile)

        self.logger.info(f"Loaded {len(self.profiles)} profiles total")
        return len(self.profiles)

    def load_profiles_from_file(self, file_path: str) -> int:
        """Load profiles from a local JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            raw_urls = []
            if isinstance(data, list):
                raw_urls = data
            elif isinstance(data, dict) and "profiles" in data:
                raw_urls = data["profiles"]

            return self.set_profiles_from_raw(raw_urls)
        except Exception as e:
            self.logger.error(f"Error loading profiles from file {file_path}: {e}")
            return 0

    def start_auto_refresh(
        self, sources: List, refresh_interval: int, on_refresh_callback: callable = None
    ):
        """
        Start automatic profile refresh

        Args:
            sources: List of source configurations
            refresh_interval: Refresh interval in seconds
            on_refresh_callback: Callback invoked after refresh
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

    def mark_profile_as_broken(self, profile: Profile):
        """Marks a profile as broken in memory"""
        with self._lock:
            self.broken_profiles.add(profile.raw_url)

    def unmark_profile_as_broken(self, profile: Profile):
        """Removes a profile from broken list"""
        with self._lock:
            if profile.raw_url in self.broken_profiles:
                self.broken_profiles.remove(profile.raw_url)

    def clear_broken_profiles(self):
        """Clears the list of broken profiles"""
        with self._lock:
            self.broken_profiles.clear()
        self.logger.info("Broken profiles list cleared")

    def is_profile_broken(self, profile: Profile) -> bool:
        """Checks if a profile is marked as broken"""
        with self._lock:
            return profile.raw_url in self.broken_profiles

    @staticmethod
    def _pick_by_preferred_engine(
        profiles: List[Profile], engine: str
    ) -> Profile:
        """
        Pick the first profile matching the preferred_engine strategy.

        * "auto"    → lowest latency (profiles[0] — already sorted)
        * "xray"    → first xhttp profile, fallback to lowest latency
        * "singbox" → first non-xhttp profile, fallback to lowest latency
        * "happ"    → first Happ-sourced profile, fallback to lowest latency
        """
        if engine == "xray":
            for p in profiles:
                if p.extra.get("type") == "xhttp":
                    return p
        elif engine == "singbox":
            for p in profiles:
                if p.extra.get("type") != "xhttp":
                    return p
        elif engine == "happ":
            for p in profiles:
                if p.extra.get("source") == "happ":
                    return p
        # auto or fallback: already sorted by latency
        return profiles[0]

    def test_and_select_best(
        self,
        max_test: int = 100,
        timeout: int = 1,
        min_latency: int = 500,
        test_real: bool = False,
        preferred_engine: str = "auto",
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
        # Filter out broken profiles from selection
        with self._lock:
            available_profiles = [p for p in self.working_profiles if p.raw_url not in self.broken_profiles]

        if not available_profiles:
            self.logger.error("NO WORKING NON-BROKEN PROFILES FOUND")
            return None

        # self.working_profiles is already sorted by latency from ProfileTester.test_profiles
        # Apply preferred_engine selection strategy on top of latency sort
        best = ProfileManager._pick_by_preferred_engine(available_profiles, preferred_engine)

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
        """Returns backup profiles (excluding broken ones)"""
        with self._lock:
            # Exclude the currently selected profile and broken ones
            backups = [p for p in self.working_profiles
                       if p != self.selected_profile and p.raw_url not in self.broken_profiles]
            return backups[:count]
