import asyncio
import hashlib
import json
import random
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

from logger import get_logger
from utils import decode_b64_if_valid


# Браузерный User-Agent для всех HTTP-запросов (против DPI по User-Agent)
_BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"


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

    _MASKED_KEYS = {"password", "uuid"}  # эти поля не попадают в __repr__ / __str__

    def __repr__(self) -> str:
        safe = {k: v if k not in self._MASKED_KEYS else "***" for k, v in self.extra.items()}
        return (
            f"Profile({self.protocol}, {self.host}:{self.port}, "
            f"comment={self.comment!r}, extra={safe})"
        )


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

    def __init__(self, cache_dir: Optional[str] = None, use_cache: bool = True, verify_tls: bool = False):
        self.cache = ProfileCache(cache_dir) if use_cache else None
        self.verify_tls = verify_tls
        self.logger = get_logger(__name__)

    # ── hpwnr helpers ────────────────────────────────────────────────────

    @staticmethod
    def _find_hpwnr() -> Optional[str]:
        import shutil
        import os
        from pathlib import Path

        # 1. PATH (covers ~/.cargo/bin/ if sourced)
        which = shutil.which("hpwnr")
        if which:
            return which

        # 2. Same directory as this script
        script_dir = Path(__file__).parent.resolve()
        local = script_dir / "hpwnr"
        if local.exists() and os.access(local, os.X_OK):
            return str(local)

        # 3. Current working directory
        cwd = Path.cwd() / "hpwnr"
        if cwd.exists() and os.access(cwd, os.X_OK):
            return str(cwd)

        # 4. Common system paths for manually placed binaries
        for p in ["/usr/local/bin/hpwnr", "/usr/bin/hpwnr"]:
            if os.path.exists(p) and os.access(p, os.X_OK):
                return p

        return None

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

    @staticmethod
    def _xray_outbound_to_vless(ob: dict) -> Optional[str]:
        """Convert a single Xray outbound dict to a vless:// URI."""
        try:
            proto = ob.get("protocol", "")
            if proto != "vless":
                return None
            settings = ob.get("settings", {})
            vnext = settings.get("vnext", [{}])[0]
            user = vnext.get("users", [{}])[0]
            uuid = user.get("id", "")
            host = vnext.get("address", "")
            port = vnext.get("port", 443)
            if not uuid or not host:
                return None

            ss = ob.get("streamSettings", {})
            params = []

            net = ss.get("network", "tcp")
            params.append(f"encryption=none")
            params.append(f"type={net}")

            sec = ss.get("security", "none")
            if sec not in ("", "none"):
                params.append(f"security={sec}")

            # TLS / Reality settings
            tls = ss.get("tlsSettings", {}) or {}
            reality = ss.get("realitySettings", {}) or {}

            sni = tls.get("serverName") or reality.get("serverName", "")
            if sni:
                params.append(f"sni={sni}")

            fp = tls.get("fingerprint") or reality.get("fingerprint", "chrome")
            params.append(f"fp={fp}")

            if reality.get("publicKey"):
                params.append(f"pbk={reality['publicKey']}")
            if reality.get("shortId"):
                params.append(f"sid={reality['shortId']}")

            # Transport-specific params
            xhttp = ss.get("xhttpSettings", {}) or {}
            ws = ss.get("wsSettings", {}) or {}
            grpc = ss.get("grpcSettings", {}) or {}

            if net == "xhttp":
                path = xhttp.get("path", "/")
                params.append(f"path={path}")
                xhost = xhttp.get("host", sni)
                if xhost:
                    params.append(f"host={xhost}")
                mode = xhttp.get("mode", "auto")
                params.append(f"mode={mode}")
                extra = xhttp.get("extra", "")
                if extra and isinstance(extra, str):
                    params.append(f"extra={extra}")
            elif net == "ws":
                wpath = ws.get("path", "/")
                params.append(f"path={wpath}")
                whost = ws.get("host", "")
                if whost:
                    params.append(f"host={whost}")
            elif net == "grpc":
                svc = grpc.get("serviceName", "grpc")
                params.append(f"serviceName={svc}")

            qs = "&".join(params)
            remark = ob.get("tag", ob.get("remarks", f"{host}:{port}"))
            from urllib.parse import quote
            return f"vless://{uuid}@{host}:{port}?{qs}#{quote(remark) if remark else ''}"
        except Exception as e:
            logger = get_logger(__name__)
            logger.warning(f"Xray outbound→VLESS conversion error: {e}")
            return None

    def _convert_json_to_uris(self, content: str) -> Optional[str]:
        """
        Parse Xray JSON array subscription → list of vless:// URIs.
        Works directly without hpwnr (which drops critical fields like
        sni, path, host in its uri mode).
        """
        text = content.strip()
        if not text.startswith("["):
            decoded = decode_b64_if_valid(text)
            if decoded and decoded.strip().startswith("["):
                text = decoded
            else:
                return None

        try:
            entries = json.loads(text)
        except json.JSONDecodeError:
            return None

        if not isinstance(entries, list):
            return None

        uris = []
        for ent in entries:
            if not isinstance(ent, dict):
                continue
            # Try outbounds array first (new format)
            outbounds = ent.get("outbounds", [])
            if outbounds:
                for ob in outbounds:
                    uri = ProfileLoader._xray_outbound_to_vless(ob)
                    if uri:
                        uris.append(uri)
            else:
                # Try direct vless:// conversion from flat object
                ob = {"protocol": "vless", "settings": {"vnext": [{
                    "address": ent.get("address", ent.get("server", "")),
                    "port": ent.get("port", ent.get("server_port", 443)),
                    "users": [{"id": ent.get("id", "")}]
                }]}, "streamSettings": ent}
                uri = ProfileLoader._xray_outbound_to_vless(ob)
                if uri:
                    uris.append(uri)

        if uris:
            return "\n".join(uris)
        return None

    def _fetch_url(self, url: str, _depth: int = 0) -> Optional[str]:
        """
        Fetch a subscription URL.
        Редиректы обрабатываем вручную (макс. 5), чтобы перехватить happ://.
        """
        if _depth > 5:
            self.logger.error(f"  Redirect loop for {url}")
            return None
        try:
            response = requests.get(url, timeout=10, verify=self.verify_tls, allow_redirects=False,
                                    headers={"User-Agent": _BROWSER_UA})

            if response.is_redirect:
                location = response.headers.get("Location", "")
                if location.startswith("happ://"):
                    self.logger.info(f"  ↳ redirect to Happ URL")
                    return location
                if location.startswith(("http://", "https://")):
                    return self._fetch_url(location, _depth + 1)
                # Неизвестный редирект
                self.logger.error(f"  Unknown redirect to {location}")
                return None

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
        self, url: str, profile_filter: str = "", use_cache_fallback: bool = True,
        _happ_out: Optional[Set[str]] = None,
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
             _happ_out: If provided, raw URLs that came from Happ decryption
                        are added to this set (for badge marking).
        """
        self.logger.debug(f"Loading profiles from: {url}")

        # ── Resolve content ──────────────────────────────────────────────
        content: Optional[str] = None
        is_happ_source = url.startswith("happ://")
        _is_happ_redirect = False  # станет True, если HTTPS source редиректнул на happ://

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
                # Если сервер вернул happ:// (редирект) — декодируем через hpwnr
                if fetched.startswith("happ://"):
                    self.logger.info("  Source redirected to Happ, decrypting…")
                    _is_happ_redirect = True
                    decrypted = self._decrypt_happ(fetched)
                    if decrypted:
                        if decrypted.startswith("http://") or decrypted.startswith("https://"):
                            self.logger.info(f"  ↳ nested subscription: {decrypted[:80]}…")
                            nested = self._fetch_url(decrypted)
                            if nested:
                                converted = self._convert_json_to_uris(nested)
                                content = converted or nested
                            else:
                                content = decrypted
                        else:
                            content = decrypted
                    else:
                        self.logger.error("  Happ decryption failed for redirect target")
                else:
                    _is_happ_redirect = False
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
                                    if _happ_out is not None:
                                        _happ_out.add(subline)
                    else:
                        # vless:// URI(s) directly
                        for subline in decrypted.split("\n"):
                            subline = subline.strip()
                            if subline:
                                profiles.append(subline)
                                if _happ_out is not None:
                                    _happ_out.add(subline)
                else:
                    self.logger.warning(f"    hpwnr failed for {line[:60]}…")
            else:
                # Regular vless://, ss://, trojan:// etc.
                profiles.append(line)

        self.logger.debug(f"   Profiles found: {len(profiles)}")

        # If the source is Happ-encrypted (оригинал или редирект), отметить профили
        if _happ_out is not None and (is_happ_source or _is_happ_redirect):
            for p in profiles:
                _happ_out.add(p)

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
    def test_tcp_connection(
        profile: Profile, timeout: int = 1
    ) -> Tuple[bool, Optional[int]]:
        """Simple TCP connection check (единственный метод проверки)."""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((profile.host, profile.port))
            sock.close()
            latency = int((time.time() - start_time) * 1000)
            return (result == 0, latency if result == 0 else None)
        except Exception:
            return False, None

    @staticmethod
    async def _test_single_profile(
        profile: Profile,
        idx: int,
        timeout: int,
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> Optional[Profile]:
        """Тестирование одного профиля (asyncio)."""
        if semaphore:
            async with semaphore:
                return await ProfileTester._do_test_profile(profile, idx, timeout)
        return await ProfileTester._do_test_profile(profile, idx, timeout)

    @staticmethod
    async def _do_test_profile(
        profile: Profile, idx: int, timeout: int
    ) -> Optional[Profile]:
        logger = get_logger(__name__)
        logger.debug(f"[{idx+1:2d}] {profile.host}:{profile.port} ({profile.protocol.upper()})...")
        loop = asyncio.get_event_loop()
        success, latency = await loop.run_in_executor(
            None, ProfileTester.test_tcp_connection, profile, timeout
        )
        profile.is_working = success
        profile.latency = latency
        profile.last_tested = time.time()
        if success:
            logger.debug(f"Profile {profile.comment} result is {latency}ms")
            return profile
        return None

    @staticmethod
    async def _test_profiles_async(
        profiles: List[Profile],
        max_test: int,
        timeout: int,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> List[Profile]:
        logger = get_logger(__name__)
        total_to_test = min(len(profiles), max_test)
        logger.info(f"Testing {total_to_test} profiles...")
        semaphore = asyncio.Semaphore(ProfileTester.MAX_CONCURRENT)

        tasks = [
            ProfileTester._test_single_profile(p, i, timeout, semaphore)
            for i, p in enumerate(profiles[:max_test])
        ]

        results = []
        completed = 0
        if on_progress:
            on_progress(0, total_to_test)

        for coro in asyncio.as_completed(tasks):
            res = await coro
            results.append(res)
            completed += 1
            if res:
                ec = "X" if res.extra.get("type") == "xhttp" else "S"
                logger.info(f"   [{completed}/{total_to_test}] {ec} {res.comment or res.host} ({res.host}) OK ({res.latency}ms)")
            else:
                logger.debug(f"   [{completed}/{total_to_test}] FAILED")
            if on_progress:
                on_progress(completed, total_to_test)

        tested = [p for p in results if p is not None]
        tested.sort(key=lambda p: p.latency or 9999)
        logger.info(f"Test results: {len(tested)}/{min(len(profiles), max_test)} working")
        return tested

    @staticmethod
    def test_profiles(
        profiles: List[Profile],
        max_test: int = 100,
        timeout: int = 1,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> List[Profile]:
        return asyncio.run(
            ProfileTester._test_profiles_async(profiles, max_test, timeout, on_progress)
        )


class ProfileManager:
    """Profile Manager with auto-update"""

    def __init__(
        self, cache_dir: str, use_cache: bool = True, config: str = "config.yaml",
        verify_tls: bool = False,
    ):
        self.profiles: List[Profile] = []
        self.working_profiles: List[Profile] = []
        self.selected_profile: Optional[Profile] = None
        self.broken_profiles: Set[str] = set()     # raw_url сломанных
        self.happ_urls: Set[str] = set()            # raw_url пришедших из Happ-источников
        self._lock = threading.Lock()
        self._loader = ProfileLoader(cache_dir, use_cache, verify_tls)
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
        Load profiles from sources with cache support

        Args:
            sources: List of source configurations
            use_cache_fallback: Use cache when source is unavailable
        """
        raw_profiles = []
        happ_raw_urls: Set[str] = set()

        for source in sources:
            if not source.enabled:
                continue

            raw_urls = self._loader.load_from_url(
                source.url, source.filter, use_cache_fallback,
                _happ_out=happ_raw_urls,
            )
            raw_profiles.extend(raw_urls)

        count = self.set_profiles_from_raw(raw_profiles)

        # Заполняем happ_urls + extra["source"] для Happ-профилей
        if happ_raw_urls:
            bases = set()
            for u in happ_raw_urls:
                if u.startswith("vless://"):
                    base = u[:u.index("?")] if "?" in u else u
                    base = base.split("#")[0]
                    bases.add(base)
            with self._lock:
                self.happ_urls.clear()
                for p in self.profiles:
                    if p.raw_url in bases:
                        self.happ_urls.add(p.raw_url)
                        p.extra["source"] = "happ"

        return count

    def set_profiles_from_raw(self, raw_urls: List[str]) -> int:
        """Parse and set profiles from raw URLs (очищает Happ-маркировку)."""
        with self._lock:
            self.profiles.clear()
            self.happ_urls.clear()
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

    def is_happ(self, profile: Profile) -> bool:
        """Проверяет, пришёл ли профиль из Happ-источника."""
        with self._lock:
            return profile.raw_url in self.happ_urls

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
            # Аккуратно: profiles уже вне замка, _happ_urls только под замком
            # Здесь вызывается из test_and_select_best, который держит _lock.
            # Но _pick_by_preferred_engine статический, без доступа к self.
            # Чтобы не усложнять — проверка через raw_url на ходу не сработает.
            # Этот метод вызывается ТОЛЬКО из test_and_select_best, который уже
            # отфильтровал broken, а для happ-фильтрации достаточно первого найденного.
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
        preferred_engine: str = "auto",
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> Optional[Profile]:
        """
        Tests profiles (TCP only) and selects the best one.
        """
        with self._lock:
            profiles_to_test = self.profiles.copy()

        self.working_profiles = ProfileTester.test_profiles(
            profiles_to_test, max_test, timeout, on_progress
        )

        if not self.working_profiles:
            self.logger.error("NO WORKING PROFILES FOUND")
            return None

        with self._lock:
            available = [p for p in self.working_profiles if p.raw_url not in self.broken_profiles]

        if not available:
            self.logger.error("NO WORKING NON-BROKEN PROFILES FOUND")
            return None

        best = ProfileManager._pick_by_preferred_engine(available, preferred_engine)

        if best.latency and best.latency <= min_latency:
            self.logger.info(f"Profile picked: {best.comment}  {best.protocol.upper()} {best.host}:{best.port} [{best.latency}ms]")
        else:
            self.logger.warning(f"High latency selected: {best.comment}  {best.protocol.upper()} {best.host}:{best.port} [{best.latency}ms]")

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
