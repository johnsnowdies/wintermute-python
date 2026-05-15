import argparse
import atexit
import datetime
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

from config_manager import ConfigManager
from healthcheck import HealthChecker
from logger import get_logger, setup_logger
from network_setup import (
    check_interface_exists,
    cleanup_iptables_rules,
    setup_iptables_rules,
    setup_linux_tun_routing,
)
from profile_manager import Profile, ProfileManager
from singbox_manager import SingboxManager
from xray_manager import XrayManager
from utils import find_singbox, find_xray
from ui import get_ui


class Wintermute:
    """Application main class"""

    singbox_config_path: Path

    def __init__(
        self,
        config_path: str = "config.yaml",
        test_mode: bool = False,
    ):
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.load()

        # Initial logging setup (root logger)
        if not test_mode:
            setup_logger(
                level=self.config.logging.level,
                log_format=self.config.logging.format,
                log_file=self.config.logging.file,
                file_level=self.config.logging.file_level,
            )

        self.logger = get_logger(__name__)
        self.test_mode = test_mode

        cache_dir = (
            self.config.cache.directory if self.config.cache.enabled else "./cache"
        )
        self.profile_manager = ProfileManager(
            cache_dir=cache_dir, use_cache=self.config.cache.enabled, config=config_path
        )
        self.singbox_manager: Optional[SingboxManager] = None
        self.xray_manager: Optional[XrayManager] = None
        self.healthchecker: Optional[HealthChecker] = None

        # Flags
        self._running = True

        self.ui = get_ui(config_path)
        self.ui.set_mode("TESTING")

        # Sing-Box config path
        self.singbox_config_path = (
            Path.home() / ".config" / "sing-box" / "wintermute_config.json"
        )

        # iptables rules
        self._iptables_rules: List[str] = []

        # register cleanup on SIGTERM
        if not test_mode:
            atexit.register(self.cleanup)

    def _create_singbox_outbound(self, profile: Profile) -> dict:
        """Create outbound configuration"""
        if profile.protocol == "vless":
            return self._create_vless_outbound(profile)
        elif profile.protocol == "shadowsocks":
            return self._create_ss_outbound(profile)
        else:
            raise ValueError(f"Неподдерживаемый протокол: {profile.protocol}")

    def _create_vless_outbound(self, profile: Profile) -> dict:
        """VLESS outbound"""
        extra = profile.extra
        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": profile.host,
            "server_port": profile.port,
            "uuid": extra["uuid"],
        }

        # Flow
        if extra.get("flow"):
            flow = extra["flow"]
            if flow.endswith("-udp443"):
                flow = flow[:-7]
            elif flow == "none":
                flow = ""
            if flow:
                outbound["flow"] = flow

        # Transport
        if extra["type"] != "tcp":
            if extra["type"] == "xhttp":
                # xhttp is for Xray
                transport = {
                    "type": "xhttp",
                    "path": extra.get("path", "/"),
                    "host": extra.get("host", ""),
                    "mode": extra.get("mode", "auto"),
                    "extra": extra.get("extra", ""),
                }
                outbound["transport"] = transport
            else:
                transport = {"type": extra["type"]}

                if extra["type"] == "ws":
                    if extra.get("path"):
                        path = extra["path"]
                        if "?ed=" in path:
                            path_without_ed = path.split("?ed=")[0]
                            transport["path"] = path_without_ed
                            ed_value = path.split("?ed=")[1]
                            if ed_value.isdigit() and int(ed_value) > 0:
                                transport["max_early_data"] = int(ed_value)
                                transport[
                                    "early_data_header_name"
                                ] = "Sec-WebSocket-Protocol"
                        else:
                            transport["path"] = path

                    if extra.get("ws_host"):
                        transport["headers"] = {"Host": extra["ws_host"]}

                elif extra["type"] == "grpc":
                    if extra.get("service_name"):
                        transport["service_name"] = extra["service_name"]

                elif extra["type"] == "http":
                    if extra.get("path"):
                        transport["path"] = extra["path"]
                    if extra.get("http_host"):
                        transport["host"] = [extra["http_host"]]
                    transport["method"] = "GET"

                outbound["transport"] = transport

        # TLS/Reality

        if extra["security"] in ["tls", "reality"]:
            tls_config = {"enabled": True, "utils": {}, "reality": {}}

            if extra.get("sni"):
                tls_config["server_name"] = extra["sni"]

            tls_config["utls"] = {
                "enabled": True,
                "fingerprint": extra.get("fp", "chrome"),
            }

            if extra["security"] == "reality" and extra.get("pbk"):
                tls_config["reality"] = {
                    "enabled": True,
                    "public_key": extra["pbk"],
                    "short_id": extra["sid"] if extra.get("sid") else "",
                }

            outbound["tls"] = tls_config

        outbound["packet_encoding"] = extra.get("packet_encoding", "xudp")

        return outbound

    def _create_ss_outbound(self, profile: Profile) -> dict:
        """ShadowSocks Outbound"""
        extra = profile.extra
        return {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": profile.host,
            "server_port": profile.port,
            "method": extra["method"],
            "password": extra["password"],
        }

    def _create_singbox_config(
        self,
        outbound: dict,
        network_config,
        proxy_mode: bool = False,
        proxy_port: int = 3128,
    ) -> dict:
        """Create Sing-Box config file"""
        tun_config = {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": network_config.tun_name,
            "mtu": network_config.mtu,
            "auto_route": True,
            "strict_route": False,
            "address": [
                f"{network_config.tun_subnet.split('/')[0].rsplit('.', 1)[0]}.1/{network_config.tun_subnet.split('/')[1]}",
                "fdfe:dcba:9876::1/126",
            ],
            "stack": "system",
            "route_exclude_address": ["127.0.0.0/8"]
            + network_config.exclude_subnets
            + ["224.0.0.0/4", "255.255.255.255/32"],
        }

        if proxy_mode:
            tun_config = {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "0.0.0.0",
                "listen_port": proxy_port,
            }

        return {
            "log": {
                "level": "error" if not self.test_mode else "panic",
                "timestamp": True,
            },
            "inbounds": [tun_config],
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {
                "auto_detect_interface": True,
                "rules": [
                    {"action": "sniff"},
                    {"inbound": "tun-in", "outbound": "proxy"},
                    {
                        "ip_cidr": ["127.0.0.0/8"] + network_config.exclude_subnets,
                        "outbound": "direct",
                    },
                    {"ip_cidr": [network_config.tun_subnet], "outbound": "direct"},
                    {"protocol": "dns", "outbound": "proxy"},
                ],
                "final": "proxy",
            },
        }

    def _create_xray_config(
        self,
        outbound: dict,
        network_config,
        proxy_mode: bool = False,
        proxy_port: int = 3128,
    ) -> dict:
        """Create Xray config file"""

        # Xray config is a bit different from Sing-box
        # We need to translate Sing-box style outbound/inbound to Xray style

        # Inbounds
        inbounds = []
        if proxy_mode:
            inbounds.append({
                "port": proxy_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
            })
        else:
            # TUN for Xray
            tun_ip = f"{network_config.tun_subnet.split('/')[0].rsplit('.', 1)[0]}.1"
            inbounds.append({
                "protocol": "tun",
                "tag": "tun-in",
                "settings": {
                    "name": network_config.tun_name,
                    "mtu": network_config.mtu,
                    "gateway": [f"{tun_ip}/{network_config.tun_subnet.split('/')[1]}"],
                    "dns": ["1.1.1.1"],
                    "autoSystemRoutingTable": True,
                    "autoOutboundsInterface": network_config.interface
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic", "fakedns"],
                    "metadataOnly": False
                }
            })

        # DNS configuration for TUN mode
        dns_config = {}
        fakedns_config = []
        if not proxy_mode:
            fakedns_config = [{"ipPool": "198.18.0.0/15", "poolSize": 65535}]
            dns_config = {
                "servers": [
                    "fakedns",
                    "https://1.1.1.1/dns-query",
                    "localhost"
                ],
                "queryStrategy": "UseIP",
                "tag": "dns-internal"
            }

        # Outbound translation
        xray_outbound = {
            "protocol": outbound["type"],
            "tag": outbound["tag"],
            "settings": {
                "vnext": [{
                    "address": outbound["server"],
                    "port": outbound["server_port"],
                    "users": [{
                        "id": outbound["uuid"],
                        "encryption": "none",
                        "flow": outbound.get("flow", "")
                    }]
                }]
            },
            "streamSettings": {
                "network": outbound.get("transport", {}).get("type", "tcp"),
                "security": "none",
                "sockopt": {
                    "mark": 255
                }
            }
        }

        # Transport
        if "transport" in outbound:
            t = outbound["transport"]
            if t["type"] == "ws":
                xray_outbound["streamSettings"]["wsSettings"] = {
                    "path": t.get("path", "/"),
                    "headers": t.get("headers", {})
                }
            elif t["type"] == "grpc":
                xray_outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": t.get("service_name", "grpc")
                }
            elif t["type"] == "xhttp":
                # Parse extra if it's a string (it usually comes from URL)
                xhttp_extra = {}
                if t.get("extra"):
                    try:
                        if isinstance(t["extra"], str):
                            xhttp_extra = json.loads(t["extra"])
                        else:
                            xhttp_extra = t["extra"]
                    except json.JSONDecodeError:
                        self.logger.warning(f"Failed to parse xhttp extra: {t['extra']}")
                        xhttp_extra = {}

                xray_outbound["streamSettings"]["xhttpSettings"] = {
                    "path": t.get("path", "/"),
                    "host": t.get("host", ""),
                    "mode": t.get("mode", "auto"),
                    "extra": xhttp_extra
                }

        # TLS/Reality
        if "tls" in outbound:
            tls = outbound["tls"]
            if tls.get("enabled"):
                if tls.get("reality", {}).get("enabled"):
                    xray_outbound["streamSettings"]["security"] = "reality"
                    xray_outbound["streamSettings"]["realitySettings"] = {
                        "show": False,
                        "fingerprint": tls.get("utls", {}).get("fingerprint", "chrome"),
                        "serverName": tls.get("server_name", ""),
                        "publicKey": tls["reality"]["public_key"],
                        "shortId": tls["reality"]["short_id"],
                        "spiderX": "/"
                    }
                else:
                    xray_outbound["streamSettings"]["security"] = "tls"
                    xray_outbound["streamSettings"]["tlsSettings"] = {
                        "serverName": tls.get("server_name", ""),
                        "fingerprint": tls.get("utls", {}).get("fingerprint", "chrome")
                    }

        config = {
            "log": {
                "access": "none",
                "error": "" if not self.test_mode else "none",
                "warning": "" if not self.test_mode else "none",
                "loglevel": "warning"
            },
            "inbounds": inbounds,
            "outbounds": [
                xray_outbound,
                {"protocol": "dns", "tag": "dns-out"},
                {"protocol": "freedom", "tag": "direct", "streamSettings": {"sockopt": {"mark": 255}}},
                {"protocol": "blackhole", "tag": "block"}
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {"type": "field", "inboundTag": ["tun-in"], "port": 53, "outboundTag": "dns-out"},
                    {"type": "field", "protocol": ["dns"], "outboundTag": "dns-out"},
                    {"type": "field", "ip": ["198.18.0.0/15"], "outboundTag": "proxy"},
                    {"type": "field", "outboundTag": "direct", "ip": ["127.0.0.0/8"] + network_config.exclude_subnets},
                    {"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}
                ]
            }
        }

        if fakedns_config:
            config["fakedns"] = fakedns_config

        if dns_config:
            config["dns"] = dns_config

        return config

    def _save_config(
        self,
        config: dict,
        filename: str,
        proxy_mode: bool = False,
        proxy_port: int = 3128,
    ) -> Path:
        """Save Config (Generic)"""

        if proxy_mode:
            config_path = (
                Path.home()
                / ".config"
                / "wintermute"
                / f"{filename}_proxy_{proxy_port}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
            )
        else:
            config_path = (
                Path.home() / ".config" / "wintermute" / f"{filename}_config.json"
            )

        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        self.logger.debug(f"Configuration saved: {config_path}")
        return config_path

    def load_and_select_profile(self) -> bool:
        """Load profiles and select the best"""
        self.logger.info("Loading profiles and starting tests...")

        # Loading profiles or fallback to cache
        count = self.profile_manager.load_profiles_from_sources(
            self.config.sources, use_cache_fallback=self.config.cache.fallback_on_error
        )

        # Update UI sources and last update
        sources_urls = [s.url for s in self.config.sources if s.enabled]
        last_update = 0
        for s in self.config.sources:
            if s.enabled:
                ts = self.profile_manager.get_last_update_time(s.url)
                if ts and ts > last_update:
                    last_update = ts

        self.ui.set_status_data(
            sources=sources_urls,
            last_update=last_update if last_update > 0 else None
        )

        if count == 0:
            self.logger.error("0 profiles loaded, interrupting")
            return False

        # Test and pickup
        best_profile = self.profile_manager.test_and_select_best(
            max_test=self.config.testing.max_test,
            timeout=self.config.testing.timeout,
            min_latency=self.config.selection.min_acceptable_latency,
            test_real=True
            if self.config.testing.healthcheck_content_url
            and self.config.testing.healthcheck_content_md5
            else False,
            prefer_xray=self.config.selection.prefer_xray,
            on_progress=self.ui.set_progress,
        )

        # Clear progress after tests
        self.ui.set_progress(0, 0)

        # Update UI with test results
        self.ui.set_status_data(test_results=self.profile_manager.working_profiles)

        if not best_profile:
            self.logger.error("No working profile found")
            return False

        return True

    def _get_core_log_path(self, core_name: str) -> Optional[str]:
        """Get path for core log file based on main log file location"""
        if not self.config.logging.file:
            return None
        log_dir = os.path.dirname(self.config.logging.file)
        if not log_dir:
            return f"{core_name}.log"
        return os.path.join(log_dir, f"{core_name}.log")

    def setup_singbox(
        self,
        profile: Optional[Profile] = None,
        proxy_mode: bool = False,
        proxy_port: int = 3128,
    ) -> bool:
        """Setup Proxy Engine (Sing-Box or Xray) as child process for selected profile"""
        profile = profile or self.profile_manager.get_selected_profile()
        if not profile:
            self.logger.error("setup_engine called without profile value")
            return False

        # Decide which engine to use
        use_xray = profile.extra.get("type") == "xhttp"
        if not self.test_mode:
            self.ui.set_core_type("xray" if use_xray else "sing-box")

        # Creating configuration
        outbound = self._create_singbox_outbound(profile)

        if use_xray:
            config = self._create_xray_config(
                outbound,
                self.config.network,
                proxy_mode,
                proxy_port,
            )
            config_path = self._save_config(config, "xray", proxy_mode, proxy_port)

            xray_path = find_xray()
            if not xray_path:
                self.logger.error("No xray found at your system.")
                return False

            xray_log = self._get_core_log_path("xray")
            self.xray_manager = XrayManager(
                xray_path,
                config_path,
                ui=self.ui if not self.test_mode else None,
                log_file=xray_log,
                quiet=self.test_mode,
            )
            if not self.xray_manager.start():
                return False

            # Manual routing for Linux Xray TUN
            if sys.platform == "linux" and not proxy_mode:
                tun_ip = f"{self.config.network.tun_subnet.split('/')[0].rsplit('.', 1)[0]}.1"
                # Use a small delay to let Xray create the interface
                time.sleep(1)
                self._iptables_rules += setup_linux_tun_routing(
                    tun_interface=self.config.network.tun_name,
                    tun_addr=f"{tun_ip}/{self.config.network.tun_subnet.split('/')[1]}",
                    proxy_host=profile.host,
                    interface=self.config.network.interface,
                    exclude_subnets=self.config.network.exclude_subnets,
                )
        else:
            config = self._create_singbox_config(
                outbound,
                self.config.network,
                proxy_mode,
                proxy_port,
            )
            config_path = self._save_config(config, "singbox", proxy_mode, proxy_port)

            singbox_path = find_singbox()
            if not singbox_path:
                self.logger.error(
                    "No sing-box found at your system. https://getsingbox.com"
                )
                return False

            singbox_log = self._get_core_log_path("singbox")
            self.singbox_manager = SingboxManager(
                singbox_path,
                config_path,
                ui=self.ui if not self.test_mode else None,
                log_file=singbox_log,
                quiet=self.test_mode,
            )
            if not self.singbox_manager.start():
                return False

        # TODO: check if necessary
        time.sleep(2 if not self.test_mode else 0.5)

        if self.config.network.ipv4_forward and not proxy_mode:
            # setup iptables
            self._iptables_rules = setup_iptables_rules(
                interface=self.config.network.interface,
                tun_interface=self.config.network.tun_name,
                tun_subnet=self.config.network.tun_subnet,
                exclude_subnets=self.config.network.exclude_subnets,
            )

        return True

    def start_healthcheck(self):
        """Start tunnel watchdog"""
        self.healthchecker = HealthChecker(
            check_urls=self.config.testing.healthcheck_urls,
            check_interval=self.config.testing.healthcheck_interval,
            timeout=self.config.testing.timeout,
            failure_threshold=self.config.testing.failure_threshold,
            on_failure_callback=self.on_tunnel_failure,
            external_fault_callback=self._has_error_burst,
            initial_delay=self.config.testing.initial_delay,
            content_url=self.config.testing.healthcheck_content_url,
            content_md5=self.config.testing.healthcheck_content_md5,
        )
        self.healthchecker.start()

    def _has_error_burst(self) -> bool:
        """Returns True when proxy engine reports too many ERROR logs in short period."""
        if self.singbox_manager and self.singbox_manager.has_error_burst(threshold=3, window_sec=60):
            return True
        if self.xray_manager and self.xray_manager.has_error_burst(threshold=3, window_sec=60):
            return True
        return False

    def on_tunnel_failure(self):
        """Called on tunnel failure detected, autorecovery"""
        self.logger.warning("TUNNEL FAILURE DETECTED, RECOVERING...")
        self.ui.set_mode("TESTING")

        # Stoping engines
        if self.singbox_manager:
            self.singbox_manager.stop()
            self.singbox_manager = None
        if self.xray_manager:
            self.xray_manager.stop()
            self.xray_manager = None

        # Using backup profiles
        backup_profiles = self.profile_manager.get_backup_profiles(
            count=self.config.selection.backup_profiles_count
        )

        for backup in backup_profiles:
            self.logger.info(f"Trying backup profile: {backup.comment}")
            self.logger.info(
                f"   {backup.protocol.upper()} {backup.host}:{backup.port} [{backup.latency}ms]"
            )

            # Pick backup profile
            self.profile_manager.selected_profile = backup
            self.ui.set_profile(backup.comment or backup.host)

            # Setup and start Sing-Box
            if self.setup_singbox():
                self.logger.warning("RESOLVED")
                self.logger.info("Switched to WORKING mode")
                self.ui.set_mode("WORKING")
                return

        # There is no suitable backups, load all profiles (cache-fallback)
        self.logger.warning("NO SUCCESS WITH BACKUP PROFILES, TESTING PROFILES")
        if self.load_and_select_profile():
            if self.setup_singbox():
                self.logger.info("Switched to WORKING mode")
                self.ui.set_mode("WORKING")

    def start_profile_refresh(self):
        """Background process of profile auto-refresh"""
        if not self.config.sources:
            return

        # Pick minimal refresh
        min_refresh = min(source.refresh for source in self.config.sources)

        # Use ProfileManager auto update
        self.profile_manager.start_auto_refresh(
            sources=self.config.sources,
            refresh_interval=min_refresh,
            on_refresh_callback=self._on_profiles_refreshed,
        )

    def _on_profiles_refreshed(self):
        """Called when profiles are updated from sources"""
        sources_urls = [s.url for s in self.config.sources if s.enabled]
        last_update = 0
        for s in self.config.sources:
            if s.enabled:
                ts = self.profile_manager.get_last_update_time(s.url)
                if ts and ts > last_update:
                    last_update = ts

        self.ui.set_status_data(
            sources=sources_urls,
            last_update=last_update if last_update > 0 else None
        )

    def force_reload_profiles(self):
        """Force reload profiles from sources without restarting engine or testing"""
        self.logger.info("Force reloading profiles from sources...")
        try:
            count = self.profile_manager.load_profiles_from_sources(
                self.config.sources, use_cache_fallback=self.config.cache.fallback_on_error
            )
            self._on_profiles_refreshed()
            self.logger.info(f"Reloaded {count} profiles.")
        except Exception as e:
            self.logger.error(f"Failed to reload profiles: {e}")

    def run(self):
        """Application entry point"""

        self.ui.start()
        self.ui.set_mode("TESTING")

        # Register hotkeys
        self.ui.register_hotkey("F5", self.force_reload_profiles)

        setup_logger(
            level=self.config.logging.level,
            log_format=self.config.logging.format,
            log_file=self.config.logging.file,
            ui=self.ui,
        )

        self.logger = get_logger(__name__)
        self.logger.info("Wintermute")

        # Check for root
        if os.geteuid() != 0:
            self.logger.error("Wintermute requires root access")
            return 1

        # Check interface exist
        if not check_interface_exists(self.config.network.interface):
            self.logger.error(f"{self.config.network.interface} interface not found")
            return 1

        # Load and select profile
        while self._running:
            if self.load_and_select_profile():
                selected = self.profile_manager.get_selected_profile()
                if selected:
                    self.ui.set_profile(selected.comment or selected.host)
                # Setup and start Sing-Box
                if self.setup_singbox():
                    self.logger.info("Switched to WORKING mode")
                    self.ui.set_mode("WORKING")
                    break

            self.logger.warning("No working profiles found. Retrying in 30 seconds...")
            time.sleep(30)

        # Running watchdog
        self.start_healthcheck()
        self.start_profile_refresh()

        self.logger.info("All systems are running. Ctrl+C to terminate.")

        # Main loop
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Terminating...")

        return 0

    def cleanup(self):
        """Cleanup of resources"""
        self._running = False

        if self.ui:
            self.ui.stop()

        if self.healthchecker:
            self.healthchecker.stop()

        # Stop profile manager auto refresh
        if self.profile_manager:
            self.profile_manager.stop_auto_refresh()

        # Cleanup iptables rules before Sing-Box termination
        if self._iptables_rules:
            cleanup_iptables_rules(self._iptables_rules)
            self._iptables_rules = []

        if self.singbox_manager:
            self.singbox_manager.stop()

        if self.xray_manager:
            self.xray_manager.stop()

        self.logger.info("Cleanup complete")


def main():
    parser = argparse.ArgumentParser(
        description="Wintermute - Sing-Box configuration manager"
    )
    parser.add_argument(
        "-c", "--config", default="config.yaml", help="Configuration file path"
    )

    args = parser.parse_args()

    try:
        app = Wintermute(config_path=args.config)
        return app.run()
    except KeyboardInterrupt:
        get_logger(__name__).info("Successfully terminated")
        return 0
    except Exception as e:
        import traceback

        get_logger(__name__).error(f"Critical error: {e} \n {traceback.format_exc()}")

        return 1


if __name__ == "__main__":
    sys.exit(main())
