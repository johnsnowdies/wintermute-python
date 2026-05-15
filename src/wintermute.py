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
)
from profile_manager import Profile, ProfileManager
from singbox_manager import SingboxManager
from utils import find_singbox


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
        self.logger = get_logger(__name__)
        self.test_mode = test_mode

        cache_dir = (
            self.config.cache.directory if self.config.cache.enabled else "./cache"
        )
        self.profile_manager = ProfileManager(
            cache_dir=cache_dir, use_cache=self.config.cache.enabled, config=config_path
        )
        self.singbox_manager: Optional[SingboxManager] = None
        self.healthchecker: Optional[HealthChecker] = None

        # Flags
        self._running = True

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
        if extra["type"] != "tcp" and extra["type"] != "xhttp":
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

    def _save_singbox_config(
        self,
        config: dict,
        config_path: Path,
        proxy_mode: bool = False,
        proxy_port: int = 3128,
    ) -> Path:
        """Save Sing-Box Config"""

        if proxy_mode:
            config_path = (
                Path.home()
                / ".config"
                / "sing-box"
                / f"proxy_{proxy_port}_{datetime.datetime.now()}.json"
            )

        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        self.logger.debug(f"Configuration saved: {config_path}")
        return config_path

    def load_and_select_profile(self) -> bool:
        """Load profiles and select the best"""
        self.logger.info("Loading and Profile testing")

        # Loading profiles or fallback to cache
        count = self.profile_manager.load_profiles_from_sources(
            self.config.sources, use_cache_fallback=self.config.cache.fallback_on_error
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
        )

        if not best_profile:
            self.logger.error("No working profile found")
            return False

        return True

    def setup_singbox(
        self,
        profile: Optional[Profile] = None,
        proxy_mode: bool = False,
        proxy_port: int = 3128,
    ) -> bool:
        """Setup Sing-Box as child process for selected profile"""
        profile = profile or self.profile_manager.get_selected_profile()
        if not profile:
            self.logger.error("setup_singbox called without profile value")
            return False

        # Creating Sing-Box configuration
        outbound = self._create_singbox_outbound(profile)
        config = self._create_singbox_config(
            outbound,
            self.config.network,
            proxy_mode,
            proxy_port,
        )

        self.singbox_config_path = self._save_singbox_config(
            config, self.singbox_config_path, proxy_mode, proxy_port
        )

        # Lookup for Sing-Box executable
        singbox_path = find_singbox()
        if not singbox_path:
            self.logger.error(
                "No sing-box found at your system. https://getsingbox.com"
            )
            return False

        # Start Sing-Box Manager
        self.singbox_manager = SingboxManager(singbox_path, self.singbox_config_path)
        if not self.singbox_manager.start():
            return False

        # TODO: check if necessary
        time.sleep(2)

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
            external_fault_callback=self._has_singbox_error_burst,
            initial_delay=self.config.testing.initial_delay,
        )
        self.healthchecker.start()

    def _has_singbox_error_burst(self) -> bool:
        """Returns True when sing-box reports too many ERROR logs in short period."""
        if not self.singbox_manager:
            return False
        return self.singbox_manager.has_error_burst(threshold=3, window_sec=60)

    def on_tunnel_failure(self):
        """Called on tunnel failure detected, autorecovery"""
        self.logger.warning("TUNNEL FAILURE DETECTED, RECOVERING...")

        # Stoping Sing-Box process
        if self.singbox_manager:
            self.singbox_manager.stop()

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

            # Setup and start Sing-Box
            if self.setup_singbox():
                self.logger.warning("RESOLVED")
                return

        # There is no suitable backups, load all profiles (cache-fallback)
        self.logger.warning("NO SUCCESS WITH BACKUP PROFILES, TESTING PROFILES")
        if self.load_and_select_profile():
            self.setup_singbox()

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
            on_refresh_callback=None,  # Пока без callback
        )

    def run(self):
        """Application entry point"""

        setup_logger(
            name=__name__,
            level=self.config.logging.level,
            log_format=self.config.logging.format,
            log_file=self.config.logging.file,
        )

        self.logger = get_logger(__name__)
        self.logger.info("=" * 80)
        self.logger.info("Wintermute")
        self.logger.info("=" * 80)

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
                # Setup and start Sing-Box
                if self.setup_singbox():
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

        if self.healthchecker:
            self.healthchecker.stop()

        # Stop profile manager auto refresh
        if self.profile_manager:
            self.profile_manager.stop_auto_refresh()

        # Cleanup iptables rules before Sing-Box termination
        if self._iptables_rules and self.config.network.ipv4_forward:
            cleanup_iptables_rules(self._iptables_rules)
            self._iptables_rules = []

        if self.singbox_manager:
            self.singbox_manager.stop()

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
