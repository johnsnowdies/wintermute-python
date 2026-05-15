from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml


def parse_time_interval(interval: str) -> int:
    """
    Parse time interval string to seconds
    Supports: 1h, 30m, 120s
    """
    if not interval:
        return 3600

    interval = interval.strip().lower()
    if interval.endswith("h"):
        return int(interval[:-1]) * 3600
    elif interval.endswith("m"):
        return int(interval[:-1]) * 60
    elif interval.endswith("s"):
        return int(interval[:-1])
    else:
        return int(interval)


@dataclass
class LoggingConfig:
    level: str
    format: str
    file: Optional[str]
    file_level: str = "debug"


@dataclass
class SourceConfig:
    """Profile source configuration"""

    url: str
    type: str = "base64"
    refresh: int = 3600  # sec
    filter: str = ""
    enabled: bool = True
    priority: int = 1


@dataclass
class NetworkConfig:
    """Network configuration for tunneling"""

    interface: str
    exclude_subnets: List[str] = field(default_factory=list)
    tun_name: str = "wintermute-tun"
    tun_subnet: str = "172.19.0.0/30"
    mtu: int = 1500
    ipv4_forward: bool = False


@dataclass
class TestingConfig:
    """Testing configuration"""

    healthcheck_urls: List[str] = field(
        default_factory=lambda: [
            "https://1.1.1.1/cdn-cgi/trace",
            "https://api.ipify.org?format=json",
            "http://connectivitycheck.gstatic.com/generate_204",
        ]
    )
    timeout: int = 5
    healthcheck_interval: int = 30  # sec
    failure_threshold: int = 3
    initial_delay: int = 10  # sec
    max_test: int = 100
    healthcheck_content_url: str = ""
    healthcheck_content_md5: str = ""


@dataclass
class SelectionConfig:
    """Profile selection strategy configuration"""

    strategy: str = "latency"
    min_acceptable_latency: int = 500  # ms
    auto_switch: bool = True
    switch_delay: int = 10  # sec
    backup_profiles_count: int = 3
    prefer_xray: bool = False


@dataclass
class CacheConfig:
    enabled: bool = True
    directory: str = "~/.cache/wintermute/profiles"
    fallback_on_error: bool = True


@dataclass
class Config:
    sources: List[SourceConfig]
    network: NetworkConfig
    testing: TestingConfig
    selection: SelectionConfig
    cache: CacheConfig
    logging: LoggingConfig


class ConfigManager:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config: Optional[Config] = None

    def load(self) -> Config:
        if not self.config_path.exists():
            raise FileNotFoundError(f"No config file found: {self.config_path}")

        with open(self.config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        sources = []
        for src in data.get("sources", []):
            if src.get("enabled", True):
                sources.append(
                    SourceConfig(
                        url=src["url"],
                        type=src.get("type", "base64"),
                        refresh=parse_time_interval(src.get("refresh", "1h")),
                        filter=src.get("filter", ""),
                        enabled=src.get("enabled", True),
                        priority=src.get("priority", 1),
                    )
                )

        # Logging
        log = data.get("logging", {})
        logging_cfg = LoggingConfig(
            level=log.get("level", "info"),
            format=log.get(
                "format", "%(asctime)s %(levelname)s: %(message)s"
            ),
            file=log.get("file"),
            file_level=log.get("file_level", "debug"),
        )

        # Network
        net = data.get("network", {})
        tun = net.get("tun", {})
        if not tun and "tun_name" not in net:
             # try old structure if tun is not a dict
             tun = {}

        network = NetworkConfig(
            interface=net.get("interface", "eth0"),
            exclude_subnets=net.get("exclude_subnets", []),
            tun_name=tun.get("name") or net.get("tun_name") or "wintermute-tun",
            tun_subnet=tun.get("subnet") or net.get("tun_subnet") or "172.19.0.0/30",
            mtu=tun.get("mtu") or net.get("mtu") or 1500,
            ipv4_forward=net.get("ipv4_forward", False),
        )

        # Testing config
        test = data.get("testing", {})
        testing = TestingConfig(
            healthcheck_urls=test.get("healthcheck_urls", []),
            timeout=test.get("timeout", 5),
            healthcheck_interval=parse_time_interval(
                test.get("healthcheck_interval", "30s")
            ),
            failure_threshold=test.get("failure_threshold", 3),
            initial_delay=parse_time_interval(test.get("initial_delay", "10s")),
            max_test=test.get("max_test", 100),
            healthcheck_content_url=test.get("healthcheck_content_url", None),
            healthcheck_content_md5=test.get("healthcheck_content_md5", None),
        )

        # Selection config
        sel = data.get("selection", {})
        selection = SelectionConfig(
            strategy=sel.get("strategy", "latency"),
            min_acceptable_latency=sel.get("min_acceptable_latency", 500),
            auto_switch=sel.get("auto_switch", True),
            switch_delay=parse_time_interval(sel.get("switch_delay", "10s")),
            backup_profiles_count=sel.get("backup_profiles_count", 3),
            prefer_xray=sel.get("prefer_xray", False),
        )

        # Cache config
        cache_data = data.get("cache", {})
        cache = CacheConfig(
            enabled=cache_data.get("enabled", True),
            directory=cache_data.get("directory", "~/.cache/wintermute/profiles"),
            fallback_on_error=cache_data.get("fallback_on_error", True),
        )

        self.config = Config(
            sources=sources,
            network=network,
            testing=testing,
            selection=selection,
            cache=cache,
            logging=logging_cfg,
        )

        return self.config

    def get_config(self) -> Config:
        if self.config is None:
            self.load()
        if self.config is None:
            raise Exception("Config not found")

        return self.config
