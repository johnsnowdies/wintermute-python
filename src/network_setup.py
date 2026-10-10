import json
import shlex
import subprocess
import socket
from typing import List, Optional

import requests

from logger import get_logger


# DoH (DNS-over-HTTPS) endpoint — Cloudflare, недоступен в РФ, поэтому
# ниже стоит fallback на системный резолвер.
_DOH_ENDPOINTS = [
    "https://1.1.1.1/dns-query",
    "https://1.0.0.1/dns-query",
]


def resolve_hostname_doh(name: str, timeout: int = 3) -> Optional[str]:
    """Resolve hostname via DoH (DNS-over-HTTPS), A record."""
    for ep in _DOH_ENDPOINTS:
        try:
            r = requests.get(
                ep,
                params={"name": name, "type": "A"},
                headers={"Accept": "application/dns-json"},
                timeout=timeout, verify=False,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("Status") == 0 and "Answer" in data:
                    # Первый A-запись
                    for ans in data["Answer"]:
                        if ans.get("type") == 1:  # A record
                            return ans["data"]
        except Exception:
            continue
    return None


def get_default_gateway() -> Optional[str]:
    """Returns current default gateway IP"""
    try:
        # Better way to get default gateway: ask which route is used for a common internet IP
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"], capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout:
            parts = result.stdout.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass

    # Fallback to old method
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout:
            # Take the first line in case of multiple defaults
            first_line = result.stdout.splitlines()[0]
            parts = first_line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None


def get_default_interface() -> Optional[str]:
    """Returns current default WAN interface name"""
    try:
        # Ask which interface is used for a common internet IP
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"], capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout:
            parts = result.stdout.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass

    # Fallback to old method
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout:
            # Take the first line in case of multiple defaults
            first_line = result.stdout.splitlines()[0]
            parts = first_line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return None


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IPv4: DoH → system resolver fallback."""
    ip = resolve_hostname_doh(hostname)
    if ip:
        return ip
    # Fallback to system resolver (может быть заблокирован)
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def resolve_hostname_v6(hostname: str) -> Optional[str]:
    """Resolve hostname to IPv6 address."""
    try:
        info = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        if info:
            return info[0][4][0]
    except Exception:
        pass
    return None


def setup_linux_tun_routing(
    tun_interface: str,
    tun_addr: str,
    proxy_host: str,
    wan_interface: str,
    exclude_subnets: List[str],
) -> List[str]:
    """
    Sets up IPv4 + IPv6 routing for TUN interface on Linux manually.
    (Xray doesn't do automatic routing like sing-box with auto_route.)
    """
    rules = []
    logger = get_logger(__name__)
    logger.info(f"Setting up manual TUN routing for {tun_interface}...")

    # ── 1. Поднять TUN-интерфейс ────────────────────────────────────────
    subprocess.run(["ip", "addr", "add", tun_addr, "dev", tun_interface], check=False)
    subprocess.run(["ip", "link", "set", "dev", tun_interface, "up"], check=False)
    subprocess.run(["ip", "-6", "addr", "add", "fdfe:dcba:9876::1/126", "dev", tun_interface], check=False)
    subprocess.run(["ip", "-6", "link", "set", "dev", tun_interface, "up"], check=False)

    # ── 2. Bypass-маршрут до прокси-сервера через оригинальный шлюз ─────
    proxy_ip_v4 = resolve_hostname(proxy_host) or proxy_host
    proxy_ip_v6 = resolve_hostname_v6(proxy_host)

    def _detect_route(dest: str) -> tuple:
        try:
            r = subprocess.run(["ip", "route", "get", dest], capture_output=True, text=True)
            if r.returncode == 0:
                parts = r.stdout.split()
                gw = parts[parts.index("via") + 1] if "via" in parts else None
                dev = parts[parts.index("dev") + 1] if "dev" in parts else None
                return gw or get_default_gateway(), dev or wan_interface
        except Exception:
            pass
        return get_default_gateway(), wan_interface

    def _add_route(dest: str, gw: str, dev: str, metric: int = 50):
        cmd = ["ip", "route", "add", dest, "via", gw, "dev", dev, "metric", str(metric)]
        subprocess.run(cmd, check=False)
        rules.append(" ".join(cmd))

    gw4, iface4 = _detect_route(proxy_ip_v4) if proxy_ip_v4 else (None, wan_interface)
    if gw4 and proxy_ip_v4:
        _add_route(proxy_ip_v4, gw4, iface4, 50)
    else:
        logger.warning(f"Cannot bypass-route proxy {proxy_ip_v4}: no gateway")

    if proxy_ip_v6:
        try:
            r = subprocess.run(["ip", "-6", "route", "get", proxy_ip_v6], capture_output=True, text=True)
            if r.returncode == 0:
                parts = r.stdout.split()
                gw6 = parts[parts.index("from") + 1] if "from" in parts else None
                dev6 = parts[parts.index("dev") + 1] if "dev" in parts else None
                if gw6 and dev6:
                    cmd = ["ip", "-6", "route", "add", proxy_ip_v6, "via", gw6, "dev", dev6, "metric", "50"]
                    subprocess.run(cmd, check=False)
                    rules.append(" ".join(cmd))
        except Exception as e:
            logger.warning(f"Cannot add IPv6 bypass route: {e}")

    # ── 3. Исключённые подсети через оригинальный шлюз ──────────────────
    if gw4:
        local = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        for subnet in sorted(set(local + exclude_subnets)):
            _add_route(subnet, gw4, iface4, 200)
        for subnet in ["fc00::/7", "fe80::/10"]:
            try:
                cmd = ["ip", "-6", "route", "add", subnet, "via", gw4, "dev", iface4, "metric", "200"]
                subprocess.run(cmd, capture_output=True)
                rules.append(" ".join(cmd))
            except Exception:
                pass

    # ── 4. Default-маршруты через TUN ───────────────────────────────────
    for half in ["0.0.0.0/1", "128.0.0.0/1"]:
        cmd = ["ip", "route", "add", half, "dev", tun_interface]
        subprocess.run(cmd, check=False)
        rules.append(" ".join(cmd))
    cmd6 = ["ip", "-6", "route", "add", "2000::/3", "dev", tun_interface]
    subprocess.run(cmd6, check=False)
    rules.append(" ".join(cmd6))

    logger.info("Manual TUN routing applied (IPv4 + IPv6)")
    return rules


def setup_iptables_rules(
    lan_interface: Optional[str], tun_interface: str, tun_subnet: str, exclude_subnets: List[str]
) -> List[str]:
    """
    Configures iptables rules for routing traffic from the interface to the TUN tunnel

    Args:
        lan_interface: Incoming interface (e.g. enp0s31f6), optional
        tun_interface: TUN interface (e.g. wintermute-tun)
        tun_subnet: Subnet of the TUN interface (for example, 172.19.0.0/30)
        exclude_subnets: List of subnets to exclude from routing

    Returns:
        List of applied rules (for subsequent cleaning)
    """
    rules = []

    logger = get_logger(__name__)

    if not lan_interface or lan_interface.lower() == "none":
        logger.warning("No lan_interface provided, skipping iptables rules setup.")
        return []

    logger.info("Setting up iptables rules...")
    logger.info(f"   LAN: {lan_interface} -> {tun_interface}, subnet: {tun_subnet}")

    # Enable forwarding
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)

    # 1. Исключить локальные подсети из маркировки
    for subnet in exclude_subnets:
        rules.append(f"iptables -t mangle -A PREROUTING -i {lan_interface} -d {subnet} -j RETURN")
    rules.append(f"iptables -t mangle -A PREROUTING -i {lan_interface} -d 224.0.0.0/4 -j RETURN")
    rules.append(f"iptables -t mangle -A PREROUTING -i {lan_interface} -d 255.255.255.255 -j RETURN")

    # 2. Маркировать весь остальной трафик с LAN-интерфейса
    rules.append(f"iptables -t mangle -A PREROUTING -i {lan_interface} -j MARK --set-mark 0x2")

    # 3. Создать отдельную таблицу маршрутизации для маркированных пакетов
    tbl = "wintermute_routing"
    try:
        with open("/etc/iproute2/rt_tables", "r") as f:
            if tbl not in f.read():
                with open("/etc/iproute2/rt_tables", "a") as f:
                    f.write(f"\n200 {tbl}\n")
    except Exception as e:
        logger.warning(f"  rt_tables warning: {e}")

    rules.append(f"ip rule add fwmark 0x2 table {tbl}")
    rules.append(f"ip route add {tun_subnet} dev {tun_interface} table {tbl}")
    rules.append(f"ip route add default dev {tun_interface} table {tbl}")

    # 4. NAT для трафика из TUN
    rules.append(f"iptables -t nat -A POSTROUTING -o {tun_interface} -j MASQUERADE")

    # 5. FORWARD между LAN и TUN
    rules.append(f"iptables -A FORWARD -i {lan_interface} -o {tun_interface} -j ACCEPT")
    rules.append(f"iptables -A FORWARD -i {tun_interface} -o {lan_interface} -m state --state RELATED,ESTABLISHED -j ACCEPT")

    # Apply all rules (shlex.split безопаснее str.split для shell-команд)
    for rule in rules:
        logger.info(f"  → {rule}")
        result = subprocess.run(shlex.split(rule), capture_output=True, text=True)
        if result.returncode != 0:
            err = result.stderr.strip() if result.stderr else ""
            if err and "File exists" not in err and "RTNETLINK answers: File exists" not in err:
                logger.warning(f"  iptables warning: {err}")
                if "ip route" in rule:
                    logger.error("  CAN NOT ADD ROUTE!")
    logger.info("iptables rules applied")
    return rules


def cleanup_iptables_rules(rules: List[str]):
    """Clears the applied iptables and iproute2 rules (shlex.split для безопасности)."""
    logger = get_logger(__name__)
    logger.info("cleaning iptables and iproute2 rules")

    def _run(cmd_str: str):
        subprocess.run(shlex.split(cmd_str), capture_output=True, check=False)

    # ── Удаляем правила iptables ────────────────────────────────────────
    for rule in reversed(rules):
        if " -A " in rule:
            _run(rule.replace(" -A ", " -D "))
        elif rule.startswith("ip rule add"):
            _run(rule.replace(" add ", " del "))

    # ── Удаляем ip-route и ip -6-route ─────────────────────────────────
    subprocess.run(["ip", "rule", "del", "fwmark", "0x2", "table", "wintermute_routing"],
                   capture_output=True, check=False)
    subprocess.run(["ip", "route", "flush", "table", "wintermute_routing"],
                   capture_output=True, check=False)

    for rule in reversed(rules):
        if " route add " in rule:
            if rule.startswith("ip -6"):
                del_rule = "ip -6 route del" + rule[rule.index("route add") + 10:]
            else:
                del_rule = rule.replace("route add", "route del")
            _run(del_rule)

    logger.info("iptables cleanup done")


def check_interface_exists(interface: str) -> bool:
    """
    Verifies the existence of a network interface

    Args:
        interface: Interface name

    Returns:
        True if the interface exists
    """
    result = subprocess.run(
        ["ip", "link", "show", interface], capture_output=True, text=True
    )
    return result.returncode == 0


def get_available_interfaces() -> List[str]:
    """[Deprecated] Returns a list of available network interfaces.

    Returns:
        List of interface names
    """
    result = subprocess.run(
        ["ip", "-o", "link", "show"], capture_output=True, text=True
    )

    if result.returncode != 0:
        return []

    interfaces = []
    for line in result.stdout.strip().split("\n"):
        if ":" in line:
            # Format: "1: lo: <LOOPBACK,UP,LOWER_UP> ..."
            parts = line.split(":")
            if len(parts) >= 2:
                iface = parts[1].strip()
                # Exclude lo and docker interfaces
                if (
                    iface != "lo"
                    and not iface.startswith("docker")
                    and not iface.startswith("veth")
                ):
                    interfaces.append(iface)

    return interfaces
