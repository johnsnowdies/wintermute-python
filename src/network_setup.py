import subprocess
import socket
from typing import List, Optional

from logger import get_logger


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
    """Resolves hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def setup_linux_tun_routing(
    tun_interface: str,
    tun_addr: str,
    proxy_host: str,
    wan_interface: str,
    exclude_subnets: List[str],
) -> List[str]:
    """
    Sets up routing for TUN interface on Linux manually (as Xray doesn't do it automatically)
    """
    rules = []
    logger = get_logger(__name__)

    logger.info(f"Setting up manual TUN routing for {tun_interface}...")

    # 1. Assign IP address
    subprocess.run(["ip", "addr", "add", tun_addr, "dev", tun_interface], check=False)
    subprocess.run(["ip", "link", "set", "dev", tun_interface, "up"], check=False)

    # 2. Add route to proxy server via original gateway
    proxy_ip = resolve_hostname(proxy_host) or proxy_host

    # Auto-detect best gateway and interface for proxy
    actual_gw = None
    actual_iface = wan_interface

    try:
        route_get = subprocess.run(
            ["ip", "route", "get", proxy_ip], capture_output=True, text=True
        )
        if route_get.returncode == 0:
            parts = route_get.stdout.split()
            if "via" in parts:
                actual_gw = parts[parts.index("via") + 1]
            if "dev" in parts:
                actual_iface = parts[parts.index("dev") + 1]
    except Exception as e:
        logger.error(f"Failed to auto-detect route for proxy: {e}")

    gw = actual_gw or get_default_gateway()

    if gw and proxy_ip:
        # Use auto-detected interface if available, otherwise fallback to provided one
        target_iface = actual_iface or wan_interface
        rule = f"ip route add {proxy_ip} via {gw} dev {target_iface}"
        logger.info(f"   Adding bypass route for proxy: {rule}")
        subprocess.run(rule.split(), check=False)
        rules.append(rule)
    else:
        logger.error(f"Could not determine gateway ({gw}) or proxy IP ({proxy_ip})!")
        logger.error("Bypass route NOT added. This will likely break connection.")

    # 3. Add routes for excluded subnets via original gateway
    if gw:
        # Standard local subnets that should always be bypassed
        local_subnets = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        all_exclude = list(set(local_subnets + exclude_subnets))

        for subnet in all_exclude:
            # We use the same gateway/interface as for proxy or original
            target_iface = actual_iface or wan_interface
            rule = f"ip route add {subnet} via {gw} dev {target_iface}"
            subprocess.run(rule.split(), capture_output=True) # Silently try to add, might fail if exists
            rules.append(rule)

    # 4. Add default routes via TUN (two-halves approach)
    rule1 = f"ip route add 0.0.0.0/1 dev {tun_interface}"
    rule2 = f"ip route add 128.0.0.0/1 dev {tun_interface}"
    subprocess.run(rule1.split(), check=False)
    subprocess.run(rule2.split(), check=False)
    rules.append(rule1)
    rules.append(rule2)

    logger.info("Manual TUN routing applied")
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
    logger.info(f"   LAN Interface: {lan_interface} -> {tun_interface}")
    logger.info(f"   TUN subnet: {tun_subnet}")

    # --- SMART CLEANUP START ---
    logger.info("Cleaning up old rules before setup...")

    # Clean mangle PREROUTING (MARK)
    # Get all rules from PREROUTING mangle and delete those matching our criteria
    mangle_dump = subprocess.run(["iptables", "-t", "mangle", "-S", "PREROUTING"], capture_output=True, text=True)
    if mangle_dump.returncode == 0:
        for line in mangle_dump.stdout.splitlines():
            if f"-i {lan_interface}" in line and "--set-xmark 0x2/0xffffffff" in line: # iptables -S uses -xmark
                cmd = line.replace("-A", "-D")
                subprocess.run(f"iptables -t mangle {cmd}".split(), check=False)
            elif f"-i {lan_interface}" in line and "-j RETURN" in line:
                cmd = line.replace("-A", "-D")
                subprocess.run(f"iptables -t mangle {cmd}".split(), check=False)

    # Clean nat POSTROUTING (MASQUERADE)
    nat_dump = subprocess.run(["iptables", "-t", "nat", "-S", "POSTROUTING"], capture_output=True, text=True)
    if nat_dump.returncode == 0:
        for line in nat_dump.stdout.splitlines():
            if f"-o {tun_interface}" in line and "-j MASQUERADE" in line:
                cmd = line.replace("-A", "-D")
                subprocess.run(f"iptables -t nat {cmd}".split(), check=False)

    # Clean filter FORWARD (ACCEPT)
    forward_dump = subprocess.run(["iptables", "-S", "FORWARD"], capture_output=True, text=True)
    if forward_dump.returncode == 0:
        for line in forward_dump.stdout.splitlines():
            if (f"-i {lan_interface} -o {tun_interface}" in line or f"-i {tun_interface} -o {lan_interface}" in line) and "-j ACCEPT" in line:
                cmd = line.replace("-A", "-D")
                subprocess.run(f"iptables {cmd}".split(), check=False)

    # Clean ip rule
    ip_rule_dump = subprocess.run(["ip", "rule", "show"], capture_output=True, text=True)
    if ip_rule_dump.returncode == 0:
        for line in ip_rule_dump.stdout.splitlines():
            if "fwmark 0x2" in line and "wintermute_routing" in line:
                subprocess.run(["ip", "rule", "del", "fwmark", "0x2", "table", "wintermute_routing"], check=False)

    # Clean ip route table
    subprocess.run(["ip", "route", "flush", "table", "wintermute_routing"], check=False)
    # --- SMART CLEANUP END ---

    # Enable forward
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)

    # 1. EXCLUDE local traffic from labeling
    # Local subnets
    for subnet in exclude_subnets:
        rule = f"iptables -t mangle -A PREROUTING -i {lan_interface} -d {subnet} -j RETURN"
        rules.append(rule)

    # Multicast/broadcast
    rules.append(
        f"iptables -t mangle -A PREROUTING -i {lan_interface} -d 224.0.0.0/4 -j RETURN"
    )
    rules.append(
        f"iptables -t mangle -A PREROUTING -i {lan_interface} -d 255.255.255.255 -j RETURN"
    )

    # 2. Mark ALL other traffic from the interface (Universal marking)
    rules.append(
        f"iptables -t mangle -A PREROUTING -i {lan_interface} -j MARK --set-mark 0x2"
    )

    # 3. Create a separate routing table for labeled packets
    routing_table_name = "wintermute_routing"
    try:
        # Check if there is already a table
        with open("/etc/iproute2/rt_tables", "r") as f:
            content = f.read()
            if routing_table_name not in content:
                with open("/etc/iproute2/rt_tables", "a") as f:
                    f.write(f"\n200 {routing_table_name}\n")
    except Exception as e:
        logger.warning(f"  rt_tables warning: {e}")

    # 4. Adding a rule for labeled packages
    rules.append(f"ip rule add fwmark 0x2 table {routing_table_name}")

    # 5. Setting up routes in the table
    rules.append(
        f"ip route add {tun_subnet} dev {tun_interface} table {routing_table_name}"
    )
    rules.append(f"ip route add default dev {tun_interface} table {routing_table_name}")

    # 6. Add NAT for traffic from TUN
    rules.append(f"iptables -t nat -A POSTROUTING -o {tun_interface} -j MASQUERADE")

    # 7. We allow forwarding between interfaces
    rules.append(f"iptables -A FORWARD -i {lan_interface} -o {tun_interface} -j ACCEPT")
    rules.append(
        f"iptables -A FORWARD -i {tun_interface} -o {lan_interface} -m state --state RELATED,ESTABLISHED -j ACCEPT"
    )

    # Apply all rusel
    for rule in rules:
        print(f"  → {rule}")
        result = subprocess.run(rule.split(), capture_output=True, text=True)
        if result.returncode != 0:
            stderr = result.stderr.strip() if result.stderr else ""
            # ignore "already exists"
            # TODO: do not ignore :D
            if (
                stderr
                and "File exists" not in stderr
                and "RTNETLINK answers: File exists" not in stderr
            ):
                logger.warning(f"  iptables modify warning: {stderr}")
                # For critical rules (routes), we output an obvious error.
                if rule.startswith("ip route add"):
                    logger.error("  CAN NOT ADD ROUTE!")

    logger.info("iptables rules applied")

    # We check that the routes have actually been added
    check_result = subprocess.run(
        ["ip", "route", "show", "table", "200"], capture_output=True, text=True
    )

    if check_result.returncode == 0 and check_result.stdout.strip():
        logger.info("Route table 200 created:")
        for line in check_result.stdout.strip().split("\n"):
            logger.info(f"     {line}")
    else:
        logger.warning("Route table 200 not found or empty")

    return rules


def cleanup_iptables_rules(rules: List[str]):
    """
    Clears the applied iptables and iproute2 rules.

    Args:
        rules: List of rules to delete
    """
    logger = get_logger(__name__)
    logger.info("cleaning iptables and iproute2 rules")

    # Removing the rules in reverse order
    for rule in reversed(rules):
        # Convert the ADD rule to DELETE
        if " -A " in rule:
            delete_rule = rule.replace(" -A ", " -D ")
            subprocess.run(delete_rule.split(), capture_output=True, check=False)
        elif rule.startswith("ip rule add"):
            delete_rule = rule.replace(" add ", " del ")
            subprocess.run(delete_rule.split(), capture_output=True, check=False)
        elif rule.startswith("ip route add"):
            # For routes, just flash the table
            continue

    # Removing the routing rule
    subprocess.run(
        ["ip", "rule", "del", "fwmark", "0x2", "table", "wintermute_routing"],
        capture_output=True,
        check=False,
    )

    # Removing manual routes
    for rule in reversed(rules):
        if rule.startswith("ip route add"):
            del_rule = rule.replace(" add ", " del ")
            subprocess.run(del_rule.split(), capture_output=True, check=False)

    # Clearing the routing table
    subprocess.run(
        ["ip", "route", "flush", "table", "wintermute_routing"],
        capture_output=True,
        check=False,
    )

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


@DeprecationWarning
def get_available_interfaces() -> List[str]:
    """
    Returns a list of available network interfaces

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
            # Формат: "1: lo: <LOOPBACK,UP,LOWER_UP> ..."
            parts = line.split(":")
            if len(parts) >= 2:
                iface = parts[1].strip()
                # Исключаем lo и docker интерфейсы
                if (
                    iface != "lo"
                    and not iface.startswith("docker")
                    and not iface.startswith("veth")
                ):
                    interfaces.append(iface)

    return interfaces
