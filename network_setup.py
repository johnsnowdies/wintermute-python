#!/usr/bin/env python3
"""
Модуль для настройки сетевых правил (iptables, iproute2)
"""
import subprocess
from typing import List


def setup_iptables_rules(interface: str, tun_interface: str, tun_subnet: str, exclude_subnets: List[str]) -> List[str]:
    """
    Настраивает iptables правила для маршрутизации трафика с интерфейса в TUN-туннель

    Args:
        interface: Входящий интерфейс (например, enp0s31f6)
        tun_interface: TUN интерфейс (например, wintermute-tun)
        tun_subnet: Подсеть TUN интерфейса (например, 172.19.0.0/30)
        exclude_subnets: Список подсетей для исключения из маршрутизации

    Returns:
        Список примененных правил (для последующей очистки)
    """
    rules = []

    print(f"\n📡 Настройка iptables правил...")
    print(f"   Интерфейс: {interface} -> {tun_interface}")
    print(f"   TUN подсеть: {tun_subnet}")

    # Включаем форвардинг
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)

    # 1. ИСКЛЮЧАЕМ локальный трафик из маркировки
    # Локальные подсети
    for subnet in exclude_subnets:
        rule = f"iptables -t mangle -A PREROUTING -i {interface} -d {subnet} -j RETURN"
        rules.append(rule)

    # Multicast/broadcast
    rules.append(f"iptables -t mangle -A PREROUTING -i {interface} -d 224.0.0.0/4 -j RETURN")
    rules.append(f"iptables -t mangle -A PREROUTING -i {interface} -d 255.255.255.255 -j RETURN")

    # 2. Маркируем ВЕСЬ остальной трафик с интерфейса
    rules.append(f"iptables -t mangle -A PREROUTING -i {interface} -p tcp -j MARK --set-mark 0x2")
    rules.append(f"iptables -t mangle -A PREROUTING -i {interface} -p udp -j MARK --set-mark 0x2")
    rules.append(f"iptables -t mangle -A PREROUTING -i {interface} -p icmp -j MARK --set-mark 0x2")

    # 3. Создаем отдельную таблицу маршрутизации для маркированных пакетов
    routing_table_name = "wintermute_routing"
    try:
        # Проверяем, есть ли уже таблица
        with open("/etc/iproute2/rt_tables", "r") as f:
            content = f.read()
            if routing_table_name not in content:
                with open("/etc/iproute2/rt_tables", "a") as f:
                    f.write(f"\n200 {routing_table_name}\n")
    except Exception as e:
        print(f"  ⚠ Предупреждение при добавлении в rt_tables: {e}")

    # 4. Добавляем правило для маркированных пакетов
    rules.append(f"ip rule add fwmark 0x2 table {routing_table_name}")

    # 5. Настраиваем маршруты в таблице
    rules.append(f"ip route add {tun_subnet} dev {tun_interface} table {routing_table_name}")
    rules.append(f"ip route add default dev {tun_interface} table {routing_table_name}")

    # 6. Добавляем NAT (маскарадинг) для трафика из TUN
    rules.append(f"iptables -t nat -A POSTROUTING -o {tun_interface} -j MASQUERADE")

    # 7. Разрешаем форвардинг между интерфейсами
    rules.append(f"iptables -A FORWARD -i {interface} -o {tun_interface} -j ACCEPT")
    rules.append(f"iptables -A FORWARD -i {tun_interface} -o {interface} -m state --state RELATED,ESTABLISHED -j ACCEPT")

    # Применяем все правила
    for rule in rules:
        print(f"  → {rule}")
        result = subprocess.run(rule.split(), capture_output=True, text=True)
        if result.returncode != 0:
            stderr = result.stderr.strip() if result.stderr else ""
            # Игнорируем ошибки "already exists"
            if stderr and "File exists" not in stderr and "RTNETLINK answers: File exists" not in stderr:
                print(f"  ⚠ Предупреждение: {stderr}")
                # Для критичных правил (маршруты) выводим явную ошибку
                if rule.startswith("ip route add"):
                    print(f"  ❌ Не удалось добавить маршрут!")

    print("✅ Правила iptables применены")

    # Проверяем что маршруты действительно добавились
    check_result = subprocess.run(
        ["ip", "route", "show", "table", "200"],
        capture_output=True,
        text=True
    )

    if check_result.returncode == 0 and check_result.stdout.strip():
        print(f"✅ Таблица маршрутизации 200 создана:")
        for line in check_result.stdout.strip().split('\n'):
            print(f"     {line}")
    else:
        print(f"⚠ Таблица маршрутизации 200 пуста или не найдена")

    return rules


def cleanup_iptables_rules(rules: List[str]):
    """
    Очищает примененные правила iptables и iproute2

    Args:
        rules: Список правил для удаления
    """
    print("\n🧹 Очистка правил iptables и маршрутизации...")

    # Удаляем правила в обратном порядке
    for rule in reversed(rules):
        # Преобразуем правило ADD в DELETE
        if " -A " in rule:
            delete_rule = rule.replace(" -A ", " -D ")
            subprocess.run(delete_rule.split(), capture_output=True, check=False)
        elif rule.startswith("ip rule add"):
            delete_rule = rule.replace(" add ", " del ")
            subprocess.run(delete_rule.split(), capture_output=True, check=False)
        elif rule.startswith("ip route add"):
            # Для маршрутов просто флашим таблицу
            continue

    # Удаляем правило маршрутизации
    subprocess.run(["ip", "rule", "del", "fwmark", "0x2", "table", "wintermute_routing"],
                   capture_output=True, check=False)

    # Очищаем таблицу маршрутизации
    subprocess.run(["ip", "route", "flush", "table", "wintermute_routing"],
                   capture_output=True, check=False)

    print("✅ Правила очищены")


def check_interface_exists(interface: str) -> bool:
    """
    Проверяет существование сетевого интерфейса

    Args:
        interface: Имя интерфейса

    Returns:
        True если интерфейс существует
    """
    result = subprocess.run(
        ["ip", "link", "show", interface],
        capture_output=True,
        text=True
    )
    return result.returncode == 0


def get_available_interfaces() -> List[str]:
    """
    Возвращает список доступных сетевых интерфейсов

    Returns:
        Список имен интерфейсов
    """
    result = subprocess.run(
        ["ip", "-o", "link", "show"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return []

    interfaces = []
    for line in result.stdout.strip().split('\n'):
        if ':' in line:
            # Формат: "1: lo: <LOOPBACK,UP,LOWER_UP> ..."
            parts = line.split(':')
            if len(parts) >= 2:
                iface = parts[1].strip()
                # Исключаем lo и docker интерфейсы
                if iface != 'lo' and not iface.startswith('docker') and not iface.startswith('veth'):
                    interfaces.append(iface)

    return interfaces
