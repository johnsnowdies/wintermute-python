#!/usr/bin/env python3
"""
Wintermute - Автоматический менеджер Sing-box туннелей
Загружает профили, тестирует, автоматически выбирает лучший и мониторит соединение
"""
import json
import sys
import subprocess
import os
import signal
import time
import threading
import atexit
from pathlib import Path
from typing import Optional, List
import argparse

from config_manager import ConfigManager
from profile_manager import ProfileManager, Profile
from healthcheck import HealthChecker
from network_setup import setup_iptables_rules, cleanup_iptables_rules, check_interface_exists, get_available_interfaces
from utils import find_singbox


class SingboxManager:
    """Менеджер процесса sing-box"""

    def __init__(self, singbox_path: str, config_path: Path):
        self.singbox_path = singbox_path
        self.config_path = config_path
        self.process: Optional[subprocess.Popen] = None
        self._running = False
        self._log_thread: Optional[threading.Thread] = None

    def _log_reader(self):
        """Читает и выводит логи sing-box"""
        if not self.process or not self.process.stdout:
            return

        try:
            for line in iter(self.process.stdout.readline, ''):
                if not line:
                    break
                print(f"[sing-box] {line.rstrip()}")
                sys.stdout.flush()
        except Exception as e:
            print(f"⚠ Ошибка чтения логов: {e}")

    def start(self):
        """Запускает sing-box"""
        if self._running and self.process:
            print("⚠ Sing-box уже запущен")
            return False

        print(f"\n🚀 Запускаю sing-box...")
        print(f"   Конфиг: {self.config_path}")

        try:
            self.process = subprocess.Popen(
                [self.singbox_path, "run", "-c", str(self.config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            self._running = True

            # Запускаем поток для чтения логов
            self._log_thread = threading.Thread(target=self._log_reader, daemon=True)
            self._log_thread.start()

            # Даем время на запуск и читаем первые строки
            time.sleep(3)

            # Проверяем что процесс запустился
            if self.process.poll() is not None:
                print("❌ Sing-box не смог запуститься")
                # Читаем вывод ошибки
                if self.process.stdout:
                    output = self.process.stdout.read()
                    if output:
                        print(f"Вывод:\n{output}")
                return False

            print("✅ Sing-box запущен")
            return True

        except Exception as e:
            print(f"❌ Ошибка запуска sing-box: {e}")
            return False

    def stop(self):
        """Останавливает sing-box"""
        if not self._running or not self.process:
            return

        print("\n🛑 Останавливаю sing-box...")
        try:
            self.process.terminate()
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

        self._running = False
        self.process = None
        print("✅ Sing-box остановлен")

    def restart(self):
        """Перезапускает sing-box"""
        print("\n🔄 Перезапускаю sing-box...")
        self.stop()
        time.sleep(1)
        return self.start()

    def is_running(self) -> bool:
        """Проверяет запущен ли sing-box"""
        if not self.process:
            return False
        return self.process.poll() is None


def create_singbox_outbound(profile: Profile) -> dict:
    """Создает outbound конфигурацию для sing-box"""
    if profile.protocol == 'vless':
        return _create_vless_outbound(profile)
    elif profile.protocol == 'shadowsocks':
        return _create_ss_outbound(profile)
    else:
        raise ValueError(f"Неподдерживаемый протокол: {profile.protocol}")


def _create_vless_outbound(profile: Profile) -> dict:
    """Создает VLESS outbound"""
    extra = profile.extra
    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": profile.host,
        "server_port": profile.port,
        "uuid": extra['uuid'],
    }

    # Flow
    if extra.get('flow'):
        flow = extra['flow']
        if flow.endswith('-udp443'):
            flow = flow[:-7]
        elif flow == 'none':
            flow = ''
        if flow:
            outbound["flow"] = flow

    # Transport
    if extra['type'] != 'tcp':
        transport = {"type": extra['type']}

        if extra['type'] == 'ws':
            if extra.get('path'):
                path = extra['path']
                if '?ed=' in path:
                    path_without_ed = path.split('?ed=')[0]
                    transport["path"] = path_without_ed
                    ed_value = path.split('?ed=')[1]
                    if ed_value.isdigit() and int(ed_value) > 0:
                        transport["max_early_data"] = int(ed_value)
                        transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
                else:
                    transport["path"] = path

            if extra.get('ws_host'):
                transport["headers"] = {"Host": extra['ws_host']}

        elif extra['type'] == 'grpc':
            if extra.get('service_name'):
                transport["service_name"] = extra['service_name']

        elif extra['type'] == 'http':
            if extra.get('path'):
                transport["path"] = extra['path']
            if extra.get('http_host'):
                transport["host"] = [extra['http_host']]
            transport["method"] = "GET"

        outbound["transport"] = transport

    # TLS/Reality
    if extra['security'] in ['tls', 'reality']:
        tls_config = {"enabled": True}

        if extra.get('sni'):
            tls_config["server_name"] = extra['sni']

        tls_config["utls"] = {
            "enabled": True,
            "fingerprint": extra.get('fp', 'chrome')
        }

        if extra['security'] == 'reality' and extra.get('pbk'):
            tls_config["reality"] = {
                "enabled": True,
                "public_key": extra['pbk'],
                "short_id": extra['sid'] if extra.get('sid') else ""
            }

        outbound["tls"] = tls_config

    outbound["packet_encoding"] = extra.get('packet_encoding', 'xudp')

    return outbound


def _create_ss_outbound(profile: Profile) -> dict:
    """Создает Shadowsocks outbound"""
    extra = profile.extra
    return {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": profile.host,
        "server_port": profile.port,
        "method": extra['method'],
        "password": extra['password']
    }


def create_singbox_config(outbound: dict, network_config) -> dict:
    """Создает полную конфигурацию sing-box"""
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
        "sniff": True,
        "route_exclude_address": ["127.0.0.0/8"] + network_config.exclude_subnets + ["224.0.0.0/4", "255.255.255.255/32"]
    }

    return {
        "log": {
            "level": "warning",
            "timestamp": True
        },
        "inbounds": [tun_config],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"}
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": [
                {"inbound": "tun-in", "outbound": "proxy"},
                {"ip_cidr": ["127.0.0.0/8"] + network_config.exclude_subnets, "outbound": "direct"},
                {"ip_cidr": [network_config.tun_subnet], "outbound": "direct"},
                {"protocol": "dns", "outbound": "proxy"}
            ],
            "final": "proxy"
        }
    }


def save_singbox_config(config: dict, config_path: Path):
    """Сохраняет конфигурацию sing-box"""
    config_path.parent.mkdir(parents=True, exist_ok=True)

    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print(f"📁 Конфигурация сохранена: {config_path}")


class Wintermute:
    """Главный класс приложения"""

    def __init__(self, config_path: str = "config.yaml"):
        # Загружаем конфигурацию
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.load()

        # Менеджеры
        cache_dir = self.config.cache.directory if self.config.cache.enabled else None
        self.profile_manager = ProfileManager(
            cache_dir=cache_dir,
            use_cache=self.config.cache.enabled
        )
        self.singbox_manager: Optional[SingboxManager] = None
        self.healthchecker: Optional[HealthChecker] = None

        # Потоки
        self._running = False

        # Путь к конфигу sing-box
        self.singbox_config_path = Path.home() / ".config" / "sing-box" / "wintermute_config.json"

        # Правила iptables (для очистки)
        self._iptables_rules: List[str] = []

        # Регистрируем очистку при выходе
        atexit.register(self.cleanup)

    def load_and_select_profile(self) -> bool:
        """Загружает профили и выбирает лучший"""
        print("\n" + "="*80)
        print("📡 ЗАГРУЗКА И ТЕСТИРОВАНИЕ ПРОФИЛЕЙ")
        print("="*80)

        # Загружаем профили (с fallback на кеш если нужно)
        count = self.profile_manager.load_profiles_from_sources(
            self.config.sources,
            use_cache_fallback=self.config.cache.fallback_on_error
        )
        if count == 0:
            print("❌ Не удалось загрузить профили")
            return False

        # Тестируем и выбираем лучший
        best_profile = self.profile_manager.test_and_select_best(
            max_test=20,
            timeout=self.config.testing.timeout,
            min_latency=self.config.selection.min_acceptable_latency
        )

        if not best_profile:
            print("❌ Не найдено рабочих профилей")
            return False

        return True

    def setup_singbox(self) -> bool:
        """Настраивает и запускает sing-box с выбранным профилем"""
        profile = self.profile_manager.get_selected_profile()
        if not profile:
            print("❌ Профиль не выбран")
            return False

        # Создаем конфигурацию
        outbound = create_singbox_outbound(profile)
        config = create_singbox_config(outbound, self.config.network)
        save_singbox_config(config, self.singbox_config_path)

        # Находим sing-box
        singbox_path = find_singbox()
        if not singbox_path:
            print("❌ Sing-box не найден в системе")
            return False

        # Запускаем sing-box
        self.singbox_manager = SingboxManager(singbox_path, self.singbox_config_path)
        if not self.singbox_manager.start():
            return False

        # Даем время sing-box поднять TUN интерфейс
        time.sleep(2)

        # Настраиваем iptables правила
        self._iptables_rules = setup_iptables_rules(
            interface=self.config.network.interface,
            tun_interface=self.config.network.tun_name,
            tun_subnet=self.config.network.tun_subnet,
            exclude_subnets=self.config.network.exclude_subnets
        )

        return True

    def start_healthcheck(self):
        """Запускает мониторинг туннеля"""
        self.healthchecker = HealthChecker(
            check_urls=self.config.testing.healthcheck_urls,
            check_interval=self.config.testing.healthcheck_interval,
            timeout=self.config.testing.timeout,
            failure_threshold=self.config.testing.failure_threshold,
            on_failure_callback=self.on_tunnel_failure,
            initial_delay=self.config.testing.initial_delay
        )
        self.healthchecker.start()

    def on_tunnel_failure(self):
        """Вызывается при падении туннеля"""
        print("\n" + "!"*80)
        print("⚠ ТУННЕЛЬ УПАЛ - ВЫБИРАЮ НОВЫЙ ПРОФИЛЬ")
        print("!"*80)

        # Останавливаем sing-box
        if self.singbox_manager:
            self.singbox_manager.stop()

        # Пробуем резервные профили
        backup_profiles = self.profile_manager.get_backup_profiles(
            count=self.config.selection.backup_profiles_count
        )

        for backup in backup_profiles:
            print(f"\n🔄 Пробую резервный профиль: {backup.comment}")
            print(f"   {backup.protocol.upper()} {backup.host}:{backup.port} [{backup.latency}ms]")

            # Устанавливаем резервный профиль как выбранный
            self.profile_manager.selected_profile = backup

            # Настраиваем и запускаем sing-box
            if self.setup_singbox():
                print("✅ Переключение успешно!")
                return

        # Если резервные не помогли - перезагружаем все профили
        print("\n🔄 Резервные профили не помогли - перезагружаю профили...")
        if self.load_and_select_profile():
            self.setup_singbox()

    def start_profile_refresh(self):
        """Запускает фоновый процесс обновления профилей"""
        if not self.config.sources:
            return

        # Берем минимальный refresh из всех источников
        min_refresh = min(source.refresh for source in self.config.sources)

        # Используем встроенное автообновление ProfileManager
        self.profile_manager.start_auto_refresh(
            sources=self.config.sources,
            refresh_interval=min_refresh,
            on_refresh_callback=None  # Пока без callback
        )

    def run(self):
        """Главный цикл приложения"""
        print("\n" + "="*80)
        print("❄️  WINTERMUTE - Автоматический менеджер Sing-box туннелей")
        print("="*80)

        # Проверка прав root
        if os.geteuid() != 0:
            print("❌ Требуются права root (sudo)")
            return 1

        # Проверяем наличие интерфейса
        if not check_interface_exists(self.config.network.interface):
            print(f"❌ Интерфейс '{self.config.network.interface}' не найден")
            print("\n📋 Доступные интерфейсы:")
            for iface in get_available_interfaces():
                print(f"   - {iface}")
            print("\nИзмените интерфейс в config.yaml")
            return 1

        # Загружаем и выбираем профиль
        if not self.load_and_select_profile():
            return 1

        # Настраиваем и запускаем sing-box
        if not self.setup_singbox():
            return 1

        # Запускаем мониторинг
        self._running = True
        self.start_healthcheck()
        self.start_profile_refresh()

        print("\n" + "="*80)
        print("✅ ВСЕ СИСТЕМЫ ЗАПУЩЕНЫ")
        print("="*80)
        print("   Для остановки нажмите Ctrl+C")
        print("-" * 80)

        # Главный цикл
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n🛑 Получен сигнал остановки...")

        self.cleanup()
        return 0

    def cleanup(self):
        """Очистка ресурсов"""
        self._running = False

        if self.healthchecker:
            self.healthchecker.stop()

        # Останавливаем автообновление профилей
        if self.profile_manager:
            self.profile_manager.stop_auto_refresh()

        # Очищаем iptables правила ПЕРЕД остановкой sing-box
        if self._iptables_rules:
            cleanup_iptables_rules(self._iptables_rules)
            self._iptables_rules = []

        if self.singbox_manager:
            self.singbox_manager.stop()

        print("✅ Очистка завершена")


def main():
    parser = argparse.ArgumentParser(description="Wintermute - Автоматический менеджер Sing-box туннелей")
    parser.add_argument('-c', '--config', default='config.yaml', help='Путь к файлу конфигурации')

    args = parser.parse_args()

    try:
        app = Wintermute(config_path=args.config)
        return app.run()
    except KeyboardInterrupt:
        print("\n\n🛑 Программа прервана пользователем")
        return 0
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
