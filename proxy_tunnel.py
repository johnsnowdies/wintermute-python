#!/usr/bin/env python3
"""
Sing-box Config Manager (на основе кода Throne)
Загружает base64 конфиги, парсит VLESS/Shadowsocks ссылки и запускает sing-box
"""

import json
import base64
import sys
import re
import requests
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
import subprocess
import os

def decode_b64_if_valid(s):
    """Декодирует base64 если возможно"""
    try:
        missing_padding = len(s) % 4
        if missing_padding:
            s += '=' * (4 - missing_padding)
        return base64.b64decode(s).decode('utf-8')
    except:
        return None

def load_profiles_from_source(source=None):
    """
    Загружает профили из разных источников:
    1. URL (скачивает файл)
    2. Локальный файл
    3. Прямой ввод base64
    4. Готовый список ссылок
    """
    profiles = []
    
    if not source:
        print("Введите base64 строку или путь к файлу (пусто для выхода):")
        source = sys.stdin.read().strip()
        if not source:
            return []
    
    # Если это URL
    if source.startswith('http://') or source.startswith('https://'):
        print(f"Загружаем из URL: {source}")
        try:
            response = requests.get(source, timeout=10)
            response.raise_for_status()
            content = response.text.strip()
        except Exception as e:
            print(f"Ошибка загрузки: {e}")
            return []
    
    # Если это файл
    elif os.path.exists(source):
        print(f"Читаем из файла: {source}")
        try:
            with open(source, 'r', encoding='utf-8') as f:
                content = f.read().strip()
        except Exception as e:
            print(f"Ошибка чтения файла: {e}")
            return []
    
    else:
        # Предполагаем что это base64 или прямая ссылка
        content = source.strip()
    
    # Пытаемся декодировать base64
    decoded = decode_b64_if_valid(content)
    if decoded:
        print("Успешно декодировано из base64")
        content = decoded
    
    # Разделяем на строки (каждая строка - отдельный профиль)
    raw_lines = content.split('\n')
    
    for line in raw_lines:
        line = line.strip()
        if line and not line.startswith('#'):
            profiles.append(line)
    
    print(f"Найдено профилей: {len(profiles)}")
    return profiles

def parse_proxy_url(url):
    """Определяет тип прокси и парсит соответствующую ссылку"""
    if url.startswith('vless://'):
        return parse_vless_url(url)
    elif url.startswith('ss://'):
        return parse_ss_url(url)
    elif url.startswith('vmess://'):
        return parse_vmess_url(url)
    else:
        print(f"Пропускаем неподдерживаемый протокол: {url[:50]}...")
        return None

def parse_vless_url(url):
    """Парсит VLESS ссылку в соответствии с логикой Throne"""
    if not url.startswith('vless://'):
        return None
    
    url = url[8:]
    
    try:
        if '@' not in url:
            return None
        
        uuid_part, rest = url.split('@', 1)
        
        server_part = rest
        query_str = ""
        fragment = ""
        
        if '?' in rest:
            server_part, query_part = rest.split('?', 1)
            if '#' in query_part:
                query_str, fragment = query_part.split('#', 1)
            else:
                query_str = query_part
        elif '#' in rest:
            server_part, fragment = rest.split('#', 1)
        
        # Хост и порт
        if ':' in server_part:
            host_port_part = server_part
            if '/' in host_port_part:
                host_port_part = host_port_part.split('/')[0]
            host, port = host_port_part.split(':', 1)
            port = int(port)
        else:
            host = server_part
            port = 443
        
        params = parse_qs(query_str)
        
        config = {
            'protocol': 'vless',
            'uuid': uuid_part,
            'host': host,
            'port': port,
            'type': params.get('type', ['tcp'])[0],
            'security': params.get('security', ['none'])[0],
            'flow': params.get('flow', [''])[0],
            'packet_encoding': params.get('packetEncoding', ['xudp'])[0]
        }
        
        # Параметры транспорта
        if config['type'] == 'grpc':
            config['service_name'] = params.get('serviceName', ['grpc'])[0]
            config['mode'] = params.get('mode', ['gun'])[0]
        elif config['type'] == 'ws':
            config['path'] = params.get('path', ['/'])[0]
            config['host'] = params.get('host', [''])[0]
        elif config['type'] == 'http':
            config['path'] = params.get('path', ['/'])[0]
            config['host'] = params.get('host', [''])[0]
        
        # Параметры TLS/Reality
        if config['security'] in ['tls', 'reality']:
            config['sni'] = params.get('sni', [''])[0]
            config['fp'] = params.get('fp', ['chrome'])[0]
            
            if config['security'] == 'reality':
                config['pbk'] = params.get('pbk', [''])[0]
                config['sid'] = params.get('sid', [''])[0]
                config['spx'] = params.get('spx', ['/'])[0]
        
        # Комментарий
        if fragment:
            config['comment'] = unquote(fragment)
        else:
            config['comment'] = f"VLESS {host}:{port}"
        
        config['raw_url'] = f"vless://{uuid_part}@{host}:{port}"  # Для отображения
        
        return config
    
    except Exception as e:
        print(f"Ошибка парсинга VLESS: {e}")
        return None

def parse_ss_url(url):
    """Парсит Shadowsocks ссылку (упрощенная версия)"""
    if not url.startswith('ss://'):
        return None
    
    url = url[5:]
    
    try:
        # Базовая реализация
        if '#' in url:
            url, fragment = url.split('#', 1)
            comment = unquote(fragment)
        else:
            comment = ""
        
        # Пытаемся декодировать base64
        if '@' in url:
            encoded, server = url.split('@', 1)
            decoded = decode_b64_if_valid(encoded)
            if decoded and ':' in decoded:
                method, password = decoded.split(':', 1)
            else:
                method, password = "chacha20-ietf-poly1305", "password"
        else:
            decoded = decode_b64_if_valid(url)
            if decoded and '@' in decoded:
                auth, server = decoded.split('@', 1)
                if ':' in auth:
                    method, password = auth.split(':', 1)
                else:
                    method, password = "chacha20-ietf-poly1305", "password"
            else:
                return None
        
        if ':' in server:
            host, port = server.split(':', 1)
            port = int(port)
        else:
            host, port = server, 8388
        
        return {
            'protocol': 'shadowsocks',
            'method': method,
            'password': password,
            'host': host,
            'port': port,
            'comment': comment if comment else f"Shadowsocks {host}:{port}",
            'raw_url': f"ss://***@{host}:{port}"
        }
    
    except Exception as e:
        print(f"Ошибка парсинга Shadowsocks: {e}")
        return None

def create_singbox_outbound(config):
    """Создает outbound для sing-box в зависимости от типа прокси"""
    if config['protocol'] == 'vless':
        return create_singbox_vless_config(config)
    elif config['protocol'] == 'shadowsocks':
        return create_singbox_ss_config(config)
    else:
        raise ValueError(f"Неподдерживаемый протокол: {config['protocol']}")

def create_singbox_vless_config(config):
    """Создает конфигурацию VLESS для sing-box"""
    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": config['host'],
        "server_port": config['port'],
        "uuid": config['uuid'],
    }
    
    # Flow
    if config.get('flow'):
        flow = config['flow']
        if flow.endswith('-udp443'):
            flow = flow[:-7]
        elif flow == 'none':
            flow = ''
        if flow:
            outbound["flow"] = flow
    
    # Transport settings
    if config['type'] != 'tcp':
        transport = {"type": config['type']}
        
        if config['type'] == 'ws':
            if config.get('path'):
                path = config['path']
                if '?ed=' in path:
                    path_without_ed = path.split('?ed=')[0]
                    transport["path"] = path_without_ed
                    ed_value = path.split('?ed=')[1]
                    if ed_value.isdigit() and int(ed_value) > 0:
                        transport["max_early_data"] = int(ed_value)
                        transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
                else:
                    transport["path"] = path
            
            if config.get('host'):
                transport["headers"] = {"Host": config['host']}
        
        elif config['type'] == 'grpc':
            if config.get('service_name'):
                transport["service_name"] = config['service_name']
            """
            if config.get('mode') == 'multi':
                transport["multi_mode"] = True
            else:
                transport["multi_mode"] = False
            """
        elif config['type'] == 'http':
            if config.get('path'):
                transport["path"] = config['path']
            if config.get('host'):
                transport["host"] = [config['host']]
            transport["method"] = "GET"
        
        outbound["transport"] = transport
    
    # TLS/Reality settings
    if config['security'] in ['tls', 'reality']:
        tls_config = {"enabled": True}
        
        if config.get('sni'):
            tls_config["server_name"] = config['sni']
        
        tls_config["utls"] = {
            "enabled": True,
            "fingerprint": config.get('fp', 'chrome')
        }
        
        if config['security'] == 'reality' and config.get('pbk'):
            tls_config["reality"] = {
                "enabled": True,
                "public_key": config['pbk'],
                "short_id": config['sid'] if config.get('sid') else ""
            }
        
        outbound["tls"] = tls_config
    
    outbound["packet_encoding"] = config.get('packet_encoding', 'xudp')
    
    return outbound

def create_singbox_ss_config(config):
    """Создает конфигурацию Shadowsocks для sing-box"""
    return {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": config['host'],
        "server_port": config['port'],
        "method": config['method'],
        "password": config['password']
    }

def create_full_singbox_config(outbound):
    """Создает полный конфиг sing-box"""
    return {
        "log": {
            "level": "info",
            "timestamp": True
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-inbound",
                "listen": "127.0.0.1",
                "listen_port": 10808,
                "sniff": True
            }
        ],
        "outbounds": [
            outbound,
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "block",
                "tag": "block"
            }
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": [
                {
                    "protocol": "dns",
                    "outbound": "direct"
                },
                {
                    "clash_mode": "direct",
                    "outbound": "direct"
                },
                {
                    "clash_mode": "global",
                    "outbound": "proxy"
                }
            ]
        }
    }

def select_profile(profiles):
    """Показывает список профилей и позволяет выбрать один"""
    if not profiles:
        print("Нет доступных профилей")
        return None
    
    print("\n" + "="*60)
    print("Доступные профили:")
    print("="*60)
    
    for i, profile in enumerate(profiles, 1):
        print(f"{i:3d}. {profile.get('comment', 'Без названия')}")
        print(f"     {profile.get('protocol', 'unknown').upper()} {profile.get('host', '')}:{profile.get('port', '')}")
        if profile.get('type'):
            print(f"     Тип: {profile.get('type')}, Безопасность: {profile.get('security', 'none')}")
        print()
    
    print("0. Выход")
    print("-"*60)
    
    while True:
        try:
            choice = int(input("Выберите профиль (номер): "))
            if choice == 0:
                return None
            if 1 <= choice <= len(profiles):
                return profiles[choice - 1]
            else:
                print(f"Пожалуйста, выберите число от 0 до {len(profiles)}")
        except ValueError:
            print("Пожалуйста, введите число")

def run_singbox(config_path):
    """Запускает sing-box с указанным конфигом"""
    # Пытаемся найти sing-box
    singbox_path = None
    possible_paths = [
        "/usr/local/bin/sing-box",
        "/usr/bin/sing-box",
        Path.home() / "sing-box" / "sing-box",
        "./sing-box",
        "sing-box"
    ]
    
    for path in possible_paths:
        if isinstance(path, Path):
            path_str = str(path)
        else:
            path_str = path
        
        try:
            result = subprocess.run([path_str, "version"], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                singbox_path = path_str
                print(f"Найден sing-box: {path_str}")
                print(f"Версия: {result.stdout.strip()}")
                break
        except (FileNotFoundError, PermissionError):
            continue
    
    if not singbox_path:
        print("Sing-box не найден в системе. Установите его:")
        print("  Linux: curl -fsSL https://sing-box.app/deb-install.sh | sudo bash")
        print("  MacOS: brew install sing-box")
        print("  Windows: https://github.com/SagerNet/sing-box/releases")
        return False
    
    print(f"\nЗапускаем sing-box...")
    print("Локальный SOCKS5 прокси: 127.0.0.1:10808")
    print("Локальный HTTP прокси: 127.0.0.1:10808")
    print("Для остановки нажмите Ctrl+C")
    print("-"*60)
    
    try:
        process = subprocess.Popen(
            [singbox_path, "run", "-c", str(config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Выводим логи в реальном времени
        for line in process.stdout:
            print(line, end='')
            sys.stdout.flush()
            
    except KeyboardInterrupt:
        print("\nОстанавливаем sing-box...")
        process.terminate()
        process.wait()
        print("Sing-box остановлен")
    except Exception as e:
        print(f"Ошибка запуска: {e}")
        return False
    
    return True

def main():
    """Основная функция"""
    print("Sing-box Config Manager")
    print("=" * 60)
    
    # Выбор источника профилей
    print("\nВыберите источник профилей:")
    print("1. URL (скачать файл)")
    print("2. Локальный файл")
    print("3. Ввести base64 вручную")
    print("4. Использовать тестовый файл из прошлой версии")
    
    choice = input("Ваш выбор (1-4): ").strip()
    
    if choice == '1':
        url = input("Введите URL: ").strip()
        raw_profiles = load_profiles_from_source(url)
    elif choice == '2':
        filepath = input("Введите путь к файлу: ").strip()
        raw_profiles = load_profiles_from_source(filepath)
    elif choice == '3':
        print("Введите base64 строку (Ctrl+D для завершения):")
        content = sys.stdin.read().strip()
        raw_profiles = load_profiles_from_source(content)
    elif choice == '4':
        # Используем тестовые данные из прошлой версии
        test_data = """dmxlc3M6Ly8wMTc2ODE2OS1hYmNlLTQzYTgtOTkwNC00Mjk4YTFjYjdkZTVAcGwuam9qYWNrLnJ1OjQ0Mz9zZWN1cml0eT1yZWFsaXR5JnR5cGU9Z3JwYyZoZWFkZXJUeXBlPSZhdXRob3JpdHk9JnNlcnZpY2VOYW1lPWdycGMmbW9kZT1ndW4mc25pPXBsLmpvamFjay5ydSZmcD1yYW5kb20mcGJrPWhTVHRscFhLQVlWVnU1eWJYM2hRZnE4ZGZzVXJPX0hvRlZnZkdHb0NIVncmc2lkPWYxODlkOTE3NjBiYjY2NjMmc3B4PSUyRiMlRjAlOUYlODclQjUlRjAlOUYlODclQjElMjAlRDAlOUYlRDAlQkUlRDAlQkIlRDElOEMlRDElODglRDAlQjAlMjAoJUYwJTlGJThFJUFGJTIwUm9ibG94KQ=="""
        raw_profiles = load_profiles_from_source(test_data)
    else:
        print("Неверный выбор")
        return
    
    if not raw_profiles:
        print("Не удалось загрузить профили")
        return
    
    # Парсим все профили
    parsed_profiles = []
    for raw_url in raw_profiles:
        profile = parse_proxy_url(raw_url)
        if profile:
            parsed_profiles.append(profile)
        else:
            print(f"Не удалось распарсить: {raw_url[:50]}...")
    
    if not parsed_profiles:
        print("Не удалось распарсить ни один профиль")
        return
    
    # Выбираем профиль
    selected_profile = select_profile(parsed_profiles)
    if not selected_profile:
        print("Выход")
        return
    
    print(f"\nВыбран профиль: {selected_profile.get('comment')}")
    print(f"Протокол: {selected_profile.get('protocol')}")
    print(f"Сервер: {selected_profile.get('host')}:{selected_profile.get('port')}")
    
    # Создаем конфигурацию sing-box
    outbound_config = create_singbox_outbound(selected_profile)
    full_config = create_full_singbox_config(outbound_config)
    
    # Сохраняем конфиг
    config_dir = Path.home() / ".config" / "sing-box"
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_path = config_dir / "config.json"
    backup_path = config_dir / "config.json.backup"
    
    # Делаем бекап старого конфига
    if config_path.exists():
        import shutil
        shutil.copy2(config_path, backup_path)
        print(f"\nСтарый конфиг сохранен как: {backup_path}")
    
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(full_config, f, indent=2, ensure_ascii=False)
    
    print(f"Новый конфиг сохранен: {config_path}")
    
    # Сохраняем выбранный профиль отдельно для быстрого переключения
    profile_path = config_dir / "last_profile.json"
    with open(profile_path, 'w', encoding='utf-8') as f:
        json.dump(selected_profile, f, indent=2, ensure_ascii=False)
    
    # Запускаем sing-box
    print("\nЗапустить sing-box? (y/n): ")
    if input().lower() == 'y':
        run_singbox(config_path)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрограмма прервана")
    except Exception as e:
        print(f"Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()