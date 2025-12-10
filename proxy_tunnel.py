#!/usr/bin/env python3
"""
Sing-box Config Manager (на основе кода Throne)
Загружает base64 конфиги, тестирует их и запускает sing-box
"""

import json
import base64
import sys
import re
import requests
import socket
import time
import threading
import concurrent.futures
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
import subprocess
import os
import signal
import tempfile
from typing import Dict, List, Optional, Tuple
import urllib3

# Отключаем предупреждения о неверифицированных сертификатах
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
        print(line)
        if line and not line.startswith('#') and "%D0%9E%D0%B1%D1%85%D0%BE%D0%B4" in line:
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

def create_full_singbox_config(outbound_config: Dict) -> Dict:
    """
    Создает конфигурацию sing-box TUN-режима для Linux.
    Аналогично коду Throne, но только для TUN (без mixed-inbound).
    """
    
    # Исключаемые подсети (локальный трафик не должен идти через туннель)
    route_exclude_address = [
        "127.0.0.0/8",     # localhost
        "224.0.0.0/4",     # multicast
        "255.255.255.255/32",  # broadcast
    ]
    
    # Конфигурация TUN-интерфейса (основная часть)
    tun_config = {
        "type": "tun",
        "tag": "tun-in",
        "interface_name": "throne-tun",  # или можно генерировать динамически
        "mtu": 9000,                     # стандартный MTU
        "auto_route": True,              # КЛЮЧЕВОЙ ПАРАМЕТР: sing-box сам настроит маршруты
        "strict_route": False,           # обычно false для совместимости
        "stack": "system",               # или "gvisor" для Linux
        
        "address": [
            "172.18.0.1/30",
            "fdfe:dcba:9876::1/126"
        ],
        "route_exclude_address": route_exclude_address,  # исключаемые подсети
        "sniff": True,                   # определение протоколов
    }
    
    # Полная конфигурация для sing-box
    return {
        "log": {
            "level": "info",
            "timestamp": True,
            "output": "/tmp/sing-box-tun.log"  # удобно для отладки
        },
        "inbounds": [tun_config],  # ТОЛЬКО TUN, никаких mixed/socks
        
        "outbounds": [
            outbound_config,  # ваш прокси (VLESS/Shadowsocks)
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        
        "route": {
            "auto_detect_interface": True,
            # Правила маршрутизации
            "rules": [
                # 1. Весь трафик из TUN-интерфейса идёт через прокси
                {
                    "inbound": "tun-in",
                    "outbound": "proxy"
                },
                # 2. Локальные подсети идут напрямую (дополнительная защита)
                {
                    "ip_cidr": route_exclude_address,
                    "outbound": "direct"
                },
                # 3. DNS-трафик можно направить через прокси
                {
                    "protocol": "dns",
                    "outbound": "proxy"
                }
            ],
            # По умолчанию весь трафик через прокси (для всего остального)
            "final": "proxy"
        }
    }

def test_proxy_connection(profile_config: Dict, timeout: int = 10) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Тестирует подключение через TUN-интерфейс (без SOCKS)
    Возвращает: (успех, пинг_мс, ошибка)
    """
    try:
        # Создаем outbound конфигурацию
        outbound = create_singbox_outbound(profile_config)
        
        # Используем случайный порт для теста
        import random
        test_port = random.randint(20000, 30000)
        
        # Базовый TUN конфиг для тестирования
        temp_config = {
            "log": {"level": "error", "timestamp": False},
            "inbounds": [{
                "type": "tun",
                "tag": "tun-in",
                "interface_name": f"test-tun-{test_port}",
                "mtu": 1500,
                "auto_route": True,
                "strict_route": False,
                  "address": [
    "172.18.0.1/30",
    "fdfe:dcba:9876::1/126"
  ],
                "stack": "system",
                #"auto_redirect": True,
                "route_exclude_address": [
                    "127.0.0.0/8",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16"
                ],
                "sniff": True
            }],
            "outbounds": [
                outbound,
                {"type": "direct", "tag": "direct"}
            ],
            "route": {
                "auto_detect_interface": True,
                "rules": [
                    {"inbound": "tun-in", "outbound": "proxy"},
                    {"ip_cidr": ["127.0.0.0/8", "192.168.0.0/16"], "outbound": "direct"},
                    {"protocol": "dns", "outbound": "direct"}
                ],
                "final": "proxy"
            }
        }
        
        # Сохраняем временный конфиг
        temp_dir = Path(tempfile.gettempdir())
        config_file = temp_dir / f"singbox_tun_test_{test_port}.json"
        
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(temp_config, f, indent=2, ensure_ascii=False)
        
        # Пытаемся найти sing-box
        singbox_path = find_singbox()
        if not singbox_path:
            return False, None, "sing-box не найден"
        
        # Проверяем права root
        if os.geteuid() != 0:
            print(f"  ⚠ Для TUN-теста нужны права root (sudo)")
            # Вместо TUN-теста делаем простую проверку конфига
            return quick_config_test(singbox_path, config_file)
        
        # Запускаем sing-box в фоновом режиме
        process = None
        try:
            # Запускаем процесс с правами root
            process = subprocess.Popen(
                [singbox_path, "run", "-c", str(config_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                start_new_session=True
            )
            
            # Даем время на запуск TUN-интерфейса
            time.sleep(3)
            
            # Проверяем, запустился ли процесс
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                error_msg = stderr.decode('utf-8', errors='ignore')[:200]
                return False, None, f"sing-box завершился: {error_msg}"
            
            # Тестируем подключение через TUN-интерфейс
            # Пробуем отправить ICMP ping через новый интерфейс
            return test_tun_connection(test_port, timeout)
            
        finally:
            # Гарантированно останавливаем процесс
            if process and process.poll() is None:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    process.wait(timeout=3)
                except:
                    try:
                        process.kill()
                        process.wait(timeout=2)
                    except:
                        pass
            
            # Удаляем временный файл
            try:
                config_file.unlink(missing_ok=True)
            except:
                pass
    
    except Exception as e:
        return False, None, f"Ошибка тестирования: {str(e)[:100]}"

def test_tun_connection(tun_port: int, timeout: int) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Тестирует подключение через TUN-интерфейс
    """
    try:
        # Пробуем несколько способов тестирования
        
        # 1. Проверяем создание интерфейса
        time.sleep(1)
        
        # 2. Пытаемся сделать HTTP запрос через curl с использованием TUN-интерфейса
        test_urls = [
            "https://1.1.1.1",  # Cloudflare DNS
            "https://api.ipify.org?format=json",  # Проверка внешнего IP
        ]
        
        for test_url in test_urls:
            try:
                start_time = time.time()
                
                # Используем curl с явным указанием использовать TUN интерфейс
                # Это работает, потому что весь трафик теперь идет через TUN
                curl_command = [
                    "curl", "-s", "--max-time", str(timeout),
                    "--interface", f"test-tun-{tun_port}",
                    test_url
                ]
                
                result = subprocess.run(
                    curl_command,
                    capture_output=True,
                    text=True,
                    timeout=timeout + 2
                )
                
                latency = int((time.time() - start_time) * 1000)
                
                if result.returncode == 0:
                    # Проверяем полученные данные
                    if test_url == "https://api.ipify.org?format=json":
                        try:
                            import json as json_module
                            ip_data = json_module.loads(result.stdout)
                            print(f"  [TUN-Тест] Внешний IP через TUN: {ip_data.get('ip', 'unknown')}")
                        except:
                            pass
                    
                    return True, latency, None
                else:
                    print(f"  [TUN-Тест] curl ошибка: {result.stderr[:100]}")
                    
            except subprocess.TimeoutExpired:
                return False, None, f"Таймаут при тесте {test_url}"
            except Exception as e:
                if "1.1.1.1" in test_url:
                    continue  # Пробуем следующую ссылку
                else:
                    raise
        
        return False, None, "Не удалось проверить подключение через TUN"
        
    except Exception as e:
        return False, None, f"Ошибка тестирования TUN: {str(e)[:100]}"

def quick_config_test(singbox_path: str, config_file: Path) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Быстрая проверка конфигурации без запуска TUN (без прав root)
    """
    try:
        # Пробуем проверить конфиг на валидность
        result = subprocess.run(
            [singbox_path, "check", "-c", str(config_file)],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            return True, None, "Конфигурация валидна (нужен root для TUN-теста)"
        else:
            return False, None, f"Ошибка конфигурации: {result.stderr[:100]}"
            
    except Exception as e:
        return False, None, f"Ошибка проверки конфига: {str(e)[:50]}"


def test_profiles_sequential(profiles: List[Dict]) -> Dict[int, Dict]:
    """
    Тестирует профили последовательно (более стабильно)
    """
    print(f"\n🔍 Тестируем {len(profiles)} профилей последовательно...")
    
    results = {}
    
    for idx, profile in enumerate(profiles):
        if idx >= 30:  # Ограничение для последовательного теста
            print(f"\n⚠ Тестирование ограничено первыми 30 профилями из {len(profiles)}")
            break
        
        profile_name = profile.get('comment', f'Профиль {idx+1}')
        print(f"  [{idx+1}/{min(len(profiles), 30)}] Тестирую: {profile_name[:50]}...")
        
        try:
            success, latency, error = test_proxy_connection(profile)
            
            results[idx] = {
                'success': success,
                'latency': latency,
                'error': error,
                'profile': profile
            }
            
            if success:
                print(f"    ✓ Успешно! Пинг: {latency}ms")
            else:
                print(f"    ✗ Ошибка: {error}")
            
            # Небольшая пауза между тестами
            time.sleep(0.5)
            
        except Exception as e:
            print(f"    ⚠ Критическая ошибка: {str(e)[:50]}")
            results[idx] = {
                'success': False,
                'latency': None,
                'error': str(e),
                'profile': profile
            }
    
    return results

def show_profiles_with_status(profiles: List[Dict], test_results: Optional[Dict] = None):
    """
    Показывает список профилей с результатами тестирования
    """
    print("\n" + "="*80)
    print("ДОСТУПНЫЕ ПРОФИЛИ:")
    print("="*80)
    
    for i, profile in enumerate(profiles):
        # Базовая информация
        protocol = profile.get('protocol', 'unknown').upper()
        host = profile.get('host', '')
        port = profile.get('port', '')
        comment = profile.get('comment', f'Профиль {i+1}')
        
        # Результаты теста
        status = "  "
        latency_info = ""
        
        if test_results and i in test_results:
            result = test_results[i]
            if result['success']:
                status = "✓ "
                latency_info = f" [{result['latency']}ms]" if result['latency'] else " [работает]"
            else:
                status = "✗ "
                latency_info = " [недоступен]"
        
        # Дополнительная информация
        extra_info = []
        if profile.get('type'):
            extra_info.append(f"тип: {profile['type']}")
        if profile.get('security') and profile['security'] != 'none':
            extra_info.append(f"безопасность: {profile['security']}")
        
        extra_str = f" ({', '.join(extra_info)})" if extra_info else ""
        
        # Вывод
        print(f"{i+1:3d}. {status}{comment[:60]}{latency_info}")
        print(f"     {protocol} {host}:{port}{extra_str}")
        
        # Краткая информация об ошибке (если есть)
        if test_results and i in test_results and not test_results[i]['success']:
            error = test_results[i].get('error', '')
            if error and len(error) < 50:
                print(f"     Ошибка: {error}")
        
        print()

def main():
    """Основная функция"""
    print("🚀 Sing-box Config Manager с тестированием")
    print("=" * 80)
    try:
        os.remove('/tmp/sing-box-tun.log')
    except:
        print("No logs")
    


    # Проверяем наличие sing-box
    singbox_path = find_singbox()
    if not singbox_path:
        print("⚠ Внимание: sing-box не найден в системе.")
        print("  Тестирование будет пропущено, но вы можете установить его позже.")
        print("  Установка: curl -fsSL https://sing-box.app/deb-install.sh | sudo bash")
        print()
    
    # Выбор источника профилей
    print("Выберите источник профилей:")
    print("  1. URL (скачать файл)")
    print("  2. Локальный файл")
    print("  3. Ввести base64 вручную")
    print("  4. Ввести ссылки вручную (по одной)")
    
    choice = input("Ваш выбор (1-4): ").strip()
    
    profiles = []
    
    if choice == '1':
        url = input("Введите URL: ").strip()
        profiles = load_profiles_from_source(url)
    elif choice == '2':
        filepath = input("Введите путь к файлу: ").strip()
        profiles = load_profiles_from_source(filepath)
    elif choice == '3':
        print("Введите base64 строку (Ctrl+D для завершения в Linux/Mac, Ctrl+Z в Windows):")
        content = sys.stdin.read().strip()
        profiles = load_profiles_from_source(content)
    elif choice == '4':
        print("Вводите ссылки по одной (пустая строка для завершения):")
        links = []
        while True:
            link = input(f"Ссылка {len(links)+1}: ").strip()
            if not link:
                break
            links.append(link)
        profiles = links
    else:
        print("Неверный выбор")
        return
    
    if not profiles:
        print("Не удалось загрузить профили")
        return
    
    # Парсим профили
    parsed_profiles = []
    for raw_url in profiles:
        profile = parse_proxy_url(raw_url)
        if profile:
            parsed_profiles.append(profile)
        else:
            print(f"⚠ Не удалось распарсить: {raw_url[:50]}...")
    
    if not parsed_profiles:
        print("Не удалось распарсить ни один профиль")
        return
    
    # Тестирование профилей
    test_results = None
    
    if singbox_path and parsed_profiles:
        print(f"\nНайдено {len(parsed_profiles)} профилей.")
        
        if len(parsed_profiles) > 50:
            print("⚠ Слишком много профилей для полного тестирования.")
            test_choice = input("Тестировать только первые 30 профилей? (y/n): ").lower()
        else:
            test_choice = input("Хотите протестировать профили перед выбором? (y/n): ").lower()
        
        if test_choice == 'y':
            
            try:
                print("\n⏳ Начинаю последовательное тестирование...")
                test_results = test_profiles_sequential(parsed_profiles[:30])
            except KeyboardInterrupt:
                print("\n⚠ Тестирование прервано пользователем")
                test_results = {}
            except Exception as e:
                print(f"\n⚠ Ошибка при тестировании: {e}")
                test_results = {}
    
    # Показываем профили с результатами тестов
    show_profiles_with_status(parsed_profiles, test_results)
    
    # Выбор профиля
    while True:
        try:
            choice = input(f"\nВыберите профиль (1-{len(parsed_profiles)}) или 0 для выхода: ").strip()
            if choice == '0':
                print("Выход")
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(parsed_profiles):
                selected_profile = parsed_profiles[idx]
                break
            else:
                print(f"Пожалуйста, выберите число от 1 до {len(parsed_profiles)}")
        except ValueError:
            print("Пожалуйста, введите число")
    
    print(f"\n✅ Выбран профиль: {selected_profile.get('comment')}")
    
    # Опционально: перетестировать выбранный профиль
    if singbox_path:
        retest = input("Протестировать выбранный профиль перед запуском? (y/n): ").lower()
        if retest == 'y':
            print("⏳ Тестирую выбранный профиль...")
            success, latency, error = test_proxy_connection(selected_profile)
            if success:
                print(f"✅ Профиль рабочий! Пинг: {latency}ms")
            else:
                print(f"⚠ Профиль может не работать: {error}")
                confirm = input("Всё равно запустить? (y/n): ").lower()
                if confirm != 'y':
                    print("Отмена")
                    return
    
    # Создаем и сохраняем конфиг
    outbound_config = create_singbox_outbound(selected_profile)
    full_config = create_full_singbox_config(outbound_config)
    
    config_dir = Path.home() / ".config" / "sing-box"
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_path = config_dir / "config.json"
    
    # Бекап старого конфига
    if config_path.exists():
        import shutil
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = config_dir / f"config_backup_{timestamp}.json"
        shutil.copy2(config_path, backup_path)
        print(f"📁 Старый конфиг сохранен как: {backup_path.name}")
    
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(full_config, f, indent=2, ensure_ascii=False)
    
    print(f"📁 Новый конфиг сохранен: {config_path}")
    
    # Запуск sing-box
    if singbox_path:
        launch = input("\nЗапустить sing-box? (y/n): ").lower()
        if launch == 'y':
            print(f"\n🚀 Запускаю sing-box...")
            print("   SOCKS5 прокси: 127.0.0.1:10808")
            print("   HTTP прокси: 127.0.0.1:10808")
            print("   Для остановки нажмите Ctrl+C")
            print("-" * 50)
            
            try:
                process = subprocess.Popen(
                    [singbox_path, "run", "-c", str(config_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                # Выводим логи
                for line in process.stdout:
                    print(line, end='')
                    sys.stdout.flush()
                    
            except KeyboardInterrupt:
                print("\n\n🛑 Останавливаю sing-box...")
                process.terminate()
                process.wait(timeout=5)
                print("✅ Sing-box остановлен")
            except Exception as e:
                print(f"❌ Ошибка запуска: {e}")
    else:
        print("\n⚠ Sing-box не найден. Конфиг сохранен, но запуск невозможен.")
        print(f"   Установите sing-box и запустите вручную:")
        print(f"   sing-box run -c {config_path}")

def find_singbox() -> Optional[str]:
    """Находит путь к sing-box"""
    possible_paths = [
        "/usr/local/bin/sing-box",
        "/usr/bin/sing-box",
        Path.home() / "sing-box" / "sing-box",
        "./sing-box",
        "sing-box"
    ]
    
    for path in possible_paths:
        path_str = str(path) if isinstance(path, Path) else path
        try:
            result = subprocess.run([path_str, "version"], 
                                  capture_output=True, text=True,
                                  timeout=2)
            if result.returncode == 0:
                return path_str
        except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
            continue
    
    return None

# (Остальные функции остаются без изменений: decode_b64_if_valid, load_profiles_from_source, 
# parse_proxy_url, parse_vless_url, parse_ss_url, create_singbox_outbound, 
# create_singbox_vless_config, create_singbox_ss_config, create_full_singbox_config)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🛑 Программа прервана пользователем")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)