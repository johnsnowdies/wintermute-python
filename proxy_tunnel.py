#!/usr/bin/env python3
"""
Sing-box Config Generator (на основе кода Throne)
Конвертирует VLESS/Shadowsocks ссылки в конфигурацию Sing-box
"""

import json
import base64
import sys
import re
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
import subprocess
import os

def decode_b64_if_valid(s):
    """Декодирует base64 если возможно (как в Throne)"""
    try:
        missing_padding = len(s) % 4
        if missing_padding:
            s += '=' * (4 - missing_padding)
        return base64.b64decode(s).decode('utf-8')
    except:
        return None

def parse_vless_url(url):
    """Парсит VLESS ссылку в соответствии с логикой Throne"""
    if not url.startswith('vless://'):
        return None
    
    # Убираем протокол
    url = url[8:]
    
    try:
        # Разделяем UUID и остальное
        if '@' not in url:
            return None
        
        uuid_part, rest = url.split('@', 1)
        
        # Разделяем сервер:порт и параметры
        server_part = rest
        query_str = ""
        
        # Проверяем наличие ? и #
        if '?' in rest:
            server_part, query_part = rest.split('?', 1)
            if '#' in query_part:
                query_str, fragment = query_part.split('#', 1)
            else:
                query_str = query_part
        elif '#' in rest:
            server_part, fragment = rest.split('#', 1)
        else:
            server_part = rest
        
        # Хост и порт
        if ':' in server_part:
            host_port_part = server_part
            if '/' in host_port_part:
                host_port_part = host_port_part.split('/')[0]
            host, port = host_port_part.split(':', 1)
            port = int(port)
        else:
            host = server_port_part
            port = 443
        
        # Парсим query параметры (как в Throne)
        params = parse_qs(query_str)
        
        # Извлекаем параметры (с логикой как в Throne)
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
        
        # Параметры TLS/Reality (ключевая часть!)
        if config['security'] in ['tls', 'reality']:
            config['sni'] = params.get('sni', [''])[0]
            config['fp'] = params.get('fp', ['chrome'])[0]
            
            if config['security'] == 'reality':
                config['pbk'] = params.get('pbk', [''])[0]
                config['sid'] = params.get('sid', [''])[0]
                config['spx'] = params.get('spx', ['/'])[0]
        
        # Комментарий
        if '#' in url:
            config['comment'] = unquote(url.split('#', 1)[1])
        else:
            config['comment'] = f"VLESS {host}:{port}"
        
        return config
    
    except Exception as e:
        print(f"Ошибка парсинга VLESS: {e}")
        return None

def create_singbox_vless_config(config):
    """
    Создает конфигурацию VLESS для sing-box на основе кода Throne
    (TrojanVLESSBean::BuildCoreObjSingBox и V2rayStreamSettings::BuildStreamSettingsSingBox)
    """
    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": config['host'],
        "server_port": config['port'],
        "uuid": config['uuid'],
    }
    
    # Flow (обработка как в Throne)
    if config.get('flow'):
        flow = config['flow']
        if flow.endswith('-udp443'):
            flow = flow[:-7]  # Убираем -udp443
        elif flow == 'none':
            flow = ''
        if flow:
            outbound["flow"] = flow
    
    # Transport settings (критически важно!)
    if config['type'] != 'tcp':
        transport = {"type": config['type']}
        
        if config['type'] == 'ws':
            # WebSocket transport
            if config.get('path'):
                # Обработка early data как в Throne
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
            # gRPC transport (исправление основной ошибки!)
            if config.get('service_name'):
                transport["service_name"] = config['service_name']
            
            # mode определяет multiMode (gun = false, multi = true)
            """
            if config.get('mode') == 'multi':
                transport["multi_mode"] = True
            else:
                transport["multi_mode"] = False
            """
        elif config['type'] == 'http':
            # HTTP transport
            if config.get('path'):
                transport["path"] = config['path']
            if config.get('host'):
                transport["host"] = [config['host']]
            transport["method"] = "GET"
        
        outbound["transport"] = transport
    
    # TLS/Reality settings (основная часть!)
    if config['security'] in ['tls', 'reality']:
        tls_config = {"enabled": True}
        
        if config.get('sni'):
            tls_config["server_name"] = config['sni']
        
        # uTLS fingerprint
        tls_config["utls"] = {
            "enabled": True,
            "fingerprint": config.get('fp', 'chrome')
        }
        
        # Reality (самая важная часть)
        if config['security'] == 'reality' and config.get('pbk'):
            tls_config["reality"] = {
                "enabled": True,
                "public_key": config['pbk'],
                "short_id": config['sid'] if config.get('sid') else ""
            }
        
        outbound["tls"] = tls_config
    
    # Packet encoding (как в Throne)
    outbound["packet_encoding"] = config.get('packet_encoding', 'xudp')
    
    return outbound

def create_singbox_full_config(proxy_config):
    """Создает полный конфиг sing-box"""
    singbox_config = {
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
            proxy_config,
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
    return singbox_config

def main():
    """Основная функция"""
    print("Sing-box Config Generator (на основе Throne)")
    print("=" * 50)
    
    # Получаем конфиг от пользователя
    print("\nВведите VLESS ссылку:")
    url = input().strip()
    
    # Парсим URL
    config = parse_vless_url(url)
    if not config:
        print("Ошибка: неверный формат ссылки")
        return
    
    print(f"\nПарсинг успешен:")
    print(f"  Сервер: {config['host']}:{config['port']}")
    print(f"  Тип: {config['type']}, Безопасность: {config['security']}")
    print(f"  Комментарий: {config.get('comment', 'Нет')}")
    
    # Создаем конфиг sing-box
    proxy_config = create_singbox_vless_config(config)
    full_config = create_singbox_full_config(proxy_config)
    
    # Сохраняем конфиг
    config_dir = Path.home() / ".config" / "sing-box"
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_path = config_dir / "config.json"
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(full_config, f, indent=2, ensure_ascii=False)
    
    print(f"\nКонфигурация сохранена в: {config_path}")
    
    # Запускаем sing-box
    print("\nЗапустить sing-box? (y/n): ")
    if input().lower() == 'y':
        # Пытаемся найти sing-box
        singbox_path = None
        possible_paths = [
            "/usr/local/bin/sing-box",
            "/usr/bin/sing-box",
            Path.home() / "sing-box" / "sing-box",
            "./sing-box"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                singbox_path = path
                break
        
        if not singbox_path:
            print("Sing-box не найден. Установите его:")
            print("  Linux: curl -fsSL https://sing-box.app/deb-install.sh | sudo bash")
            print("  MacOS: brew install sing-box")
            print("  Windows: https://github.com/SagerNet/sing-box/releases")
            return
        
        print(f"Запускаем sing-box... (SOCKS5: 127.0.0.1:10808)")
        print("Для остановки нажмите Ctrl+C")
        
        try:
            subprocess.run([singbox_path, "run", "-c", str(config_path)], 
                          check=True)
        except KeyboardInterrupt:
            print("\nSing-box остановлен")
        except Exception as e:
            print(f"Ошибка запуска: {e}")

if __name__ == "__main__":
    main()