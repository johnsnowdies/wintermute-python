# Wintermute

Automatic proxy tunnel manager supporting sing-box and xray-core. Downloads profiles from remote sources, tests them for latency and content integrity, selects the best one, and monitors the tunnel with automatic failover.

## Features

- **Dual-engine support** — works with sing-box (TUN/mixed proxy mode) and xray-core (TUN/VLESS Reality/xHTTP/gRPC)
- **Profile sources** — load subscription URLs in base64 or plain text format (VLESS, Shadowsocks)
- **Smart selection** — tests TCP connectivity and optionally verifies content via MD5; selects the lowest-latency profile
- **Health monitoring** — periodic HTTP health checks with configurable failure threshold and auto-switch
- **Auto-refresh** — background profile refresh from sources without interrupting the current tunnel
- **Caching** — caches profiles to disk with fallback on source unavailability
- **Backup profiles** — tries backup profiles on failure before full re-test
- **TUN mode** — routes all system traffic through the tunnel
- **Proxy mode** — runs as a local SOCKS5 proxy for selective routing
- **USB loading** — loads profiles from a USB drive (profiles_*.json files)
- **TUI** — terminal UI with hotkeys, live log panels, profile list, and configuration editor

## Requirements

- Python 3.7+
- sing-box or xray-core (see installation below)
- Root privileges (required for TUN interface, routing, and iptables)

## Installation

### 1. Install sing-box

```bash
curl -fsSL https://sing-box.app/deb-install.sh | sudo bash
```

Or download from [releases](https://github.com/SagerNet/sing-box/releases).

### 2. Install xray-core

```bash
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
```

Or download from [releases](https://github.com/XTLS/Xray-core/releases).

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

Or using a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4. Clone the repository

```bash
git clone https://github.com/your-username/wintermute
cd wintermute
```

## Configuration

Copy the example config and edit it:

```bash
cp config.example.yaml config.yaml
```

Key configuration sections:

- **sources** — subscription URLs with refresh intervals and optional filters
- **network** — WAN interface, TUN interface settings, excluded subnets
- **testing** — healthcheck URLs, timeout, failure threshold
- **selection** — strategy (latency), minimum acceptable latency, backup profile count
- **cache** — caching directory and fallback behavior
- **logging** — log level, format, file output

### Example config

```yaml
sources:
  - url: "https://example.com/subscription"
    type: "base64"
    refresh: "1h"
    enabled: true

network:
  wan_interface: "eth0"
  exclude_subnets:
    - "192.168.0.0/16"
  tun:
    name: "wintermute-tun"
    subnet: "172.19.0.0/30"
    mtu: 1500

testing:
  healthcheck_urls:
    - "https://1.1.1.1/cdn-cgi/trace"
    - "http://connectivitycheck.gstatic.com/generate_204"
  timeout: 5
  healthcheck_interval: "30s"
  failure_threshold: 3
  max_test: 100

selection:
  strategy: "latency"
  min_acceptable_latency: 500
  auto_switch: true
  backup_profiles_count: 3
```

## Usage

The application must be run as **root** because it creates a TUN interface, modifies routing tables, and configures iptables rules.

Using the virtual environment:

```bash
sudo .venv/bin/python src/wintermute.py
```

Or specifying a custom config path:

```bash
sudo .venv/bin/python src/wintermute.py -c /path/to/config.yaml
```

### Hotkeys

| Key | Action |
|-----|--------|
| F1 | Toggle help |
| F2 | Manual profile selection |
| F3 | Manage profile sources |
| F4 | Edit application configuration |
| F5 | Reload profiles from sources |
| F6 | Switch to next best profile (current marked as broken) |
| F7 | Clear broken profiles and start full re-test |
| F8 | Load profiles from USB drive |
| F9 | Toggle healthcheck |

Press Ctrl+C to terminate.

## How it works

1. **Profile loading** — Wintermute downloads profiles from configured sources
2. **Caching** — saves profiles to disk; uses cache when sources are unavailable
3. **Testing** — tests TCP connectivity to the first N profiles, optionally verifies response content via MD5 hash
4. **Selection** — picks the profile with the lowest latency
5. **Engine launch** — generates an engine-specific config (sing-box or xray depending on protocol/transport) and starts it as a child process in TUN mode
6. **Monitoring** — healthchecker periodically verifies tunnel connectivity
7. **Failover** — on failure, tries backup profiles first, then performs a full re-test
8. **Refresh** — profiles are updated in the background at the configured interval

## Supported protocols and transports

- VLESS (TCP, WebSocket, gRPC, HTTP, xHTTP)
- VLESS with TLS and Reality
- Shadowsocks (AEAD ciphers)

Engine selection is automatic: profiles with xHTTP transport use xray-core; all others use sing-box.

## Debugging

Enable debug logging in config.yaml:

```yaml
logging:
  level: "debug"
```

Check TUN interface:

```bash
ip link show wintermute-tun
ip addr show wintermute-tun
```

## Compatibility

Tested on:
- Ubuntu 22.04+
- Debian 11+
- Arch Linux

## License

MIT