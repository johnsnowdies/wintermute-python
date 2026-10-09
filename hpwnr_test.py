#!/usr/bin/env python3
"""
Proof of Concept: decrypt Happ-encrypted subscription links via hpwnr
and parse the resulting VLESS profiles.

Usage:
    python hpwnr_test.py [example.txt]

Happ links are often nested:  happ://crypt4/...  →  https://sub.example/...  →  vless://...
hpwnr unwraps the first layer; the script follows the second automatically.

Requires:
    hpwnr CLI — https://github.com/Omegaplexx/hpwnr
    pip install requests   (for fetching nested subscription URLs)
"""

import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional
from urllib.parse import parse_qs, unquote

import requests


# ═══════════════════════════════════════════════════════════════════════════
#  hpwnr wrapper
# ═══════════════════════════════════════════════════════════════════════════

def find_hpwnr() -> Optional[str]:
    import shutil
    return shutil.which("hpwnr")


def decrypt_happ(url: str, hpwnr_bin: str) -> Optional[str]:
    """Decrypt a single happ://crypt* link → stdout text."""
    try:
        result = subprocess.run(
            [hpwnr_bin, url],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            print(f"    ⚠ hpwnr exited {result.returncode}: "
                  f"{result.stderr.strip()}", file=sys.stderr)
            return None
        out = result.stdout.strip()
        return out if out else None
    except FileNotFoundError:
        print(f"    ⚠ hpwnr not found at {hpwnr_bin}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print(f"    ⚠ hpwnr timed out for {url[:60]}...", file=sys.stderr)
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  URL detection helpers
# ═══════════════════════════════════════════════════════════════════════════

def is_http_url(text: str) -> bool:
    """True if the whole string looks like a plain http(s) URL."""
    t = text.strip()
    return t.startswith("http://") or t.startswith("https://")


def is_vless_url(text: str) -> bool:
    return text.strip().startswith("vless://")


def extract_happ_urls(text: str) -> List[str]:
    """Extract all happ://crypt* lines, ignoring trailing garbage."""
    urls = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.search(r'(happ://crypt[0-9]+/[^\s\[\]<>]+)', line)
        if m:
            urls.append(m.group(1))
    return urls


# ═══════════════════════════════════════════════════════════════════════════
#  Fetch subscription content
# ═══════════════════════════════════════════════════════════════════════════

def fetch_subscription(url: str) -> Optional[str]:
    """Fetch plaintext subscription from an HTTPS URL, decode base64 if needed."""
    try:
        resp = requests.get(url, timeout=15, verify=False)
        resp.raise_for_status()
    except Exception as e:
        print(f"    ⚠ fetch failed: {e}", file=sys.stderr)
        return None

    raw = resp.text.strip()

    import base64
    # Try base64 decode if it looks like base64
    try:
        decoded = base64.b64decode(raw).decode("utf-8").strip()
        if decoded:
            return decoded
    except Exception:
        pass

    return raw


def parse_json_subscription(text: str) -> List[str]:
    """
    If text is a JSON array of subscription entries, try to convert each
    to a vless:// URI.  Returns a list of URIs (may be empty if parsing
    fails or none are convertible).
    """
    import json
    import base64

    text = text.strip()
    # Some providers wrap JSON in base64
    if not text.startswith("["):
        try:
            decoded = base64.b64decode(text).decode("utf-8").strip()
            if decoded.startswith("["):
                text = decoded
        except Exception:
            pass

    if not text.startswith("["):
        return []

    try:
        entries = json.loads(text)
    except json.JSONDecodeError:
        return []

    if not isinstance(entries, list):
        return []

    uris = []
    for ent in entries:
        if not isinstance(ent, dict):
            continue

        # Try to build a vless:// URI from JSON fields
        # Standard V2Ray JSON format
        if "id" in ent and "address" in ent:
            # Xray-style: { "id": ..., "address": ..., "port": ..., ... }
            uuid = ent.get("id", "")
            host = ent.get("address", "")
            port = ent.get("port", 443)
            enc = ent.get("encryption", "none")
            net = ent.get("network", "tcp")
            sec = ent.get("security", "none")

            params = []
            params.append(f"encryption={enc}")
            params.append(f"type={net}")
            if sec not in ("", "none"):
                params.append(f"security={sec}")
            if ent.get("path"):
                params.append(f"path={ent['path']}")
            if ent.get("host"):
                params.append(f"host={ent['host']}")
            if ent.get("sni"):
                params.append(f"sni={ent['sni']}")
            if ent.get("pbk"):
                params.append(f"pbk={ent['pbk']}")
            if ent.get("sid"):
                params.append(f"sid={ent['sid']}")
            if ent.get("fp"):
                params.append(f"fp={ent['fp']}")

            qs = "&".join(params)
            remark = ent.get("remarks", ent.get("comment", f"{host}:{port}"))
            uri = f"vless://{uuid}@{host}:{port}?{qs}#{remark}"
            uris.append(uri)

        elif "id" in ent and "server" in ent and "server_port" in ent:
            # Alternative: { "id": ..., "server": ..., "server_port": ..., "type": ... }
            uuid = ent.get("id", "")
            host = ent.get("server", "")
            port = ent.get("server_port", 443)

            params = []
            net = ent.get("network", "tcp")
            sec = ent.get("security", "none")
            params.append(f"encryption=none")
            params.append(f"type={net}")
            if sec not in ("", "none"):
                params.append(f"security={sec}")
            if ent.get("path"):
                params.append(f"path={ent['path']}")
            if ent.get("host"):
                params.append(f"host={ent['host']}")
            if ent.get("sni"):
                params.append(f"sni={ent['sni']}")
            if ent.get("pbk"):
                params.append(f"pbk={ent['pbk']}")
            if ent.get("sid"):
                params.append(f"sid={ent['sid']}")

            qs = "&".join(params)
            remark = ent.get("remarks", ent.get("comment", f"{host}:{port}"))
            uri = f"vless://{uuid}@{host}:{port}?{qs}#{remark}"
            uris.append(uri)

    return uris


def resolve_content(text: str, hpwnr_bin: str) -> str:
    """
    Decode + follow one level of nesting.
    happ://crypt → http(s) → vless://  (or JSON → VLESS URI)
    """
    lines = text.splitlines()
    if len(lines) == 1 and is_http_url(lines[0]):
        print(f"    ↳ nested subscription URL detected, fetching …")
        fetched = fetch_subscription(lines[0])
        if fetched:
            # Check if the fetched content is JSON → convert
            json_uris = parse_json_subscription(fetched)
            if json_uris:
                return "\n".join(json_uris)
            return fetched
        return text  # fallback to original
    return text


# ═══════════════════════════════════════════════════════════════════════════
#  VLESS parser (minimal — mirrors profile_manager.py logic)
# ═══════════════════════════════════════════════════════════════════════════

def parse_vless(url: str) -> Optional[dict]:
    """Parse a vless:// URI → dict or None."""
    if not url.startswith("vless://"):
        return None

    body = url[8:]

    try:
        if "@" not in body:
            return None
        uuid_part, rest = body.split("@", 1)

        server_part = rest
        query_str = ""
        fragment = ""

        if "?" in rest:
            server_part, query_part = rest.split("?", 1)
            if "#" in query_part:
                query_str, fragment = query_part.split("#", 1)
            else:
                query_str = query_part
        elif "#" in rest:
            server_part, fragment = rest.split("#", 1)

        if ":" in server_part:
            host_port_part = server_part
            if "/" in host_port_part:
                host_port_part = host_port_part.split("/")[0]
            host, port = host_port_part.split(":", 1)
            port = int(port)
        else:
            host = server_part
            port = 443

        params = parse_qs(query_str)

        extra = {
            "type": params.get("type", ["tcp"])[0],
            "security": params.get("security", ["none"])[0],
            "flow": params.get("flow", [""])[0],
        }
        if extra["security"] in ("tls", "reality"):
            extra["sni"] = params.get("sni", [""])[0]
            extra["fp"] = params.get("fp", ["chrome"])[0]
        if extra["security"] == "reality":
            extra["pbk"] = params.get("pbk", [""])[0]
            extra["sid"] = params.get("sid", [""])[0]
        if extra["type"] in ("ws", "xhttp", "http"):
            extra["path"] = params.get("path", [""])[0]
        if extra["type"] == "ws":
            extra["ws_host"] = params.get("host", [""])[0]
        if extra["type"] == "xhttp":
            extra["host"] = params.get("host", [""])[0]
            extra["mode"] = params.get("mode", ["auto"])[0]

        comment = unquote(fragment) if fragment else f"VLESS {host}:{port}"

        return {
            "protocol": "vless",
            "uuid": uuid_part,
            "host": host,
            "port": port,
            "comment": comment,
            "extra": extra,
        }
    except Exception as e:
        print(f"    ⚠ parse error: {e}", file=sys.stderr)
        return None


def profile_badge(p: dict) -> str:
    """X (xhttp) / S (sing-box native)."""
    return "X" if p["extra"].get("type") == "xhttp" else "S"


# ═══════════════════════════════════════════════════════════════════════════
#  main
# ═══════════════════════════════════════════════════════════════════════════

def main():
    hpwnr_bin = find_hpwnr()
    if not hpwnr_bin:
        print("hpwnr not found.  Install:")
        print("  git clone https://github.com/Omegaplexx/hpwnr.git")
        print("  cd hpwnr && cargo build --release")
        print("  cp target/release/hpwnr ~/.cargo/bin/")
        sys.exit(1)

    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("example.txt")
    if not input_path.exists():
        print(f"File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    raw_text = input_path.read_text(encoding="utf-8")
    happ_urls = extract_happ_urls(raw_text)

    if not happ_urls:
        print("No happ://crypt* URLs found in", input_path)
        sys.exit(0)

    # ── Step 1: decrypt ────────────────────────────────────────────────
    print(f"Found {len(happ_urls)} Happ encrypted URL(s)\n")
    decrypted: List[tuple[str, str]] = []  # (original_url, plaintext)

    for i, url in enumerate(happ_urls, 1):
        short = url[:68] + "…" if len(url) > 72 else url
        print(f"  [{i}/{len(happ_urls)}] decrypting … ", end="", flush=True)
        plain = decrypt_happ(url, hpwnr_bin)
        if plain is None:
            print("❌")
            continue
        print("✅")
        decrypted.append((url, plain))

    if not decrypted:
        print("\nNothing to work with – all decrypts failed.")
        sys.exit(1)

    # ── Step 2: resolve nested subscriptions & parse ───────────────────
    print(f"\n{'═' * 88}")
    print(f"{'#':<4} {'Comment':<36} {'Host':<22} {'Port':<5} {'B':<3} Type")
    print(f"{'─' * 88}")

    seen: set = set()
    all_profiles: list[dict] = []

    for orig_url, plain in decrypted:
        final = resolve_content(plain, hpwnr_bin)

        for line in final.splitlines():
            line = line.strip()
            if not line:
                continue

            p = parse_vless(line)
            if not p:
                # non-VLESS line — could be JSON, trojan://, ss://, etc.
                preview = line[:60].replace("\n", " ")
                # Try JSON array at line level too
                json_uris = parse_json_subscription(line)
                if json_uris:
                    for j_uri in json_uris:
                        p2 = parse_vless(j_uri)
                        if p2:
                            key = f"{p2['host']}:{p2['port']}#{p2['uuid']}"
                            if key in seen:
                                continue
                            seen.add(key)
                            p2["_source"] = "happ"
                            all_profiles.append(p2)
                            badge = profile_badge(p2)
                            print(f"  {len(seen):<3} {p2['comment'][:35]:<36} "
                                  f"{p2['host']:<22} {p2['port']:<5} "
                                  f"{badge:<3} {p2['extra'].get('type', 'tcp')}")
                else:
                    print(f"  —    {'(non-VLESS)':<36} {preview[:60]}")
                continue

            # Dedup
            key = f"{p['host']}:{p['port']}#{p['uuid']}"
            if key in seen:
                continue
            seen.add(key)
            p["_source"] = "happ"
            all_profiles.append(p)

            badge = profile_badge(p)
            extra = p["extra"]
            t = extra.get("type", "tcp")
            info = t
            if extra.get("path"):
                info += f" path={extra['path'][:12]}…"
            if extra.get("security", "none") != "none":
                info += f" {extra['security']}"
            if extra.get("sni"):
                info += f" sni={extra['sni']}"

            print(f"  {len(seen):<3} {p['comment'][:35]:<36} "
                  f"{p['host']:<22} {p['port']:<5} "
                  f"{badge:<3} {info}")

    # ── Summary ────────────────────────────────────────────────────────
    xray_ct = sum(1 for p in all_profiles
                  if p["extra"].get("type") == "xhttp")
    sb_ct = len(all_profiles) - xray_ct

    print(f"\n{'═' * 88}")
    print(f"Total unique profiles : {len(all_profiles)}")
    print(f"  → Xray-compatible   : {xray_ct}  (badge: X — xhttp transport)")
    print(f"  → sing-box-native   : {sb_ct}   (badge: S — everything else)")
    print(f"  → Happ-source       : {len(all_profiles)}      (badge: H)")
    print()
    print("All good — hpwnr integration into Wintermute is viable.")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()