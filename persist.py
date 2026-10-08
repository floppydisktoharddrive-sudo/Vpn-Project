#!/usr/bin/env python3
"""Applied-data file and save file for NetLock."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "vpn_data"
SAVE_DIR = BASE / "saves"
APPLIED_FILE = DATA_DIR / "applied.json"
SAVE_FILE = SAVE_DIR / "netlock_save.json"
SAVE_TEXT = SAVE_DIR / "netlock_save.txt"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_record() -> dict:
    return {
        "updated_at": _now(),
        "firewall_mode": "off",
        "tunnel_port": 51821,
        "socks_port": 1080,
        "tunnel_dns": ["1.1.1.1", "1.0.0.1"],
        "bind": "127.0.0.1",
        "vpn_running": False,
        "key_file": "vpn_data/aes256.key",
        "sites_blocked": False,
    }


def load_applied() -> dict:
    rec = default_record()
    if APPLIED_FILE.exists():
        try:
            saved = json.loads(APPLIED_FILE.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                rec.update(saved)
        except json.JSONDecodeError:
            pass
    return rec


def load_save() -> dict:
    rec = default_record()
    if SAVE_FILE.exists():
        try:
            saved = json.loads(SAVE_FILE.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                rec.update(saved)
        except json.JSONDecodeError:
            pass
    elif APPLIED_FILE.exists():
        rec = load_applied()
    return rec


def _text(rec: dict) -> str:
    return "\n".join(
        [
            "NetLock save",
            f"Updated: {rec.get('updated_at')}",
            f"Firewall mode: {rec.get('firewall_mode')}",
            f"Tunnel port: {rec.get('tunnel_port')}",
            f"SOCKS port: {rec.get('socks_port')}",
            f"DNS: {', '.join(rec.get('tunnel_dns') or [])}",
            f"Bind: {rec.get('bind')}",
            f"DHCP IP: {rec.get('dhcp_ip')}",
            f"DHCP DNS: {', '.join(rec.get('dhcp_dns') or rec.get('protected_dns') or [])}",
            f"HTTP/HTTPS VPN: {rec.get('http_https_vpn')}",
            f"VPN running: {rec.get('vpn_running')}",
            f"Sites blocked: {rec.get('sites_blocked')}",
            f"Key file: {rec.get('key_file')}",
            "",
        ]
    )


def write_applied_and_save(updates: dict | None = None) -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SAVE_DIR.mkdir(parents=True, exist_ok=True)
    rec = load_applied()
    if updates:
        rec.update(updates)
    rec["updated_at"] = _now()
    rec["key_file"] = "vpn_data/aes256.key"
    payload = json.dumps(rec, indent=2)
    APPLIED_FILE.write_text(payload, encoding="utf-8")
    SAVE_FILE.write_text(payload, encoding="utf-8")
    SAVE_TEXT.write_text(_text(rec), encoding="utf-8")
    return rec
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
