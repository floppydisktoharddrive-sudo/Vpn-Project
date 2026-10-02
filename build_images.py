#!/usr/bin/env python3
"""Pack NetLock into .pak, hard-disk .img, ISO 9660 .iso, and export configuration JSON."""

from __future__ import annotations

import json
import os
import struct
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
PAK_PATH = BASE / "netlock.pak"
IMG_PATH = BASE / "netlock.img"
ISO_PATH = BASE / "netlock.iso"
JSON_PATH = BASE / "netlock_config.json"

SKIP_DIR = {"bin", "__pycache__", "vpn_data", "saves"}
SKIP_NAME = {".pyc"}


def collect_files() -> list[tuple[str, bytes]]:
    items: list[tuple[str, bytes]] = []
    for path in sorted(BASE.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(BASE).as_posix()
        top = rel.split("/", 1)[0]
        if top in SKIP_DIR:
            continue
        if path.suffix in SKIP_NAME:
            continue
        if path.name in {"netlock.pak", "netlock.img", "netlock.iso", "netlock_config.json"}:
            continue
        items.append((rel, path.read_bytes()))
    # Keep driver DLLs so the image can actually run Wintun on Windows.
    for dll in sorted((BASE / "bin").rglob("wintun.dll")):
        rel = dll.relative_to(BASE).as_posix()
        items.append((rel, dll.read_bytes()))
    return items


def write_pak(files: list[tuple[str, bytes]]) -> Path:
    """NLPAK1: magic + count + repeating (name_len, name, size, data)."""
    blob = bytearray(b"NLPAK1\0")
    blob += struct.pack("<I", len(files))
    for name, data in files:
        raw = name.encode("utf-8")
        blob += struct.pack("<H", len(raw))
        blob += raw
        blob += struct.pack("<I", len(data))
        blob += data
    PAK_PATH.write_bytes(blob)
    return PAK_PATH


def write_img(pak: bytes) -> Path:
    """Simple 8 MiB raw hard-disk image with a NetLock header + PAK payload."""
    size = 8 * 1024 * 1024
    img = bytearray(size)
    header = struct.pack(
        "<8sIII",
        b"NLHDIMG1",
        512,  # sector size
        1,  # payload starts at LBA 1
        len(pak),
    )
    img[0:20] = header
    label = b"NETLOCK-HDD"
    img[20 : 20 + len(label)] = label
    start = 512
    img[start : start + len(pak)] = pak
    IMG_PATH.write_bytes(img)
    return IMG_PATH


def _iso9660_date(ts: float | None = None) -> bytes:
    t = time.gmtime(ts if ts is not None else time.time())
    return struct.pack("BBBBBBB", t.tm_year - 1900, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, 0)


def write_iso(files: list[tuple[str, bytes]]) -> Path:
    """Minimal ISO 9660 with README + netlock.pak at the root."""
    sector = 2048
    readme = (
        "NetLock disc image\n"
        "Mount or copy netlock.pak / run start.bat from the extracted tree.\n"
        "Private broadband bind: 192.x:8000\n"
    ).encode("ascii")
    payload = [("README.TXT", readme), ("NETLOCK.PAK", PAK_PATH.read_bytes() if PAK_PATH.exists() else b"")]

    # Layout: 16 system sectors, PVD, terminator, path table, root dir, files
    sys_area = 16
    pvd_lba = 16
    term_lba = 17
    path_lba = 18
    root_lba = 19
    next = 20
    placements = []
    for name, data in payload:
        nsec = max(1, (len(data) + sector - 1) // sector)
        placements.append((name, data, next, nsec))
        next += nsec
    volume_sectors = next

    def pad(data: bytes, n: int) -> bytes:
        if len(data) >= n:
            return data[:n]
        return data + b"\x00" * (n - len(data))

    def both32(v: int) -> bytes:
        return struct.pack("<I", v) + struct.pack(">I", v)

    def both16(v: int) -> bytes:
        return struct.pack("<H", v) + struct.pack(">H", v)

    def rec(name: bytes, lba: int, size: int, flags: int = 0) -> bytes:
        ident = name
        length = 33 + len(ident)
        if length % 2:
            length += 1
        raw = bytearray(length)
        raw[0] = length
        raw[2:10] = both32(lba)
        raw[10:18] = both32(size)
        raw[18:25] = _iso9660_date()
        raw[25] = flags
        raw[28:32] = both16(1)
        raw[32] = len(ident)
        raw[33 : 33 + len(ident)] = ident
        return bytes(raw)

    root_records = rec(b"\x00", root_lba, sector, 2) + rec(b"\x01", root_lba, sector, 2)
    for name, data, lba, _n in placements:
        ident = name.encode("ascii")
        if b"." in ident:
            ident = ident  # already uppercase with dot
        root_records += rec(ident, lba, len(data), 0)
    root_dir = pad(root_records, sector)

    path_table_le = bytearray()
    path_table_le += bytes([1, 0])  # ident len, ext
    path_table_le += struct.pack("<I", root_lba)
    path_table_le += struct.pack("<H", 1)
    path_table_le += b"\x00\x00"
    path_table_le = pad(bytes(path_table_le), sector)

    pvd = bytearray(sector)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[8:40] = pad(b"NETLOCK", 32)
    pvd[40:72] = pad(b"NETLOCK DISC", 32)
    pvd[80:88] = both32(volume_sectors)
    pvd[120:124] = both16(1)
    pvd[124:128] = both16(1)
    pvd[128:132] = both16(1)
    pvd[132:136] = both16(1)
    pvd[140:144] = both32(sector)[:4] + both32(sector)[4:]  # path table size placeholder
    pvd[132:140] = both32(len(path_table_le) if False else 10)
    pvd[140:144] = struct.pack("<I", path_lba)
    pvd[148:152] = struct.pack(">I", path_lba)
    # root directory record at 156
    root_dr = rec(b"\x00", root_lba, sector, 2)
    pvd[156 : 156 + len(root_dr)] = root_dr[:34] if len(root_dr) >= 34 else pad(root_dr, 34)
    pvd[156] = 34
    pvd[318:446] = pad(b"NETLOCK", 128)
    pvd[446:574] = pad(b"NETLOCK", 128)
    pvd[574:702] = pad(b"AES TUNNEL", 128)
    pvd[702:830] = pad(b"1.0", 128)
    pvd[831:837] = b"CD001"
    pvd[882:889] = _iso9660_date()
    pvd[889] = 0
    pvd[890:897] = _iso9660_date()

    term = bytearray(sector)
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1

    out = bytearray(volume_sectors * sector)
    # system area zeros
    out[pvd_lba * sector : (pvd_lba + 1) * sector] = pvd
    out[term_lba * sector : (term_lba + 1) * sector] = term
    out[path_lba * sector : (path_lba + 1) * sector] = path_table_le
    out[root_lba * sector : (root_lba + 1) * sector] = root_dir
    for name, data, lba, nsec in placements:
        chunk = pad(data, nsec * sector)
        out[lba * sector : (lba + nsec) * sector] = chunk
    ISO_PATH.write_bytes(out)
    return ISO_PATH


def write_json_config() -> Path:
    """Generates the structured firewall and proxy configuration profile."""
    config_data = {
        "updated_at": "2026-10-02T07:04:11Z",
        "firewall_mode": "vpn",
        "tunnel_port": 51821,
        "socks_port": 1080,
        "tunnel_dns": ["192.168.49.1"],
        "bind": "192.168.49.72",
        "vpn_running": True,
        "key_file": "vpn_data/aes256.key",
        "sites_blocked": False,
        "http_guard": True,
        "shield_http_https": True,
        "local_ip": "192.168.49.72",
        "gateway": "192.168.49.1",
        "adapter": "Wi-Fi",
        "connection_kind": "modem_router_wifi",
        "wintun_driver": "Wintun kernel driver ready; adapter NetLockTUN created from C:\\Users\\user\\Desktop\\vpn blocker\\bin\\amd64\\wintun.dll",
        "app_proxies": [
            {"pid": "15748", "app": "CalculatorApp.exe", "proxy": "127.0.0.1:18348"},
            {"pid": "2328", "app": "chrome.exe", "proxy": "127.0.0.1:8080"},
            {"pid": "15532", "app": "cmd.exe", "proxy": "127.0.0.1:18132"},
            {"pid": "12204", "app": "Microsoft.Media.Player.exe", "proxy": "127.0.0.1:18304"},
            {"pid": "6344", "app": "notepad++.exe", "proxy": "127.0.0.1:18444"},
            {"pid": "2736", "app": "python.exe", "proxy": "127.0.0.1:18336"},
            {"pid": "16680", "app": "TextInputHost.exe", "proxy": "127.0.0.1:18280"},
        ],
        "c_net": {
            "ok": True,
            "ip": "192.168.49.72",
            "port": 8000,
            "dns": [],
            "gateway": "192.168.49.1",
            "source": "netlock_net 1.0",
            "bound": True,
            "connected": False,
            "ifaces": [
                {"name": "Ethernet", "ip": "169.254.200.17", "netmask": "", "is_192": False, "is_loopback": False},
                {"name": "NetLockTUN", "ip": "169.254.110.21", "netmask": "", "is_192": False, "is_loopback": False},
                {"name": "PdaNet Broadband Connection", "ip": "10.1.19.2", "netmask": "", "is_192": False, "is_loopback": False},
                {"name": "Local Area Connection* 9", "ip": "169.254.45.22", "netmask": "", "is_192": false, "is_loopback": False},
                {"name": "Local Area Connection* 11", "ip": "169.254.137.168", "netmask": "", "is_192": false, "is_loopback": False},
                {"name": "Wi-Fi", "ip": "192.168.49.72", "netmask": "", "is_192": True, "is_loopback": False},
                {"name": "Bluetooth Network Connection", "ip": "169.254.251.128", "netmask": "", "is_192": false, "is_loopback": False},
                {"name": "Loopback Pseudo-Interface 1", "ip": "127.0.0.1", "netmask": "", "is_192": False, "is_loopback": True},
                {"name": "Loopback Pseudo-Interface 2", "ip": "1.0.0.1", "netmask": "", "is_192": False, "is_loopback": True},
                {"name": "Loopback Pseudo-Interface 3", "ip": "1.1.1.1", "netmask": "", "is_192": False, "is_loopback": True},
            ],
        },
        "broadband_port": 8000,
        "last_engine_hit": "blocked-ip: 142.251.214.46:443 pid=2736",
        "session_key_rotated": True,
        "session_key": "C:\\Users\\user\\Desktop\\vpn blocker\\vpn_data\\session.key",
        "firewall_detected": {"domain": {"logging": ""}, "private": {"logging": ""}, "public": {"logging": ""}},
        "protected_dns": ["192.168.49.1", "1.1.1.1", "1.0.0.1"],
        "dhcp_dns": ["192.168.49.1"],
        "dhcp_ip": "192.168.49.72",
        "dhcp_gateway": "192.168.49.1",
        "dhcp_adapter": "Wi-Fi",
        "dhcp_enabled": True,
        "dhcp_lease_server": "10.1.19.1",
        "http_proxy": "127.0.0.1:8080",
        "https_proxy": "127.0.0.1:8080",
        "vpn_monitors_only": True,
        "auto_bind": True,
        "firewall_profiles": ["domain", "private", "public"],
        "vpn_scope": "private",
        "vpn_public_running": True,
        "vpn_scope_public": "public",
        "site_filter": True,
        "http_https_vpn": True,
    }
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=4)
    return JSON_PATH


def main() -> None:
    files = collect_files()
    pak = write_pak(files)
    img = write_img(pak.read_bytes())
    iso = write_iso(files)
    config_json = write_json_config()
    print(f"PAK  {pak}  {pak.stat().st_size} bytes  ({len(files)} files)")
    print(f"IMG  {img}  {img.stat().st_size} bytes")
    print(f"ISO  {iso}  {iso.stat().st_size} bytes")
    print(f"JSON {config_json} written successfully.")


if __name__ == "__main__":
    main()
