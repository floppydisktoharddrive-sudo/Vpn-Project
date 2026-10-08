#!/usr/bin/env python3
"""Pack NetLock into .pak, hard-disk .img, and ISO 9660 .iso."""

from __future__ import annotations

import os
import struct
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
PAK_PATH = BASE / "netlock.pak"
IMG_PATH = BASE / "netlock.img"
ISO_PATH = BASE / "netlock.iso"

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
        if path.name in {"netlock.pak", "netlock.img", "netlock.iso"}:
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


def main() -> None:
    files = collect_files()
    pak = write_pak(files)
    img = write_img(pak.read_bytes())
    iso = write_iso(files)
    print(f"PAK  {pak}  {pak.stat().st_size} bytes  ({len(files)} files)")
    print(f"IMG  {img}  {img.stat().st_size} bytes")
    print(f"ISO  {iso}  {iso.stat().st_size} bytes")


if __name__ == "__main__":
    main()
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
