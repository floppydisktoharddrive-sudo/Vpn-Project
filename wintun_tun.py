#!/usr/bin/env python3
"""Load bundled wintun.dll and run a packet loop into the AES path."""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
import threading
from pathlib import Path

BASE = Path(__file__).resolve().parent
ADAPTER_NAME = "NetLockTUN"
TUNNEL_TYPE = "NetLock"

_dll = None
_adapter = None
_session = None
_stop = threading.Event()
_thread = None
_ok = False
_msg = "Wintun not started"


def _dll_path() -> Path:
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64"}:
        folder = "amd64"
    elif machine in {"arm64", "aarch64"}:
        folder = "arm64"
    elif machine in {"arm", "armv7l"}:
        folder = "arm"
    else:
        folder = "x86"
    return BASE / "bin" / folder / "wintun.dll"


def available() -> bool:
    return os.name == "nt" and _dll_path().exists()


def _load_dll():
    global _dll
    path = _dll_path()
    if not path.exists():
        raise FileNotFoundError(str(path))
    if _dll is None:
        _dll = ctypes.WinDLL(str(path))
    return _dll


def install_driver() -> tuple[bool, str]:
    """Load bundled wintun.dll so Windows installs the Wintun kernel driver (admin)."""
    global _adapter, _msg
    if os.name != "nt":
        return False, "Wintun driver only installs on Windows"
    try:
        dll = _load_dll()
    except Exception as exc:
        _msg = f"Wintun DLL missing: {exc}"
        return False, _msg
    create = dll.WintunCreateAdapter
    create.restype = ctypes.c_void_p
    create.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]
    adapter = create(ADAPTER_NAME, TUNNEL_TYPE, None)
    if not adapter:
        err = ctypes.GetLastError()
        _msg = f"Wintun driver install/create failed (Win32 {err}). Run as admin."
        return False, _msg
    _adapter = adapter
    _msg = f"Wintun kernel driver ready; adapter {ADAPTER_NAME} created from {_dll_path()}"
    return True, _msg


def _nearby_ip(local_ip: str) -> str:
    parts = (local_ip or "").split(".")
    if len(parts) != 4:
        return "192.168.77.2"
    last = int(parts[3]) if parts[3].isdigit() else 2
    alt = 254 if last != 254 else 253
    return ".".join(parts[:3] + [str(alt)])


def assign_broadband_ip(local_ip: str, gateway: str, adapter: str = "") -> str:
    """Point NetLockTUN at an address in the same 192.x LAN as the live broadband NIC."""
    if os.name != "nt":
        return "IP assign skipped"
    tun_ip = _nearby_ip(local_ip)
    gw = gateway or ".".join((local_ip or "192.168.1.2").split(".")[:3] + ["1"])
    cmd = (
        f"netsh interface ip set address name='{ADAPTER_NAME}' static {tun_ip} 255.255.255.0 {gw}"
    )
    subprocess.run(["cmd", "/c", cmd], capture_output=True, text=True)
    extra = ""
    if adapter:
        extra = f" (broadband NIC '{adapter}' {local_ip})"
    return f"NetLockTUN address {tun_ip}/24 gw {gw}{extra}"


def status() -> str:
    return _msg


def running() -> bool:
    return _ok and not _stop.is_set()


def start() -> tuple[bool, str]:
    global _dll, _adapter, _session, _thread, _ok, _msg
    if os.name != "nt":
        _msg = "Wintun only loads on Windows"
        return False, _msg
    path = _dll_path()
    if not path.exists():
        _msg = f"Missing {path}"
        return False, _msg
    try:
        _dll = ctypes.WinDLL(str(path))
    except OSError as exc:
        _msg = f"Could not load wintun.dll: {exc}"
        return False, _msg

    create = _dll.WintunCreateAdapter
    create.restype = ctypes.c_void_p
    create.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]
    start_session = _dll.WintunStartSession
    start_session.restype = ctypes.c_void_p
    start_session.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

    _adapter = create(ADAPTER_NAME, TUNNEL_TYPE, None)
    if not _adapter:
        err = ctypes.GetLastError()
        _msg = f"WintunCreateAdapter failed (Win32 {err}). Run as admin. Driver may need first-time install."
        return False, _msg
    _session = start_session(_adapter, 0x400000)
    if not _session:
        _msg = f"WintunStartSession failed (Win32 {ctypes.GetLastError()})"
        return False, _msg
    _stop.clear()
    _ok = True
    _thread = threading.Thread(target=_loop, name="wintun-aes", daemon=True)
    _thread.start()
    _msg = f"Wintun adapter {ADAPTER_NAME} up; packets inspected and AES-tagged"
    return True, _msg


def _loop() -> None:
    """Pull packets from Wintun. Drop blacklisted IPs. UDP/53 and UDP/443 are flagged."""
    import engine
    import blocker

    recv = _dll.WintunReceivePacket
    recv.restype = ctypes.c_void_p
    recv.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    release = _dll.WintunReleaseReceivePacket
    release.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    wait_ev = _dll.WintunGetReadWaitEvent
    wait_ev.restype = ctypes.c_void_p
    wait_ev.argtypes = [ctypes.c_void_p]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    event = wait_ev(_session)
    while not _stop.is_set() and _session:
        size = ctypes.c_uint32(0)
        ptr = recv(_session, ctypes.byref(size))
        if not ptr:
            kernel32.WaitForSingleObject(ctypes.c_void_p(event), 250)
            continue
        try:
            buf = ctypes.string_at(ptr, size.value)
        finally:
            release(_session, ptr)
        if len(buf) < 20:
            continue
        version = buf[0] >> 4
        if version != 4:
            continue
        proto = buf[9]
        dst = ".".join(str(b) for b in buf[16:20])
        src = ".".join(str(b) for b in buf[12:16])
        if dst in blocker.blocked_ips() or src in blocker.blocked_ips():
            engine.note_hit("wintun-drop", f"{src}->{dst}")
            continue
        if proto == 17 and len(buf) >= 28:
            dport = int.from_bytes(buf[22:24], "big")
            # Do not note_hit DNS/QUIC — that rotates the AES session key and stalls YouTube.
            if dport in {53, 443}:
                continue
        # Skip deep inspect on large UDP/TCP video-sized packets
        if len(buf) > 1200:
            continue
        hit = engine.inspect_payload(buf)
        if hit:
            engine.note_hit(hit, f"wintun {src}->{dst}")


def stop() -> str:
    global _ok, _adapter, _session, _msg
    _stop.set()
    _ok = False
    try:
        if _dll and _session:
            _dll.WintunEndSession(ctypes.c_void_p(_session))
        if _dll and _adapter:
            _dll.WintunCloseAdapter(ctypes.c_void_p(_adapter))
    except Exception:
        pass
    _session = None
    _adapter = None
    _msg = "Wintun stopped"
    return _msg
