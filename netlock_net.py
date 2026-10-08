#!/usr/bin/env python3
"""Python wrapper around netlock_net.c (netlock_net.so / netlock_net.dll)."""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
BROADBAND_PORT = 8000

_lib = None


class NlIface(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 64),
        ("ip", ctypes.c_char * 64),
        ("netmask", ctypes.c_char * 64),
        ("is_192", ctypes.c_int),
        ("is_loopback", ctypes.c_int),
    ]


def _lib_candidates() -> list[Path]:
    # Never name the native library netlock_net.so/.pyd in this folder —
    # Python's importer would load it instead of this wrapper (no PyInit_*).
    if os.name == "nt":
        return [
            BASE / "libnetlock_net.dll",
            BASE / "netlock_net.dll",
        ]
    return [
        BASE / "libnetlock_net.so",
        BASE / "netlock_net.so",
    ]


def _lib_path() -> Path:
    for path in _lib_candidates():
        if path.exists():
            return path
    return _lib_candidates()[0]


def load():
    global _lib
    if _lib is not None:
        return _lib
    path = _lib_path()
    if not path.exists():
        raise FileNotFoundError(f"netlock_net library missing: {path}")
    _lib = ctypes.CDLL(str(path))
    _lib.nl_broadband_port.restype = ctypes.c_int
    _lib.nl_list_ifaces.argtypes = [ctypes.POINTER(NlIface), ctypes.c_int]
    _lib.nl_list_ifaces.restype = ctypes.c_int
    _lib.nl_best_192.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    _lib.nl_best_192.restype = ctypes.c_int
    _lib.nl_bind_192_port.argtypes = [ctypes.c_char_p, ctypes.c_int]
    _lib.nl_bind_192_port.restype = ctypes.c_int
    _lib.nl_connect_broadband.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    _lib.nl_connect_broadband.restype = ctypes.c_int
    _lib.nl_version.restype = ctypes.c_char_p
    return _lib


def available() -> bool:
    return _lib_path().exists()


def version() -> str:
    try:
        raw = load().nl_version()
        return raw.decode("utf-8", errors="replace") if raw else ""
    except Exception as exc:
        return f"unavailable: {exc}"


def broadband_port() -> int:
    try:
        return int(load().nl_broadband_port())
    except Exception:
        return BROADBAND_PORT


def list_ifaces() -> list[dict]:
    lib = load()
    buf = (NlIface * 32)()
    n = lib.nl_list_ifaces(buf, 32)
    rows = []
    for i in range(max(0, n)):
        rows.append(
            {
                "name": buf[i].name.decode("utf-8", errors="replace"),
                "ip": buf[i].ip.decode("utf-8", errors="replace"),
                "netmask": buf[i].netmask.decode("utf-8", errors="replace"),
                "is_192": bool(buf[i].is_192),
                "is_loopback": bool(buf[i].is_loopback),
            }
        )
    return rows


def best_192() -> tuple[str, str]:
    lib = load()
    ip = ctypes.create_string_buffer(64)
    name = ctypes.create_string_buffer(64)
    rc = lib.nl_best_192(ip, 64, name, 64)
    if rc <= 0:
        return "", ""
    return ip.value.decode("utf-8", errors="replace"), name.value.decode("utf-8", errors="replace")


def bind_192(ip: str, port: int = BROADBAND_PORT) -> bool:
    lib = load()
    return lib.nl_bind_192_port(ip.encode("ascii"), int(port)) == 0


def connect_broadband(ip: str, port: int = BROADBAND_PORT, timeout_ms: int = 3000) -> bool:
    lib = load()
    return lib.nl_connect_broadband(ip.encode("ascii"), int(port), int(timeout_ms)) == 1


def internet_from(local_ip: str, gateway: str = "") -> tuple[bool, str]:
    """Prove the bound 192.x address can reach the Internet."""
    import socket

    targets = []
    if gateway and str(gateway).startswith("192."):
        targets.extend([(gateway, 80), (gateway, 443)])
    targets.extend([("1.1.1.1", 443), ("8.8.8.8", 443)])
    for host, port in targets:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.5)
        try:
            if local_ip and local_ip.startswith("192."):
                try:
                    s.bind((local_ip, 0))
                except OSError:
                    pass
            s.connect((host, port))
            s.close()
            return True, f"{host}:{port}"
        except OSError:
            try:
                s.close()
            except OSError:
                pass
    return False, ""


def _python_attach(ip: str, port: int) -> dict:
    """Fallback when the native library is missing. Still bind/probe 192.x:8000."""
    import socket

    import persist

    rec = persist.load_applied()
    if not ip:
        ip = str(rec.get("dhcp_ip") or rec.get("bind") or rec.get("local_ip") or "")
    dns = rec.get("dhcp_dns") or rec.get("protected_dns") or []
    gw = rec.get("dhcp_gateway") or rec.get("gateway") or ""
    info = {
        "ok": False,
        "ip": ip,
        "port": int(port or BROADBAND_PORT),
        "dns": dns,
        "gateway": gw,
        "source": "python-fallback",
        "bound": False,
        "connected": False,
    }
    if not ip.startswith("192."):
        return info
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((ip, 0))
        info["bound"] = True
        info["bound_ep"] = f"{sock.getsockname()[0]}:{sock.getsockname()[1]}"
    except OSError as exc:
        info["bind_error"] = str(exc)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    for target in (ip, gw):
        if not target or not str(target).startswith("192."):
            continue
        try:
            s = socket.create_connection((target, info["port"]), timeout=2)
            s.close()
            info["connected"] = True
            info["connected_ep"] = f"{target}:{info['port']}"
            break
        except OSError:
            continue
    if not info["connected"]:
        live, ep = internet_from(ip, gw)
        info["connected"] = live
        if ep:
            info["connected_ep"] = ep
    info["ok"] = True
    persist.write_applied_and_save({"c_net": info, "bind": ip, "broadband_port": info["port"]})
    try:
        import stream

        stream.event("c-helper", f"{ip}:{info['port']} dns={','.join(dns)} ok=true")
    except Exception:
        pass
    return info


def attach_existing_broadband(ip: str = "", port: int = BROADBAND_PORT) -> dict:
    """Attach to 192.x:8000. Uses the C library when present, else Python sockets."""
    import persist

    rec = persist.load_applied()
    if not ip:
        ip = str(rec.get("dhcp_ip") or rec.get("bind") or rec.get("local_ip") or "")
    port = int(port or rec.get("broadband_port") or BROADBAND_PORT)
    if not available():
        return _python_attach(ip, port)
    info = {
        "ok": False,
        "ip": ip,
        "port": port,
        "dns": rec.get("dhcp_dns") or rec.get("protected_dns") or [],
        "gateway": rec.get("dhcp_gateway") or rec.get("gateway") or "",
        "source": "python-fallback",
    }
    try:
        load()
        if not ip:
            ip, _name = best_192()
        if not ip:
            return _python_attach("", port)
        info["ip"] = ip
        info["port"] = port
        info["source"] = version()
        info["bound"] = bind_192(ip, port)
        info["connected"] = connect_broadband(ip, port)
        if not info["connected"]:
            live, ep = internet_from(ip, str(info.get("gateway") or ""))
            info["connected"] = live
            if ep:
                info["connected_ep"] = ep
        info["ok"] = True
        info["ifaces"] = list_ifaces()
        persist.write_applied_and_save({"c_net": info, "bind": ip, "broadband_port": port})
        try:
            import stream

            stream.event("c-helper", f"{ip}:{port} source={info['source']} ok=true")
        except Exception:
            pass
    except Exception as exc:
        info["error"] = str(exc)
        return _python_attach(ip, port)
    return info


if __name__ == "__main__":
    print("library:", _lib_path(), "exists=" + str(available()))
    print("version:", version())
    if available():
        print("best 192:", best_192())
        for row in list_ifaces():
            print(" ", row)
        print("attach:", attach_existing_broadband())
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
