#!/usr/bin/env python3
"""Per-app temporary HTTP proxies. Live while the app window is open."""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor

import apps
import persist

BROWSER_NAMES = (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
)

BROWSER_PORT = 8080
_BASE_PORT = 18100
_stop = threading.Event()
_thread = None
_pool = ThreadPoolExecutor(max_workers=16, thread_name_prefix="app-proxy")
_live: dict[str, dict] = {}
_lock = threading.Lock()


def _pipe(a: socket.socket, b: socket.socket) -> None:
    def one(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    t = threading.Thread(target=one, args=(b, a), daemon=True)
    t.start()
    one(a, b)


_http_leftover: dict[int, bytearray] = {}


def _recv_line(sock: socket.socket) -> bytes:
    key = id(sock)
    buf = _http_leftover.setdefault(key, bytearray())
    while b"\n" not in buf and len(buf) < 16384:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf.extend(chunk)
    nl = buf.find(b"\n")
    if nl >= 0:
        line = bytes(buf[: nl + 1])
        del buf[: nl + 1]
        return line
    line = bytes(buf)
    buf.clear()
    _http_leftover.pop(key, None)
    return line


def _handle(client: socket.socket) -> None:
    try:
        client.settimeout(20)
        first = _recv_line(client)
        if not first:
            return
        parts = first.decode("iso-8859-1", errors="replace").split()
        headers = [first]
        while True:
            line = _recv_line(client)
            headers.append(line)
            if line in (b"\r\n", b"\n", b""):
                break
        if len(parts) < 2:
            return
        method, target = parts[0].upper(), parts[1]
        host = ""
        port = 80
        if method == "CONNECT":
            hostport = target.split("/")[0]
            if ":" in hostport:
                host, ps = hostport.rsplit(":", 1)
                port = int(ps) if ps.isdigit() else 443
            else:
                host, port = hostport, 443
        else:
            for raw in headers:
                if raw.lower().startswith(b"host:"):
                    host = raw.split(b":", 1)[1].strip().decode("iso-8859-1", errors="replace")
            if ":" in host:
                host, ps = host.rsplit(":", 1)
                port = int(ps) if ps.isdigit() else 80
            else:
                port = 80
        if not host:
            return
        remote = socket.create_connection((host, port), timeout=15)
        if method == "CONNECT":
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            remote.sendall(b"".join(headers))
        _pipe(client, remote)
    except Exception:
        pass
    finally:
        _http_leftover.pop(id(client), None)
        try:
            client.close()
        except OSError:
            pass


def _serve(port: int, key: str) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", port))
        srv.listen(32)
        srv.settimeout(1.0)
    except OSError:
        return
    with _lock:
        if key in _live:
            _live[key]["sock"] = srv
    while not _stop.is_set():
        with _lock:
            if key not in _live:
                break
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        _pool.submit(_handle, conn)
    try:
        srv.close()
    except OSError:
        pass


def _port_for(pid: str, name: str) -> int:
    if name.lower() in BROWSER_NAMES:
        return BROWSER_PORT
    try:
        n = int(pid) % 500
    except ValueError:
        n = sum(ord(c) for c in name) % 500
    return _BASE_PORT + n


def _watch() -> None:
    while not _stop.is_set():
        procs = apps.desktop_processes()
        seen = {}
        for p in procs:
            pid = str(p.get("pid") or "")
            name = p.get("app") or ""
            if not pid or not name:
                continue
            seen[pid] = name
        with _lock:
            current = set(_live)
        for pid in current - set(seen):
            stop_one(pid)
        for pid, name in seen.items():
            with _lock:
                if pid in _live:
                    continue
            port = _port_for(pid, name)
            rec = {"pid": pid, "app": name, "port": port, "sock": None}
            with _lock:
                _live[pid] = rec
            threading.Thread(target=_serve, args=(port, pid), daemon=True, name=f"px-{pid}").start()
        persist.write_applied_and_save(
            {
                "app_proxies": [
                    {"pid": v["pid"], "app": v["app"], "proxy": f"127.0.0.1:{v['port']}"}
                    for v in list(_live.values())
                ]
            }
        )
        _stop.wait(5.0)


def stop_one(pid: str) -> None:
    with _lock:
        rec = _live.pop(str(pid), None)
    if not rec:
        return
    sock = rec.get("sock")
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass


def snapshot() -> list[dict]:
    with _lock:
        return [
            {"pid": v["pid"], "app": v["app"], "proxy": f"127.0.0.1:{v['port']}"}
            for v in _live.values()
        ]


def start() -> str:
    global _thread
    _stop.clear()
    if _thread is None or not _thread.is_alive():
        _thread = threading.Thread(target=_watch, name="app-proxy-watch", daemon=True)
        _thread.start()
    return "Per-app proxies watching open windows (browser = 127.0.0.1:8080)."


def stop() -> str:
    _stop.set()
    with _lock:
        pids = list(_live)
    for pid in pids:
        stop_one(pid)
    return "Per-app proxies stopped."
