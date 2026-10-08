#!/usr/bin/env python3
"""16 workers per running exe from the 256 worker pool. Not a scan pool.

Wildcard 0.0.0.0 can stay off. Each worker scans its process, binds a companion
port, and seals that data stream with the revolving AES key.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import data_stream
import secure_stream

WILDCARD = "0.0.0.0"
POOL_START = 52100
POOL_END = 52900
SCAN_SECONDS = 0.025  # local table only, tens of milliseconds
MAX_WORKERS = 256

# VPN and SQL ports are bound, then brute-force and injection attempts are dropped.
SQL_PORTS = {1433, 1434, 3306, 5432, 14330, 1521, 27017}
VPN_PORTS = {1194, 1723, 500, 4500, 1701, 51820, 51821, 51822, 443}
SCRIPT_SUFFIXES = (".py", ".pyw", ".ps1", ".bat", ".cmd", ".js", ".vbs", ".wsf")
SCRIPT_HOSTS = {"python", "pythonw", "py", "wscript", "cscript", "powershell", "pwsh", "cmd", "bash", "sh"}
APP_WORKERS = 16
SCRIPT_WORKERS = 1

_stop = threading.Event()
_workers: dict[str, dict] = {}
_lock = threading.Lock()
_pool: ThreadPoolExecutor | None = None
_scan_thread: threading.Thread | None = None


def _listening_ports() -> list[dict]:
    rows = []
    try:
        import connections
        rows = connections.list_connections()
    except Exception:
        return []
    found = []
    for row in rows:
        state = (row.get("state") or "").upper()
        proto = (row.get("proto") or "").upper()
        if "LISTEN" not in state and not proto.startswith("UDP"):
            continue
        local = row.get("local") or ""
        port = _port_of(local)
        if port <= 0:
            continue
        pid = int(row.get("pid") or 0)
        found.append({
            "pid": pid,
            "port": port,
            "proto": proto or "TCP",
            "app": row.get("app") or "",
            "local": local,
        })
    return found


def _port_of(local: str) -> int:
    if not local:
        return 0
    if local.startswith("["):
        host, _, port = local.rpartition(":")
        try:
            return int(port)
        except ValueError:
            return 0
    host, sep, port = local.rpartition(":")
    if not sep:
        return 0
    try:
        return int(port)
    except ValueError:
        return 0


def _can_bind(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((WILDCARD, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _free_port() -> int:
    with _lock:
        used = {int(item.get("bound_port") or 0) for item in _workers.values()}
    for port in range(POOL_START, POOL_END):
        if port in used:
            continue
        if _can_bind(port):
            return port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        host = "127.0.0.1"
        try:
            import persist
            if persist.load_applied().get("wildcard") is True:
                host = WILDCARD
        except Exception:
            pass
        sock.bind((host, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


PROXY_PORTS = {8080, 1080, 1081, 3128, 8000, 8118, 9050, 8888}
HTTP_PORTS = {80, 8080, 8000, 8008, 8888}
HTTPS_PORTS = {443, 8443}
FTP_PORTS = {20, 21, 989, 990}


def _bind_host() -> str:
    """Process binds stay up when the 0.0.0.0 listener is off."""
    try:
        import persist
        if persist.load_applied().get("wildcard") is True:
            return WILDCARD
    except Exception:
        pass
    return "127.0.0.1"


def _attack(blob: bytes, peer: str, port: int) -> str:
    try:
        import engine
        hit = engine.inspect_payload(blob, peer=peer) or ""
    except Exception:
        hit = ""
    armed = port in SQL_PORTS or port in VPN_PORTS or port in PROXY_PORTS or port in HTTP_PORTS or port in HTTPS_PORTS or port in FTP_PORTS
    if hit and (armed or hit in {"sql-injection", "brute-force", "malware-injection"}):
        return hit
    return ""


def _seal_stream(blob: bytes, peer: str, port: int, pid: int) -> bytes:
    sealed, _kept = secure_stream.end_to_end(blob[:4096])
    data_stream.traffic("in", len(sealed), peer, port, pid)
    return secure_stream.open_endpoint(sealed)


def _serve(sock: socket.socket, pid: int, port: int, app: str) -> None:
    sock.settimeout(1.0)
    while not _stop.is_set():
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        peer = f"{addr[0]}:{addr[1]}"
        secure_stream.rotate_now("inbound")
        token = secure_stream.seal_wildcard(port, pid, peer)
        _note("in", f"0.0.0.0:{port} pid={pid} {app} {peer} token={token[:18]}")
        try:
            blob = conn.recv(65536)
            if blob:
                hit = _attack(blob, peer, port)
                if hit:
                    _note("block", f"{hit} pid={pid} {app} {peer} port={port}")
                    try:
                        import engine
                        engine.note_hit(hit, f"{peer} port={port} {app}")
                    except Exception:
                        pass
                    continue
                _seal_stream(blob, peer, port, pid)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
    try:
        sock.close()
    except OSError:
        pass


def _posture() -> str:
    return (os.environ.get("NETLOCK_SCAN") or "hidden").strip().lower()


def _note(kind: str, detail: str) -> None:
    data_stream.event(kind, detail)
    if _posture() == "visible":
        print(f"[{kind}] {detail}", flush=True)


def _sighting(port: int, app: str, pid: int, proto: str) -> None:
    kind = ""
    if port in SQL_PORTS:
        kind = "sql-block"
    elif port in VPN_PORTS:
        kind = "vpn-block"
    if not kind:
        return
    _note(kind, f"armed {proto} {WILDCARD} pid={pid} port={port} {app} (brute-force and injection blocked)")


def open_for_process(pid: int, port: int, app: str = "", proto: str = "TCP") -> dict:
    """Bind a companion 0.0.0.0 port for one process. Never takes the process port."""
    key = f"{pid}:{port}:{proto}"
    with _lock:
        existing = _workers.get(key)
        if existing and existing.get("alive"):
            return existing
    _sighting(port, app, pid, proto)
    script = _is_script(app) or proto.upper() == "SCRIPT"
    bound_port = _free_port()
    host = _bind_host()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, bound_port))
    sock.listen(64)
    name = (app or "process").replace("\\", "/").split("/")[-1]
    line = f"{name} {host}:{bound_port}"
    token = secure_stream.seal_wildcard(bound_port, pid, line)
    rec = {
        "pid": pid,
        "process_port": port,
        "bound_port": bound_port,
        "wildcard": host,
        "proto": proto,
        "app": app,
        "line": line,
        "token": token,
        "key_generation": secure_stream.ring().generation,
        "alive": True,
    }
    with _lock:
        _workers[key] = rec
    data_stream.note_bind(pid, bound_port, token, app or str(pid))
    rec["script"] = script
    rec["socket"] = sock
    return rec


def bind_outbound(pid: int, remote: str, remote_port: int) -> dict:
    """Source-bind an outbound socket to 0.0.0.0 and seal that connection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host = _bind_host()
    sock.bind((host, 0))
    local_port = int(sock.getsockname()[1])
    token = secure_stream.seal_wildcard(local_port, pid, f"{remote}:{remote_port}")
    try:
        sock.settimeout(8)
        sock.connect((remote, int(remote_port)))
        data_stream.traffic("out", 0, f"{remote}:{remote_port}", local_port, pid)
    except OSError as exc:
        data_stream.event("out-fail", f"0.0.0.0:{local_port} -> {remote}:{remote_port} {exc}")
    data_stream.note_bind(pid, local_port, token, "outbound")
    return {"socket": sock, "port": local_port, "token": token, "wildcard": WILDCARD}


def _is_script(app: str) -> bool:
    low = (app or "").lower().replace("\\", "/").split("/")[-1]
    if low.endswith(SCRIPT_SUFFIXES):
        return True
    stem = low[:-4] if low.endswith(".exe") else low
    return stem in SCRIPT_HOSTS


def _workers_for(app: str) -> int:
    return SCRIPT_WORKERS if _is_script(app) else APP_WORKERS


BROWSERS = {"chrome", "msedge", "firefox", "brave", "opera", "iexplore", "chromium"}


def _window_titles() -> list[dict]:
    """Open process windows, including the active tab title of each browser window."""
    if os.name != "nt":
        return []
    import subprocess
    script = (
        "Get-Process | Where-Object { $_.MainWindowTitle } | "
        "ForEach-Object { Write-Output ($_.Id.ToString() + '|' + $_.ProcessName + '|' + $_.MainWindowTitle) }"
    )
    try:
        res = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=8)
    except Exception:
        return []
    rows = []
    for line in res.stdout.splitlines():
        pid, sep, rest = line.partition("|")
        name, sep2, title = rest.partition("|")
        if not sep or not pid.isdigit() or not title.strip():
            continue
        rows.append({"pid": int(pid), "name": name.strip(), "title": title.strip()})
    return rows


def running_targets() -> list[dict]:
    """Every running .exe, plus script files and browser tabs. Listeners keep their real port."""
    found: list[dict] = []
    seen: set[tuple] = set()
    for row in _listening_ports():
        key = (int(row.get("pid") or 0), int(row.get("port") or 0), row.get("proto") or "TCP")
        if key in seen:
            continue
        seen.add(key)
        found.append(row)
    try:
        import connections
        names = connections.process_map()
    except Exception:
        names = {}
    for pid, app in names.items():
        try:
            pid_i = int(pid)
        except (TypeError, ValueError):
            continue
        if pid_i <= 0 or not app:
            continue
        low = app.lower()
        if not low.endswith(".exe") and not _is_script(app):
            continue
        key = (pid_i, 0, "PROC")
        if any(item[0] == pid_i for item in seen):
            continue
        seen.add(key)
        found.append({"pid": pid_i, "port": 0, "proto": "PROC", "app": app, "local": ""})
    for win in _window_titles():
        stem = (win.get("name") or "").lower()
        if stem not in BROWSERS:
            continue
        found.append({
            "pid": win["pid"],
            "port": 0,
            "proto": "TAB",
            "app": win["name"] + ".exe",
            "title": win["title"],
            "local": "",
        })
    return found


def _worker(pid: int, app: str) -> None:
    """One of the 16 workers. It scans its exe, binds, and seals the stream."""
    sock = None
    bound = 0
    while not _stop.is_set():
        try:
            rows = [row for row in running_targets() if int(row.get("pid") or 0) == pid]
            if not rows:
                rows = [{"pid": pid, "port": 0, "proto": "PROC", "app": app}]
            for row in rows:
                rec = open_for_process(pid, int(row.get("port") or 0), app, row.get("proto") or "TCP")
                token = secure_stream.seal_wildcard(int(rec.get("bound_port") or 0), pid, rec.get("line") or app)
                rec["token"] = token
                rec["key_generation"] = secure_stream.ring().generation
                plain = secure_stream.open_endpoint(token.encode())
                _note("scan", f"{rec.get('line')} key={rec['key_generation']} open={len(plain)}")
                if sock is None and rec.get("socket") is not None:
                    sock = rec["socket"]
                    bound = int(rec.get("bound_port") or 0)
            if sock is not None:
                sock.settimeout(0.2)
                try:
                    conn, addr = sock.accept()
                except socket.timeout:
                    conn = None
                except OSError:
                    conn = None
                if conn is not None:
                    peer = f"{addr[0]}:{addr[1]}"
                    try:
                        blob = conn.recv(65536)
                        if blob:
                            hit = _attack(blob, peer, bound)
                            if hit:
                                _note("block", f"{hit} pid={pid} {app} {peer}")
                            else:
                                _seal_stream(blob, peer, bound, pid)
                    except OSError:
                        pass
                    finally:
                        try:
                            conn.close()
                        except OSError:
                            pass
        except OSError as exc:
            _note("bind-skip", f"pid={pid} {exc}")
        except RuntimeError:
            return
        _stop.wait(0.05)


def _vpn_bind() -> str:
    try:
        import persist
        rec = persist.load_applied()
        return str(rec.get("bind") or rec.get("dhcp_ip") or "127.0.0.1")
    except Exception:
        return "127.0.0.1"


def _launch_workers() -> int:
    import worker_pool
    pool = _pool or worker_pool.pool_256()
    launched = 0
    seen: set[int] = set()
    vpn_ip = _vpn_bind()
    for row in running_targets():
        pid = int(row.get("pid") or 0)
        app = row.get("app") or ""
        port = int(row.get("port") or 0)
        if pid <= 0 or pid in seen:
            continue
        seen.add(pid)
        name = (row.get("title") or app.replace("\\", "/").split("/")[-1] or "process")
        local = row.get("local") or f"{vpn_ip}:{port}"
        line = f"{name} {local}".strip()
        _note("process", line)
        grant = worker_pool.assign_process(f"exe:{pid}", workers=_workers_for(app))
        for n in range(grant):
            rec = open_for_process(pid, port, app, row.get("proto") or "TCP")
            rec["line"] = f"{name} {local}".strip()
            rec["worker"] = n + 1
            _note("bind", rec["line"])
            pool.submit(_worker, pid, app)
            launched += 1
    return launched


def preload_binds() -> list[dict]:
    """Detect running processes at startup. Does not start the workers."""
    rows = []
    seen: set[int] = set()
    vpn_ip = _vpn_bind()
    for row in running_targets():
        pid = int(row.get("pid") or 0)
        if pid <= 0 or pid in seen:
            continue
        seen.add(pid)
        app = row.get("app") or ""
        name = row.get("title") or app.replace("\\", "/").split("/")[-1] or "process"
        local = row.get("local") or f"{vpn_ip}:{int(row.get('port') or 0)}"
        rows.append({
            "pid": pid,
            "app": app,
            "line": f"{name} {local}".strip(),
            "port": int(row.get("port") or 0),
            "proto": row.get("proto") or "PROC",
            "workers": _workers_for(app),
        })
    out = Path(__file__).resolve().parent / "vpn_data"
    out.mkdir(parents=True, exist_ok=True)
    (out / "worker_preload.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return rows


def write_runtime_script(rows: list[dict] | None = None) -> str:
    """Write the process runtime script from the startup preload."""
    out = Path(__file__).resolve().parent / "vpn_data"
    out.mkdir(parents=True, exist_ok=True)
    preload = out / "worker_preload.json"
    if rows is None and preload.exists():
        try:
            rows = json.loads(preload.read_text(encoding="utf-8"))
        except Exception:
            rows = []
    rows = rows or preload_binds()
    lines = ["@echo off", "rem worker runtime generated from processes detected at startup"]
    for row in rows:
        line = str(row.get("line") or "").replace("%", "%%")
        workers = int(row.get("workers") or 1)
        lines.append(f'echo {line} workers={workers}')
    path = out / "worker_runtime.bat"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def start() -> dict:
    global _pool, _scan_thread
    if _scan_thread and _scan_thread.is_alive():
        return {"ok": True, "already": True, "binds": list_binds(), "script": write_runtime_script()}
    _stop.clear()
    try:
        import worker_pool
        _pool = worker_pool.pool_256()
    except Exception:
        _pool = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="wild")
    script = write_runtime_script()
    launched = _launch_workers()

    def _keep() -> None:
        while not _stop.is_set():
            _stop.wait(1.0)

    _scan_thread = threading.Thread(target=_keep, name="parallel-workers", daemon=True)
    _scan_thread.start()
    _note("parallel", f"workers={launched} script={script} wildcard={_bind_host()} pid={os.getpid()}")
    return {"ok": True, "already": False, "binds": list_binds(), "workers": launched, "script": script}


def stop() -> None:
    _stop.set()
    with _lock:
        items = list(_workers.values())
        _workers.clear()
    for rec in items:
        sock = rec.get("socket")
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        data_stream.drop_bind(int(rec.get("pid") or 0), int(rec.get("bound_port") or 0))
    try:
        import worker_pool
        worker_pool.release_all()
        shared = worker_pool.pool_256()
    except Exception:
        shared = None
    if _pool is not None and _pool is not shared:
        _pool.shutdown(wait=False, cancel_futures=True)


def list_binds() -> list[dict]:
    with _lock:
        out = []
        for rec in _workers.values():
            out.append({k: v for k, v in rec.items() if k != "socket"})
        return out

try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
