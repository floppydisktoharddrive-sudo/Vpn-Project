#!/usr/bin/env python3
"""In/out byte stream for the 0.0.0.0 wildcard. New file; does not replace stream.py.

When this process is the GUI, events are also forwarded into stream.py so the
existing data-stream pane keeps its layout. A detached listener appends the
same lines to vpn_data/wildcard_stream.log.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
LOG = BASE / "vpn_data" / "wildcard_stream.log"

_lock = threading.Lock()
_lines: list[str] = []
_bytes_in = 0
_bytes_out = 0
_binds: dict[str, dict] = {}
MAX_LINES = 400


def _forward(kind: str, detail: str, nbytes: int = 0, direction: str = "") -> None:
    try:
        import stream
    except Exception:
        return
    try:
        stream.event(kind, detail)
        if nbytes and direction:
            stream.traffic("up" if direction == "out" else "down", nbytes, detail)
    except Exception:
        pass


def event(kind: str, detail: str) -> None:
    ts = time.strftime("%H:%M:%S")
    line = f"{ts} [{kind}] {detail}"
    with _lock:
        _lines.append(line)
        if len(_lines) > MAX_LINES:
            del _lines[: MAX_LINES // 2]
    try:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    _forward(kind, detail)


SMALL_CHUNK = 4096
SMALL_FLUSH = 16384


def push_small(buf: bytearray, data: bytes) -> list[bytes]:
    """Gather small chunks into byte blocks. A large read is already a block."""
    ready: list[bytes] = []
    if len(data) <= SMALL_CHUNK:
        buf.extend(data)
        if len(buf) >= SMALL_FLUSH:
            ready.append(bytes(buf))
            buf.clear()
        return ready
    if buf:
        ready.append(bytes(buf))
        buf.clear()
    ready.append(data)
    return ready


def drain_small(buf: bytearray) -> bytes | None:
    """Return any gathered small-chunk bytes still waiting."""
    if not buf:
        return None
    out = bytes(buf)
    buf.clear()
    return out


UPLOAD_SUFFIXES = (
    "drive.google.com",
    "docs.google.com",
    "upload.google.com",
    "googleapis.com",
    "googleusercontent.com",
    "dropbox.com",
    "dropboxapi.com",
    "dropboxusercontent.com",
    "mail.google.com",
    "gmail.com",
    "outlook.office.com",
    "outlook.live.com",
    "office.com",
    "office365.com",
    "facebook.com",
    "fbcdn.net",
    "messenger.com",
)


def upload_host(host: str) -> bool:
    h = (host or "").split(":")[0].lower().strip(".")
    return any(h == s or h.endswith("." + s) for s in UPLOAD_SUFFIXES)


def send_upload_bytes(dst, data: bytes) -> int:
    """Write this upload chunk immediately, one byte block at a time."""
    if not data:
        return 0
    dst.sendall(data)
    return len(data)


def send_small(src, dst, data: bytes, buf: bytearray) -> None:
    """Process one read in bytes and write ready blocks."""
    import select

    for block in push_small(buf, data):
        dst.sendall(block)
    if buf and len(data) <= SMALL_CHUNK and not select.select([src], [], [], 0)[0]:
        pending = drain_small(buf)
        if pending:
            dst.sendall(pending)


def traffic(direction: str, nbytes: int, peer: str = "", port: int = 0, pid: int = 0) -> None:
    """direction is 'in' or 'out'. Wildcard listens on 0.0.0.0 for both."""
    global _bytes_in, _bytes_out
    now = time.strftime("%H:%M:%S")
    with _lock:
        if direction == "out":
            _bytes_out += nbytes
        else:
            _bytes_in += nbytes
            direction = "in"
        line = f"{now} [{direction}] {nbytes}B 0.0.0.0:{port} pid={pid} {peer}".strip()
        _lines.append(line)
        if len(_lines) > MAX_LINES:
            del _lines[: MAX_LINES // 2]
    try:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    _forward(direction, f"{nbytes}B {peer}".strip(), nbytes, direction)


def note_bind(pid: int, port: int, token: str, process: str = "") -> None:
    key = f"{pid}:{port}"
    with _lock:
        _binds[key] = {
            "pid": pid,
            "port": port,
            "wildcard": "0.0.0.0",
            "token": token,
            "process": process,
            "at": time.time(),
        }
    event("bind", f"0.0.0.0:{port} pid={pid} {process} token={token[:18]}")


def drop_bind(pid: int, port: int) -> None:
    key = f"{pid}:{port}"
    with _lock:
        _binds.pop(key, None)
    event("unbind", f"0.0.0.0:{port} pid={pid}")


def snapshot(limit: int = 80) -> dict:
    with _lock:
        return {
            "lines": list(_lines[-limit:]),
            "bytes_in": _bytes_in,
            "bytes_out": _bytes_out,
            "binds": list(_binds.values()),
        }


def tail_log(limit: int = 40) -> list[str]:
    if not LOG.exists():
        return []
    try:
        lines = LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return lines[-limit:]
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
