#!/usr/bin/env python3
"""List TCP/UDP connections on this computer."""

from __future__ import annotations

import os
import re
import socket
import subprocess
import time

_proc_cache: dict[str, str] = {}
_proc_cache_ts = 0.0


def _netstat() -> str:
    if os.name == "nt":
        cmd = ["netstat", "-ano"]
    else:
        cmd = ["ss", "-tuanp"] if _has("ss") else ["netstat", "-tuanp"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return res.stdout or res.stderr or ""
    except Exception as exc:
        return f"Could not list connections: {exc}\n"


def _has(name: str) -> bool:
    from shutil import which

    return which(name) is not None


def parse_windows(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if not (line.startswith("TCP") or line.startswith("UDP")):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 3:
            continue
        proto = parts[0]
        local = parts[1]
        remote = parts[2] if proto == "TCP" or (len(parts) > 2 and parts[2] != "") else "*:*"
        if proto == "TCP" and len(parts) >= 5:
            state, pid = parts[3], parts[4]
        elif proto == "TCP" and len(parts) == 4:
            state, pid = parts[3], ""
        else:
            state, pid = "", parts[-1] if parts[-1].isdigit() else ""
            if len(parts) >= 4 and not parts[3].isdigit():
                remote = parts[2]
        rows.append(
            {
                "proto": proto,
                "local": local,
                "remote": remote,
                "state": state,
                "pid": pid,
            }
        )
    return rows


def parse_ss(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].upper()
        state = parts[1] if proto.startswith("TCP") else ""
        local = parts[4] if len(parts) > 4 else ""
        remote = parts[5] if len(parts) > 5 else ""
        pid = ""
        m = re.search(r"pid=(\d+)", line)
        if m:
            pid = m.group(1)
        rows.append({"proto": proto, "local": local, "remote": remote, "state": state, "pid": pid})
    return rows


def process_map() -> dict[str, str]:
    global _proc_cache, _proc_cache_ts
    now = time.time()
    if _proc_cache and now - _proc_cache_ts < 5:
        return _proc_cache
    names: dict[str, str] = {}
    if os.name == "nt":
        try:
            res = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            for line in res.stdout.splitlines():
                parts = [p.strip().strip('"') for p in line.split(",")]
                if len(parts) >= 2 and parts[1].isdigit():
                    names[parts[1]] = parts[0]
        except Exception:
            pass
        _proc_cache, _proc_cache_ts = names, now
        return names
    try:
        res = subprocess.run(["ps", "-eo", "pid,comm"], capture_output=True, text=True, timeout=10)
        for line in res.stdout.splitlines()[1:]:
            parts = line.split(None, 1)
            if len(parts) == 2:
                names[parts[0]] = parts[1].strip()
    except Exception:
        pass
    _proc_cache, _proc_cache_ts = names, now
    return names


def list_connections() -> list[dict]:
    raw = _netstat()
    if os.name == "nt":
        rows = parse_windows(raw)
    else:
        rows = parse_ss(raw) if raw.lstrip().startswith("Netid") or "State" in raw.split("\n", 1)[0] else parse_windows(raw)
    names = process_map()
    host = socket.gethostname()
    for row in rows:
        row["host"] = host
        pid = str(row.get("pid") or "")
        row["app"] = names.get(pid, "")
    return rows


def as_text(rows: list[dict] | None = None) -> str:
    rows = rows if rows is not None else list_connections()
    if not rows:
        return "No connections reported."
    lines = [f"{'PROTO':<8}{'STATE':<16}{'LOCAL':<28}{'REMOTE':<28}{'PID':<8}"]
    for r in rows:
        lines.append(
            f"{r.get('proto',''):<8}{r.get('state',''):<16}{r.get('local',''):<28}{r.get('remote',''):<28}{r.get('pid',''):<8}"
        )
    lines.append(f"\nTotal: {len(rows)}")
    return "\n".join(lines)
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
