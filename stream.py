#!/usr/bin/env python3
"""In-process data stream for the GUI (bytes and events)."""

from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_lines: list[str] = []
_bytes_up = 0
_bytes_down = 0
_win_up = []  # (t, bytes)
_win_down = []
MAX_LINES = 400
SPEED_WINDOW = 3.0


def event(kind: str, detail: str) -> None:
    ts = time.strftime("%H:%M:%S")
    line = f"{ts} [{kind}] {detail}"
    with _lock:
        _lines.append(line)
        if len(_lines) > MAX_LINES:
            del _lines[: MAX_LINES // 2]


def traffic(direction: str, nbytes: int, peer: str = "") -> None:
    global _bytes_up, _bytes_down
    now = time.time()
    with _lock:
        if direction in {"up", "out", "send"}:
            _bytes_up += nbytes
            _win_up.append((now, nbytes))
        else:
            _bytes_down += nbytes
            _win_down.append((now, nbytes))
        _trim_windows(now)
    event(direction, f"{nbytes}B {peer}".strip())


def _trim_windows(now: float) -> None:
    cutoff = now - SPEED_WINDOW
    while _win_up and _win_up[0][0] < cutoff:
        _win_up.pop(0)
    while _win_down and _win_down[0][0] < cutoff:
        _win_down.pop(0)


def _bps(window: list) -> float:
    if not window:
        return 0.0
    now = time.time()
    cutoff = now - SPEED_WINDOW
    total = sum(n for t, n in window if t >= cutoff)
    span = max(now - window[0][0], 0.25)
    return total / span


def format_speed(bps: float) -> str:
    bits = bps * 8
    if bits >= 1_000_000:
        return f"{bits / 1_000_000:.2f} Mbps"
    if bits >= 1_000:
        return f"{bits / 1_000:.1f} kbps"
    return f"{bits:.0f} bps"


def snapshot(limit: int = 80) -> dict:
    now = time.time()
    with _lock:
        _trim_windows(now)
        up_bps = max(_bps(_win_up), _nic_up_bps)
        down_bps = max(_bps(_win_down), _nic_down_bps)
        return {
            "lines": list(_lines[-limit:]),
            "bytes_up": _bytes_up,
            "bytes_down": _bytes_down,
            "up_bps": up_bps,
            "down_bps": down_bps,
            "upload": format_speed(up_bps),
            "download": format_speed(down_bps),
        }


_nic_prev = None
_nic_prev_t = 0.0
_nic_up_bps = 0.0
_nic_down_bps = 0.0


def poll_nic() -> tuple[float, float]:
    """Adapter-level bytes/sec from the working Internet interface."""
    global _nic_prev, _nic_prev_t, _nic_up_bps, _nic_down_bps
    import os
    import subprocess

    if os.name != "nt":
        try:
            sent = recv = 0
            with open("/proc/net/dev", encoding="utf-8") as fh:
                for line in fh:
                    if ":" not in line:
                        continue
                    name, rest = line.split(":", 1)
                    name = name.strip()
                    if name == "lo":
                        continue
                    parts = rest.split()
                    if len(parts) >= 9:
                        recv += int(parts[0])
                        sent += int(parts[8])
            now = time.time()
            if _nic_prev is not None and now > _nic_prev_t:
                dt = max(now - _nic_prev_t, 0.2)
                _nic_up_bps = max(0.0, (sent - _nic_prev[0]) / dt)
                _nic_down_bps = max(0.0, (recv - _nic_prev[1]) / dt)
            _nic_prev = (sent, recv)
            _nic_prev_t = now
        except Exception:
            pass
        return _nic_up_bps, _nic_down_bps
    try:
        rec = None
        try:
            import persist

            rec = persist.load_applied()
        except Exception:
            rec = {}
        name = (rec or {}).get("dhcp_adapter") or (rec or {}).get("adapter") or ""
        cmd = (
            "Get-NetAdapterStatistics | "
            "Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Json -Compress"
        )
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=8,
        )
        import json

        raw = res.stdout.strip()
        if not raw:
            return _nic_up_bps, _nic_down_bps
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        sent = recv = 0
        for row in data or []:
            n = str(row.get("Name") or "")
            if name and name.lower() not in n.lower() and n.lower() not in name.lower():
                if not str((rec or {}).get("local_ip") or "").startswith("192."):
                    continue
            sent += int(row.get("SentBytes") or 0)
            recv += int(row.get("ReceivedBytes") or 0)
        now = time.time()
        if _nic_prev is not None and now > _nic_prev_t:
            dt = max(now - _nic_prev_t, 0.2)
            _nic_up_bps = max(0.0, (sent - _nic_prev[0]) / dt)
            _nic_down_bps = max(0.0, (recv - _nic_prev[1]) / dt)
        _nic_prev = (sent, recv)
        _nic_prev_t = now
    except Exception:
        pass
    return _nic_up_bps, _nic_down_bps


def text(limit: int = 80) -> str:
    snap = snapshot(limit)
    head = f"UP {snap['bytes_up']}  DOWN {snap['bytes_down']}"
    return head + "\n" + "\n".join(snap["lines"])
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
