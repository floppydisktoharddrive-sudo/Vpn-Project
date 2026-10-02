#!/usr/bin/env python3
"""Discover open desktop apps and keep them on the protection list."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parent
APPS_FILE = BASE / "vpn_data" / "protected_apps.json"

SKIP = {
    "explorer.exe",
    "searchhost.exe",
    "texinputhost.exe",
    "applicationframehost.exe",
    "systemsettings.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "runtimebroker.exe",
    "dwm.exe",
    "sihost.exe",
    "taskmgr.exe",
    "conhost.exe",
}


def load_protected() -> list[str]:
    if APPS_FILE.exists():
        try:
            data = json.loads(APPS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("apps"), list):
                return [str(a) for a in data["apps"] if a]
        except json.JSONDecodeError:
            pass
    return []


def save_protected(apps: list[str]) -> list[str]:
    APPS_FILE.parent.mkdir(parents=True, exist_ok=True)
    unique = []
    seen = set()
    for name in apps:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(name)
    APPS_FILE.write_text(json.dumps({"apps": unique}, indent=2), encoding="utf-8")
    return unique


def desktop_processes() -> list[dict]:
    rows: list[dict] = []
    if os.name == "nt":
        cmd = (
            "Get-Process | Where-Object { $_.MainWindowTitle } | "
            "Select-Object Id, ProcessName, MainWindowTitle | ConvertTo-Json -Compress"
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=20,
            )
            raw = res.stdout.strip()
            if raw:
                data = json.loads(raw)
                if isinstance(data, dict):
                    data = [data]
                for item in data or []:
                    name = str(item.get("ProcessName") or "")
                    if not name:
                        continue
                    exe = name if name.lower().endswith(".exe") else name + ".exe"
                    if exe.lower() in SKIP:
                        continue
                    rows.append(
                        {
                            "pid": str(item.get("Id") or ""),
                            "app": exe,
                            "title": str(item.get("MainWindowTitle") or ""),
                        }
                    )
        except Exception:
            pass
        return rows
    try:
        res = subprocess.run(["ps", "-eo", "pid,comm"], capture_output=True, text=True, timeout=10)
        for line in res.stdout.splitlines()[1:]:
            parts = line.split(None, 1)
            if len(parts) == 2:
                rows.append({"pid": parts[0], "app": parts[1], "title": ""})
    except Exception:
        pass
    return rows


def all_process_names() -> list[str]:
    names: list[str] = []
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
                if parts and parts[0].lower().endswith(".exe") and parts[0].lower() not in SKIP:
                    names.append(parts[0])
        except Exception:
            pass
        return names
    return [p["app"] for p in desktop_processes()]


def sync_open_apps() -> list[str]:
    """Desktop-window apps stay on the do-not-kill list."""
    current = load_protected()
    found = [p["app"] for p in desktop_processes()]
    return save_protected(current + found)


def list_api_clients() -> list[str]:
    """Every running program is treated as a proxy/API client."""
    return sorted(set(all_process_names() + [p["app"] for p in desktop_processes()]))


def is_protected_app(name: str) -> bool:
    name = (name or "").lower()
    if not name:
        return False
    for item in load_protected():
        item_l = item.lower()
        if name == item_l or name.startswith(item_l.removesuffix(".exe")) or item_l in name:
            return True
    return False
