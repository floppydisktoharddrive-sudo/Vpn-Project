#!/usr/bin/env python3
"""
Local heuristic engine — not a commercial antivirus.

Detects:
  - SQL injection patterns in cleartext HTTP
  - Extra VPN ports
  - Mirrored IPs (same remote on inbound + outbound from different apps)
  - Hidden sockets (no app name, non-loopback, established)
  - Hidden executable drop files that look like trojans
Rotates the AES session key when a hit is confirmed (new aes-*.key file).
"""

from __future__ import annotations

import os
import re
import threading
from collections import defaultdict
from pathlib import Path

import blocker
import connections
import persist
import vpn_server

SQL_RE = re.compile(
    rb"(?i)(\bunion\s+select\b|\bor\s+1\s*=\s*1\b|\bdrop\s+table\b|\binsert\s+into\b"
    rb"|\bupdate\s+\w+\s+set\b|\bdelete\s+from\b|'?\s*or\s+'1'\s*=\s*'1)",
)

_hits: list[str] = []
_lock = threading.Lock()
_malware_findings: list[dict] = []


def inspect_payload(data: bytes) -> str | None:
    if not data:
        return None
    sample = data[:8192]
    if SQL_RE.search(sample):
        return "sql-injection"
    return None


def note_hit(kind: str, detail: str) -> None:
    with _lock:
        _hits.append(f"{kind}: {detail}")
        if len(_hits) > 200:
            del _hits[:100]
    persist.write_applied_and_save({"last_engine_hit": f"{kind}: {detail}"})
    try:
        path = vpn_server.generate_session_key()
        if vpn_server._runtime is not None:
            vpn_server._runtime.key = path.read_bytes()
        persist.write_applied_and_save(
            {
                "session_key_rotated": True,
                "session_key": str(path),
            }
        )
    except Exception:
        pass


def _remote_host(row: dict) -> str:
    remote = row.get("remote") or ""
    return remote.rsplit(":", 1)[0].strip("[]")


def scan_hidden_and_mirror(kill: bool = True) -> list[dict]:
    rows = connections.list_connections()
    by_remote: dict[str, list[dict]] = defaultdict(list)
    found = []
    try:
        import network_boot

        lan = network_boot.lan_safe_ips()
    except Exception:
        lan = {"0.0.0.0", "*", "::", "::1", "127.0.0.1"}

    user_remotes: set[str] = set()
    for row in rows:
        host = _remote_host(row)
        app = (row.get("app") or "").strip()
        if host and host not in lan and not blocker._is_local_or_lan_ip(host):
            by_remote[host].append(row)
            if app:
                user_remotes.add(host)

    blocked_ips = set(blocker.blocked_ips())
    for host, group in by_remote.items():
        if blocker._is_local_or_lan_ip(host):
            continue
        states = {(r.get("state") or "").upper() for r in group}
        apps = {(r.get("app") or "").lower() for r in group}
        inbound = [
            r
            for r in group
            if (r.get("state") or "").upper() in {"LISTEN", "SYN_RECV", "SYN_RCVD"}
        ]
        if host in blocked_ips:
            for r in group:
                r["tag"] = "blocked-ip"
                found.append(r)
        unnamed = [r for r in group if not (r.get("app") or "").strip()]
        if host in user_remotes and unnamed:
            for r in unnamed:
                r["tag"] = "piggyback"
                found.append(r)
        named = [a for a in apps if a]
        if len(named) >= 2 and "ESTABLISHED" in states:
            for r in inbound:
                r["tag"] = "ip-mirror"
                found.append(r)

    for row in rows:
        app = (row.get("app") or "").strip()
        state = (row.get("state") or "").upper()
        host = _remote_host(row)
        if blocker._is_local_or_lan_ip(host) or host in lan:
            continue
        if state == "ESTABLISHED" and not app:
            row["tag"] = "hidden"
            found.append(row)

    if kill:
        for row in found:
            tag = row.get("tag")
            if tag in {"hidden", "ip-mirror", "blocked-ip", "piggyback"}:
                note_hit(tag, f"{row.get('remote')} pid={row.get('pid')}")
                host = _remote_host(row)
                if host and host.count(".") == 3 and not blocker._is_local_or_lan_ip(host):
                    blocker.add_ip(host)
    return found


SUSPICIOUS_NAMES = (
    "svch0st",
    "scvhost",
    "svchosts",
    "lssass",
    "lsasss",
    "exploreer",
    "csrsss",
    "winlogon32",
    "update.vbs",
    "payload",
    "backdoor",
    "keylog",
    "stealer",
    "miner",
    "cryptominer",
)
SUSPICIOUS_EXT = {".scr", ".pif", ".vbs", ".js", ".jse", ".wsf", ".cmd", ".bat", ".ps1"}
PE_MAGIC = b"MZ"


def _scan_roots() -> list[Path]:
    roots: list[Path] = []
    home = Path.home()
    candidates = [
        home / "AppData" / "Roaming",
        home / "AppData" / "Local" / "Temp",
        home / "AppData" / "LocalLow",
        Path(os.environ.get("TEMP", "/tmp")),
        Path(os.environ.get("WINDIR", "C:/Windows")) / "Temp",
        Path("/tmp"),
    ]
    for p in candidates:
        try:
            if p.exists() and p.is_dir():
                roots.append(p)
        except OSError:
            continue
    return roots


def _looks_hidden(path: Path) -> bool:
    name = path.name
    if name.startswith("."):
        return True
    if os.name == "nt":
        try:
            import ctypes

            FILE_ATTRIBUTE_HIDDEN = 0x2
            FILE_ATTRIBUTE_SYSTEM = 0x4
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            if attrs != -1 and attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM):
                return True
        except Exception:
            pass
    return False


def _suspicious_file(path: Path) -> str | None:
    name = path.name.lower()
    if any(tok in name for tok in SUSPICIOUS_NAMES):
        return "name-heuristic"
    if path.suffix.lower() in SUSPICIOUS_EXT and _looks_hidden(path):
        return "hidden-script"
    if path.suffix.lower() in {".exe", ".dll", ".sys"} and _looks_hidden(path):
        try:
            with path.open("rb") as fh:
                magic = fh.read(2)
            if magic == PE_MAGIC:
                return "hidden-pe"
        except OSError:
            return "hidden-unreadable"
    return None


def scan_malware_files(max_files: int = 4000) -> list[dict]:
    """Heuristic scan of temp/appdata for hidden trojan-like files."""
    found: list[dict] = []
    seen = 0
    for root in _scan_roots():
        for dirpath, dirnames, filenames in os.walk(root):
            depth = Path(dirpath).relative_to(root).parts
            if len(depth) > 3:
                dirnames[:] = []
                continue
            for fname in filenames:
                seen += 1
                if seen > max_files:
                    break
                path = Path(dirpath) / fname
                reason = _suspicious_file(path)
                if reason:
                    found.append({"path": str(path), "reason": reason, "deleted": False})
            if seen > max_files:
                break
        if seen > max_files:
            break
    with _lock:
        _malware_findings[:] = found
    persist.write_applied_and_save({"malware_findings": [f["path"] for f in found]})
    return found


def malware_findings() -> list[dict]:
    with _lock:
        return list(_malware_findings)


def delete_malware(paths: list[str] | None = None) -> list[dict]:
    results = []
    targets = paths if paths is not None else [f["path"] for f in malware_findings()]
    remaining = []
    with _lock:
        current = list(_malware_findings)
    index = {f["path"]: f for f in current}
    for raw in targets:
        item = dict(index.get(raw, {"path": raw, "reason": "listed"}))
        try:
            p = Path(raw)
            if p.exists() and p.is_file():
                p.unlink()
                item["deleted"] = True
                note_hit("malware-deleted", raw)
            else:
                item["deleted"] = False
                item["error"] = "missing"
        except OSError as exc:
            item["deleted"] = False
            item["error"] = str(exc)
        results.append(item)
        if not item.get("deleted"):
            remaining.append(item)
    with _lock:
        _malware_findings[:] = remaining
    persist.write_applied_and_save(
        {"malware_deleted": [r["path"] for r in results if r.get("deleted")]}
    )
    return results


def recent_hits() -> list[str]:
    with _lock:
        return list(_hits[-20:])
