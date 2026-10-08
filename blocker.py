#!/usr/bin/env python3
"""
Simple hosts-file website blocker.

Usage:
  python blocker.py              # block listed sites
  python blocker.py --unblock    # remove this tool's entries
  python blocker.py --list       # show current block list
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Edit this list to change what gets blocked.
BLOCK_SITES = [
    "google-analytics.com",
    "www.google-analytics.com",
    "ssl.google-analytics.com",
    "googletagmanager.com",
    "www.googletagmanager.com",
    "doubleclick.net",
    "stats.g.doubleclick.net",
    "adservice.google.com",
    "pagead2.googlesyndication.com",
    "scorecardresearch.com",
    "sb.scorecardresearch.com",
    "quantserve.com",
    "pixel.quantserve.com",
    "hotjar.com",
    "static.hotjar.com",
    "segment.io",
    "api.segment.io",
    "mixpanel.com",
    "api.mixpanel.com",
    "amplitude.com",
    "api2.amplitude.com",
    "sentry.io",
    "tr.outbrain.com",
    "ads.linkedin.com",
    "bat.bing.com",
    "analytics.tiktok.com",
    "ads.yahoo.com",
    "sp.analytics.yahoo.com",
]

MARKER_BEGIN = "# --- BLOCKER START ---"
MARKER_END = "# --- BLOCKER END ---"
REDIRECT_IP = "127.0.0.1"


def hosts_path() -> Path:
    if os.name == "nt":
        windir = os.environ.get("WINDIR", r"C:\Windows")
        return Path(windir) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def read_hosts(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def write_hosts(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def backup_hosts(path: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"hosts.blocker-backup-{stamp}")
    backup.write_text(path.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
    return backup


def strip_block_section(text: str) -> str:
    lines = text.splitlines()
    out: list[str] = []
    skipping = False
    for line in lines:
        if line.strip() == MARKER_BEGIN:
            skipping = True
            continue
        if line.strip() == MARKER_END:
            skipping = False
            continue
        if not skipping:
            out.append(line)
    return "\n".join(out).rstrip() + "\n"


def build_block_section(sites: list[str]) -> str:
    unique = []
    seen = set()
    for site in sites:
        site = site.strip().lower()
        if site and site not in seen:
            seen.add(site)
            unique.append(site)
    body = "\n".join(f"{REDIRECT_IP} {site}" for site in unique)
    return f"{MARKER_BEGIN}\n{body}\n{MARKER_END}\n"


def apply_block(path: Path, sites: list[str]) -> None:
    original = read_hosts(path)
    cleaned = strip_block_section(original)
    new_content = cleaned.rstrip() + "\n\n" + build_block_section(sites)
    backup = backup_hosts(path)
    write_hosts(path, new_content)
    print(f"Blocked {len(sites)} hostnames.")
    print(f"Backup written to: {backup}")
    print("You may need to flush DNS (ipconfig /flushdns) for changes to apply immediately.")


def apply_unblock(path: Path) -> None:
    original = read_hosts(path)
    cleaned = strip_block_section(original)
    if cleaned == original:
        print("No blocker section found. Nothing to remove.")
        return
    backup = backup_hosts(path)
    write_hosts(path, cleaned)
    print("Blocker section removed.")
    print(f"Backup written to: {backup}")


FILTER_FILE = Path(__file__).resolve().parent / "vpn_data" / "site_filter.json"


def _is_local_or_lan_ip(ip: str) -> bool:
    """True for loopback, unspecified, link-local, and RFC1918 LAN addresses."""
    ip = (ip or "").strip().split("%")[0]
    if not ip or ip in {"*", "::", "::1", "0.0.0.0", "127.0.0.1"}:
        return True
    if ip.startswith("127.") or ip.startswith("169.254.") or ip.startswith("::ffff:127."):
        return True
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        if ip.startswith("172."):
            try:
                second = int(ip.split(".")[1])
            except (IndexError, ValueError):
                return False
            return 16 <= second <= 31
        return True
    if ip.startswith("fc") or ip.startswith("fd") or ip.startswith("fe80"):
        return True
    return False


# Common third-party telemetry / data-mining hosts (blocked by default).
TRACKER_SITES = [
    "google-analytics.com",
    "www.google-analytics.com",
    "ssl.google-analytics.com",
    "googletagmanager.com",
    "www.googletagmanager.com",
    "doubleclick.net",
    "stats.g.doubleclick.net",
    "adservice.google.com",
    "pagead2.googlesyndication.com",
    "scorecardresearch.com",
    "sb.scorecardresearch.com",
    "quantserve.com",
    "pixel.quantserve.com",
    "hotjar.com",
    "static.hotjar.com",
    "segment.io",
    "api.segment.io",
    "mixpanel.com",
    "api.mixpanel.com",
    "amplitude.com",
    "api2.amplitude.com",
    "sentry.io",
    "facebook.com",
    "connect.facebook.net",
    "graph.facebook.com",
    "tr.outbrain.com",
    "ads.linkedin.com",
    "bat.bing.com",
    "analytics.tiktok.com",
    "ads.yahoo.com",
    "sp.analytics.yahoo.com",
]


def _default_filter() -> dict:
    sites = [{"host": h, "blocked": False} for h in BLOCK_SITES]
    seen = {h["host"] for h in sites}
    for h in TRACKER_SITES:
        if h not in seen:
            sites.append({"host": h, "blocked": True})
            seen.add(h)
    return {
        "sites": sites,
        "ip_blacklist": [],
        "protected_dns": [],
    }


def load_filter() -> dict:
    data = _default_filter()
    if FILTER_FILE.exists():
        try:
            saved = json.loads(FILTER_FILE.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                if isinstance(saved.get("sites"), list) and saved["sites"]:
                    data["sites"] = saved["sites"]
                if isinstance(saved.get("ip_blacklist"), list):
                    data["ip_blacklist"] = [
                        ip for ip in saved["ip_blacklist"] if ip and not _is_local_or_lan_ip(str(ip))
                    ]
                if isinstance(saved.get("protected_dns"), list):
                    data["protected_dns"] = saved["protected_dns"]
        except json.JSONDecodeError:
            pass
    return data


def save_filter(data: dict) -> dict:
    FILTER_FILE.parent.mkdir(parents=True, exist_ok=True)
    FILTER_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def all_sites() -> list[dict]:
    return load_filter()["sites"]


def blocked_hosts() -> list[str]:
    return [str(s.get("host") or "").lower() for s in all_sites() if s.get("blocked") and s.get("host")]


def protected_hosts() -> list[str]:
    return [str(s.get("host") or "").lower() for s in all_sites() if not s.get("blocked") and s.get("host")]


def blocked_ips() -> list[str]:
    return [ip.strip() for ip in load_filter().get("ip_blacklist", []) if ip.strip()]


def protected_dns() -> list[str]:
    return [ip.strip() for ip in load_filter().get("protected_dns", []) if ip.strip()]


def add_site(host: str) -> dict:
    host = host.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    if not host:
        raise ValueError("empty host")
    data = load_filter()
    if any(s.get("host") == host for s in data["sites"]):
        return data
    data["sites"].append({"host": host, "blocked": False})
    return save_filter(data)


def set_site_blocked(host: str, blocked: bool) -> dict:
    host = host.strip().lower()
    data = load_filter()
    found = False
    for site in data["sites"]:
        if site.get("host") == host:
            site["blocked"] = bool(blocked)
            found = True
    if not found and host:
        data["sites"].append({"host": host, "blocked": bool(blocked)})
    save_filter(data)
    apply_hosts_from_filter()
    return data


def add_ip(ip: str) -> dict:
    ip = ip.strip()
    data = load_filter()
    if not ip:
        return data
    if _is_local_or_lan_ip(ip):
        # Never blacklist the user's own machine or LAN gateway addresses.
        return data
    if ip not in data["ip_blacklist"]:
        data["ip_blacklist"].append(ip)
        save_filter(data)
    return data


def remove_ip(ip: str) -> dict:
    ip = ip.strip()
    data = load_filter()
    data["ip_blacklist"] = [x for x in data["ip_blacklist"] if x != ip]
    return save_filter(data)


def apply_hosts_from_filter() -> None:
    path = hosts_path()
    blocked = blocked_hosts()
    if blocked:
        apply_block(path, blocked)
    else:
        apply_unblock(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Block or unblock sites via the hosts file.")
    parser.add_argument("--unblock", action="store_true", help="Remove this tool's hosts entries")
    parser.add_argument("--list", action="store_true", help="Print the configured block list")
    args = parser.parse_args()

    if args.list:
        print("Configured sites:")
        for site in BLOCK_SITES:
            print(f"  {site}")
        return 0

    path = hosts_path()
    if not path.exists():
        print(f"Hosts file not found: {path}", file=sys.stderr)
        return 1

    if not os.access(path, os.W_OK) and not is_admin():
        print("This action needs administrator / root rights to edit the hosts file.", file=sys.stderr)
        print("On Windows, right-click run_blocker.bat and choose Run as administrator.", file=sys.stderr)
        return 1

    try:
        if args.unblock:
            apply_unblock(path)
        else:
            apply_block(path, BLOCK_SITES)
    except PermissionError:
        print("Permission denied while writing hosts file. Run as administrator.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
