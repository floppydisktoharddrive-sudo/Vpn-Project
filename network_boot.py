#!/usr/bin/env python3
"""Reset adapters to a clean default, probe the Internet, print LAN addresses."""

from __future__ import annotations

import os
import time
from pathlib import Path
import re
import socket
import subprocess
import sys
from typing import Callable

import persist

# Existing broadband listener on the 192.x LAN (not PdaNet 10.x).
BROADBAND_PORT = 8000


def _run(cmd: list[str], timeout: int = 45) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        return subprocess.CompletedProcess(cmd, 1, "", str(exc))


def _ps(script: str, timeout: int = 45) -> str:
    res = _run(["powershell", "-NoProfile", "-Command", script], timeout=timeout)
    return (res.stdout or res.stderr or "").strip()


_BRIDGE_NAMES = (
    "vethernet",
    "hyper-v",
    "default switch",
    "wsl",
    "docker",
    "virtualbox",
    "vmware",
    "vbox",
    "loopback",
    "bluetooth",
    "isatap",
    "teredo",
    "nat",
)


def _is_192(ip: str) -> bool:
    return (ip or "").startswith("192.")


def _is_10(ip: str) -> bool:
    return (ip or "").startswith("10.")


def _is_bridge_name(name: str) -> bool:
    n = (name or "").lower()
    return any(tok in n for tok in _BRIDGE_NAMES)


_PDANET_NAMES = (
    "pdanet",
    "pda net",
    "pda-net",
    "foxfi",
    "juno",
    "remote ndis",
    "rndis",
    "usb ethernet",
    "usb tethering",
    "android usb",
    "windows mobile",
    "internet sharing device",
    "mobile broadband",
    "lte",
    "cellular",
)


def _is_pdanet_name(name: str) -> bool:
    n = (name or "").lower()
    return any(tok in n for tok in _PDANET_NAMES)


def classify_adapter(name: str, ip: str = "", gw: str = "") -> str:
    if _is_pdanet_name(name):
        return "pdanet"
    if _is_bridge_name(name) or _is_10(ip) or _is_10(gw):
        return "bridge"
    low = (name or "").lower()
    if "wi-fi" in low or "wifi" in low or "wlan" in low:
        return "modem_router_wifi"
    if "ethernet" in low or "local area" in low or "gigabit" in low or "realtek" in low:
        return "modem_router_ethernet"
    if _is_192(ip) or _is_192(gw):
        return "modem_router"
    return "other"


def probe_broadband_192(local_ip: str, gateway: str = "", timeout: float = 3.0) -> tuple[bool, str, int]:
    """Attach to the existing 192.x:8000 broadband endpoint."""
    candidates = []
    if _is_192(local_ip):
        candidates.append(local_ip)
    if _is_192(gateway):
        candidates.append(gateway)
    for host in candidates:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if local_ip and _is_192(local_ip):
                try:
                    s.bind((local_ip, 0))
                except OSError:
                    pass
            s.connect((host, BROADBAND_PORT))
            s.close()
            return True, host, BROADBAND_PORT
        except OSError:
            try:
                s.close()
            except OSError:
                pass
    # Do not report success just because the address is 192.x — that hid real
    # connect failures and made boot skip DHCP repair.
    return False, local_ip if _is_192(local_ip) else "", BROADBAND_PORT


def probe_from(local_ip: str, timeout: float = 3.0) -> tuple[bool, str, int]:
    """Bind to a 192.x address and see if the Internet answers. Returns (ok, host, port)."""
    if _is_192(local_ip):
        ok, host, port = probe_broadband_192(local_ip, timeout=timeout)
        if ok:
            return ok, host, port
    targets = [("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 53)]
    last_port = 443
    for host, port in targets:
        last_port = port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if local_ip and local_ip not in {"0.0.0.0", "127.0.0.1"}:
                try:
                    s.bind((local_ip, 0))
                except OSError:
                    pass
            s.connect((host, port))
            s.close()
            return True, host, port
        except OSError:
            try:
                s.close()
            except OSError:
                pass
            continue
    return False, "", last_port


def _drop_fec(items) -> list[str]:
    """Windows invents fec0:0:0:ffff::* when no DNS is set. Never keep those."""
    out, seen = [], set()
    for raw in items or []:
        item = str(raw).strip()
        low = item.lower()
        if not item or low in {"0.0.0.0", "::", "::1"} or low.startswith("fec0:"):
            continue
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def auto_dns(row: dict) -> list[str]:
    """Modem/router: use NIC DNS or the 192.x gateway. PdaNet: keep whatever is already working."""
    dns = _drop_fec(d for d in (row.get("dns") or []) if d and not _is_10(d) and d not in {"0.0.0.0"})
    gw = row.get("gateway") or ""
    kind = classify_adapter(row.get("adapter") or "", row.get("local_ip") or "", gw)
    if kind.startswith("modem_router"):
        if gw and _is_192(gw) and gw not in dns:
            dns = [gw] + dns
        if not dns:
            dns = ["1.1.1.1", "1.0.0.1"]
        # unique, gateway first
        out, seen = [], set()
        for item in dns:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out[:4]
    if kind == "pdanet":
        if dns:
            return dns[:4]
        if gw:
            return [gw, "1.1.1.1"]
        return ["1.1.1.1", "8.8.8.8"]
    if dns:
        return dns[:4]
    if gw:
        return [gw, "1.1.1.1"]
    return ["1.1.1.1", "1.0.0.1"]


def _score_lan(row: dict) -> int:
    """Prefer real 192.x LAN + 192.x gateway. Demote 10.x virtual bridges."""
    ip = row.get("local_ip") or ""
    gw = row.get("gateway") or ""
    name = row.get("adapter") or ""
    score = 0
    if _is_bridge_name(name):
        score -= 1000
    if _is_192(gw):
        score += 800
    if _is_192(ip):
        score += 600
    if ip.startswith("192.168.") or gw.startswith("192.168."):
        score += 200
    if _is_10(gw) or _is_10(ip):
        score -= 500
    low = name.lower()
    if _is_pdanet_name(name):
        score += 900
    if "wi-fi" in low or "wifi" in low or "ethernet" in low or "local area" in low:
        score += 80
    if row.get("up"):
        score += 30
    if gw:
        score += 10
    return score


def _parse_rows(raw: str) -> list[dict]:
    rows: list[dict] = []
    cur: dict = {}
    for line in raw.splitlines():
        line = line.strip()
        if line == "---":
            if cur.get("local_ip"):
                rows.append(cur)
            cur = {}
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if k == "LOCAL":
            cur["local_ip"] = v
        elif k == "GATEWAY":
            cur["gateway"] = v
        elif k == "ADAPTER":
            cur["adapter"] = v
        elif k == "DNS":
            cur["dns"] = _drop_fec(p.strip() for p in v.split(",") if p.strip())
        elif k == "UP":
            cur["up"] = v.lower() in {"true", "up", "1", "yes"}
    if cur.get("local_ip"):
        rows.append(cur)
    return rows


def _route_gateways_192() -> list[tuple[str, str]]:
    """(gateway, iface_ip_hint) from route print, 192.x first."""
    found: list[tuple[str, str]] = []
    if os.name != "nt":
        return found
    route = _run(["route", "print"])
    text = route.stdout or ""
    for m in re.finditer(
        r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
        text,
    ):
        gw, iface = m.group(1), m.group(2)
        found.append((gw, iface))
    found.sort(key=lambda t: (0 if _is_192(t[0]) else 1, 0 if _is_192(t[1]) else 1, 0 if not _is_10(t[0]) else 1))
    return found


def local_and_gateway() -> dict:
    """Pick the true LAN NIC: 192.x address + 192.x gateway, never a 10.x bridge first."""
    info = {"local_ip": "", "gateway": "", "adapter": "", "dns": [], "raw": "", "candidates": []}
    rows: list[dict] = []
    if os.name == "nt":
        script = (
            "Get-NetIPConfiguration | ForEach-Object { "
            "  $ip = ($_.IPv4Address | Select-Object -First 1).IPAddress; "
            "  $gw = ($_.IPv4DefaultGateway | Select-Object -First 1).NextHop; "
            "  $dns = @($_.DNSServer.ServerAddresses) -join ','; "
            "  $up = $_.NetAdapter.Status; "
            "  if ($ip) { "
            "    Write-Output ('LOCAL=' + $ip); "
            "    Write-Output ('GATEWAY=' + $gw); "
            "    Write-Output ('ADAPTER=' + $_.InterfaceAlias); "
            "    Write-Output ('DNS=' + $dns); "
            "    Write-Output ('UP=' + $up); "
            "    Write-Output '---'; "
            "  } "
            "}"
        )
        raw = _ps(script)
        info["raw"] = raw
        rows = _parse_rows(raw)
    info["candidates"] = [
        f"{r.get('adapter')} {r.get('local_ip')} gw={r.get('gateway') or '-'} score={_score_lan(r)}"
        for r in rows
    ]

    preferred = [r for r in rows if _is_192(r.get("local_ip") or "") or _is_192(r.get("gateway") or "")]
    preferred = [r for r in preferred if not _is_10(r.get("local_ip") or "") and not _is_10(r.get("gateway") or "")]
    pool = preferred or [r for r in rows if not _is_10(r.get("gateway") or "") and not _is_bridge_name(r.get("adapter") or "")] or rows
    if pool:
        best = max(pool, key=_score_lan)
        info["local_ip"] = best.get("local_ip") or ""
        info["gateway"] = best.get("gateway") or ""
        info["adapter"] = best.get("adapter") or ""
        info["dns"] = best.get("dns") or []

    # If PowerShell still handed us a 10.x gateway, take a 192.x default route instead.
    if _is_10(info.get("gateway") or "") or not info.get("gateway"):
        for gw, iface in _route_gateways_192():
            if _is_192(gw):
                info["gateway"] = gw
                if _is_192(iface) and not _is_192(info.get("local_ip") or ""):
                    info["local_ip"] = iface
                break

    if _is_10(info.get("local_ip") or ""):
        for r in sorted(rows, key=_score_lan, reverse=True):
            if _is_192(r.get("local_ip") or "") and not _is_bridge_name(r.get("adapter") or ""):
                info["local_ip"] = r["local_ip"]
                info["adapter"] = r.get("adapter") or info.get("adapter") or ""
                if _is_192(r.get("gateway") or ""):
                    info["gateway"] = r["gateway"]
                if r.get("dns"):
                    info["dns"] = r["dns"]
                break

    if not info["local_ip"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("1.1.1.1", 80))
            hint = s.getsockname()[0]
            s.close()
            if _is_192(hint) or not info["local_ip"]:
                if not _is_10(hint):
                    info["local_ip"] = hint
        except OSError:
            try:
                hint = socket.gethostbyname(socket.gethostname())
                if _is_192(hint):
                    info["local_ip"] = hint
            except OSError:
                pass
    if not info["local_ip"]:
        info["local_ip"] = "127.0.0.1"

    # Private bind = 192.x LAN. PdaNet 10.x is a separate public tether.
    live_rows = []
    for r in rows:
        ok, host, port = probe_from(r.get("local_ip") or "", timeout=2.5)
        r = dict(r)
        r["internet_ok"] = ok
        r["broadband_target"] = host
        r["broadband_port"] = port
        r["kind"] = classify_adapter(r.get("adapter") or "", r.get("local_ip") or "", r.get("gateway") or "")
        if ok:
            live_rows.append(r)
    pick = None
    pdanet_live = [r for r in live_rows if r.get("kind") == "pdanet"]
    router_live = [r for r in live_rows if str(r.get("kind") or "").startswith("modem_router") or _is_192(r.get("local_ip") or "")]
    lan_192 = [
        r
        for r in (rows + live_rows)
        if _is_192(r.get("local_ip") or "") or _is_192(r.get("gateway") or "")
    ]
    if lan_192:
        pick = max(lan_192, key=_score_lan)
    elif router_live:
        pick = max(router_live, key=_score_lan)
    elif pdanet_live:
        pick = max(pdanet_live, key=_score_lan)
    elif live_rows:
        pick = max(live_rows, key=_score_lan)
    if pdanet_live:
        pd = max(pdanet_live, key=_score_lan)
        info["public_ip"] = pd.get("local_ip") or ""
        info["public_gateway"] = pd.get("gateway") or ""
        info["public_adapter"] = pd.get("adapter") or ""
    if pick:
        info["local_ip"] = pick.get("local_ip") or info["local_ip"]
        info["gateway"] = pick.get("gateway") or info["gateway"]
        info["adapter"] = pick.get("adapter") or info["adapter"]
        info["dns"] = auto_dns(pick)
        info["kind"] = pick.get("kind") or classify_adapter(info.get("adapter") or "", info.get("local_ip") or "", info.get("gateway") or "")
        if _is_192(info.get("local_ip") or "") or _is_192(info.get("gateway") or ""):
            ok192, host192, port192 = probe_broadband_192(
                info.get("local_ip") or "",
                info.get("gateway") or "",
            )
            info["internet_ok"] = bool(ok192 or pick.get("internet_ok") or live_rows)
            info["broadband_target"] = host192 or info.get("local_ip") or ""
            info["broadband_port"] = port192 or BROADBAND_PORT
        else:
            info["internet_ok"] = bool(pick.get("internet_ok") or live_rows or pdanet_live)
            info["broadband_target"] = pick.get("broadband_target") or ""
            info["broadband_port"] = pick.get("broadband_port") or BROADBAND_PORT
    else:
        info["dns"] = auto_dns(info)
        info["internet_ok"] = False
        ok, host, port = probe_from(info.get("local_ip") or "", timeout=2.5)
        info["internet_ok"] = ok
        info["broadband_target"] = host
        info["broadband_port"] = port
        info["kind"] = classify_adapter(info.get("adapter") or "", info.get("local_ip") or "", info.get("gateway") or "")
    return info


def probe_internet(timeout: float = 3.0, info: dict | None = None) -> tuple[bool, str]:
    info = info or local_and_gateway()
    ok = bool(info.get("internet_ok"))
    host = info.get("broadband_target") or ""
    port = info.get("broadband_port") or 443
    kind = info.get("kind") or "unknown"
    adapter = info.get("adapter") or "(unknown)"
    if not ok:
        ok, host, port = probe_from(info.get("local_ip") or "", timeout=timeout)
    if ok:
        label = {
            "pdanet": "PdaNet tether",
            "modem_router": "modem/router",
            "modem_router_wifi": "Wi-Fi modem/router",
            "modem_router_ethernet": "Ethernet modem/router",
        }.get(kind, kind)
        ip = info.get("local_ip") or ""
        if _is_192(ip):
            return True, (
                f"OK reachable via 192.x broadband {ip}:{BROADBAND_PORT} "
                f"gw {info.get('gateway') or '-'} ({label})"
            )
        return True, (
            f"OK reachable via {label} adapter '{adapter}' "
            f"{ip} -> gw {info.get('gateway') or '-'} "
            f"to {host}:{port}"
        )
    return False, f"No Internet on '{adapter}' {info.get('local_ip')} gw {info.get('gateway') or '-'}"


def reset_to_default(log: Callable[[str], None] | None = None) -> list[str]:
    """Clear proxy / DNS overrides and flush name cache. Does not wipe the NIC."""
    notes: list[str] = []

    def say(msg: str) -> None:
        notes.append(msg)
        if log:
            log(msg)
        else:
            print(msg)

    if os.name != "nt":
        say("Not Windows — skipped adapter reset.")
        return notes

    say("Resetting WinHTTP and user proxy to default (direct)...")
    _run(["netsh", "winhttp", "reset", "proxy"])
    _ps(
        "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
        "-Name ProxyEnable -Value 0 -ErrorAction SilentlyContinue"
    )

    say("Resetting NIC DNS to DHCP/automatic...")
    _ps(
        "$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue); "
        "foreach ($a in $adapters) { "
        "Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue; "
        "netsh interface ipv4 set dnsservers name=\"$($a.Name)\" source=dhcp | Out-Null; "
        "netsh interface ipv6 set dnsservers name=\"$($a.Name)\" source=dhcp | Out-Null "
        "}; "
        "Get-DnsClient -ErrorAction SilentlyContinue | ForEach-Object { "
        "Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue }"
    )

    say("Flushing DNS cache...")
    _run(["ipconfig", "/flushdns"])

    say("Clearing ARP cache...")
    _run(["netsh", "interface", "ip", "delete", "arpcache"])

    say("Proxy and DNS restored. Port lock/block is not applied.")
    return notes


def repair_if_offline(log: Callable[[str], None] | None = None) -> list[str]:
    """Deeper repair used only when the Internet probe fails."""
    notes: list[str] = []

    def say(msg: str) -> None:
        notes.append(msg)
        if log:
            log(msg)
        else:
            print(msg)

    if os.name != "nt":
        say("Offline repair skipped (not Windows).")
        return notes

    say("No Internet — running adapter diagnostics...")
    info = local_and_gateway()
    say(f"  Local IPv4 : {info.get('local_ip') or '(none)'}")
    say(f"  Gateway    : {info.get('gateway') or '(none)'}")
    say(f"  Adapter    : {info.get('adapter') or '(unknown)'}")
    say(f"  NIC DNS    : {', '.join(info.get('dns') or []) or '(dhcp)'}")

    adapter = info.get("adapter") or ""
    flag = Path(__file__).resolve().parent / "vpn_data" / "need_soft_reset.flag"
    flag.parent.mkdir(parents=True, exist_ok=True)
    flag.write_text(adapter, encoding="utf-8")
    say("Offline only — soft adapter + Winsock reset. Desktop stays logged in. No reboot.")
    bat = Path(__file__).resolve().parent / "soft_reset.bat"
    if bat.exists():
        say(f"Running {bat.name} for '{adapter or 'all adapters'}'...")
        _run(["cmd", "/c", str(bat), adapter], timeout=120)
        try:
            flag.unlink()
        except OSError:
            pass
    else:
        say("soft_reset.bat missing — running the same steps inline.")
        _run(["netsh", "winsock", "reset"], timeout=60)
        _run(["netsh", "int", "ip", "reset"], timeout=60)
        _run(["netsh", "winhttp", "reset", "proxy"])
        _run(["ipconfig", "/flushdns"])
        _run(["netsh", "interface", "ip", "delete", "arpcache"])
        if adapter:
            say(f"Bouncing adapter '{adapter}' (disable/enable, session stays up)...")
            _run(["netsh", "interface", "set", "interface", f"name={adapter}", "admin=disabled"], timeout=30)
            _run(["netsh", "interface", "set", "interface", f"name={adapter}", "admin=enabled"], timeout=30)
        _run(["ipconfig", "/release"], timeout=60)
        _run(["ipconfig", "/renew"], timeout=90)
        _run(["net", "stop", "dnscache"], timeout=30)
        _run(["net", "start", "dnscache"], timeout=30)
    say("Soft reset finished. Windows may print a reboot hint; this process does not restart the PC.")
    return notes


def boot_network() -> dict:
    """Called from start.bat before the GUI."""
    print("=== NetLock connection bind ===")
    print("Detecting working Internet first, then binding, then launch.")
    info = local_and_gateway()
    ok, detail = probe_internet(info=info)
    if ok:
        print("Internet already working — skipping adapter reset so the session stays up.")
    else:
        print("Internet not reachable — resetting adapters to default.")
        reset_to_default()
        info = local_and_gateway()
    print(f"Local IPv4 : {info.get('local_ip') or '(none)'}")
    print(f"Gateway    : {info.get('gateway') or '(none)'}")
    print(f"Adapter    : {info.get('adapter') or '(unknown)'}")
    print(f"Kind       : {info.get('kind') or '(unknown)'}")
    print(f"DNS auto   : {', '.join(info.get('dns') or []) or '(none)'}")
    if info.get("candidates"):
        print("Adapters considered (192.x modem/router or PdaNet; 10.x bridge demoted):")
        for line in info["candidates"]:
            print(f"  {line}")
    ok, detail = probe_internet(info=info)
    print(f"Internet   : {'OK reachable — ' + detail if ok else 'FAIL — ' + detail}")
    if not ok:
        repair_if_offline()
        info = local_and_gateway()
        print("--- after repair ---")
        print(f"Local IPv4 : {info.get('local_ip') or '(none)'}")
        print(f"Gateway    : {info.get('gateway') or '(none)'}")
        print(f"Kind       : {info.get('kind') or '(unknown)'}")
        ok, detail = probe_internet(info=info)
        print(f"Internet   : {'OK reachable — ' + detail if ok else 'FAIL — ' + detail}")
        if not ok:
            print("Still offline. Check the cable/Wi-Fi radio or PdaNet tether, then start the GUI anyway.")
    persist.write_applied_and_save(
        {
            "local_ip": info.get("local_ip"),
            "gateway": info.get("gateway"),
            "adapter": info.get("adapter"),
            "bind": info.get("local_ip") if str(info.get("local_ip") or "").startswith("192.") else "",
            "internet_ok": ok,
            "internet_detail": detail,
            "connection_kind": info.get("kind"),
            "broadband_target": info.get("broadband_target"),
            "broadband_port": info.get("broadband_port"),
            "tunnel_dns": info.get("dns") or ["1.1.1.1", "1.0.0.1"],
            "wildcard": False,
            "wildcard_online": bool(ok),
        }
    )
    try:
        import dhcp_bind

        bound = dhcp_bind.auto_bind_and_save()
        print(
            f"DHCP bind  : {bound.get('dhcp_ip') or '(none)'} "
            f"dns={', '.join(bound.get('dhcp_dns') or [])} "
            f"gateway_dns={'ok' if bound.get('dhcp_dns_verified') else 'fail'} "
            f"binding={'ok' if bound.get('dhcp_binding_ok') else 'fail'}"
        )
        print(f"Protected DNS: {', '.join(bound.get('protected_dns') or [])}")
        print("VPN off. DHCP bind left on the selected mode.")
        persist.write_applied_and_save({"firewall_mode": "off", "port_lock": False})
    except Exception as exc:
        print(f"DHCP bind  : skipped ({exc})")
    try:
        import netlock_net

        attached = netlock_net.attach_existing_broadband(info.get("local_ip") or "", BROADBAND_PORT)
        print(f"C helper   : {attached}")
        info["c_net"] = attached
    except Exception as exc:
        print(f"C helper   : skipped ({exc})")
    persist.write_applied_and_save({
        "wildcard": False,
        "wildcard_configured": False,
        "wildcard_online": bool(ok),
    })
    print("Wildcard   : False address=0.0.0.0 (off until the GUI turns it on)")
    info["wildcard"] = False
    print("=== reset complete ===")
    return {"ok": ok, "detail": detail, **info}


def restore_original_and_wait() -> bool:
    """Drop NetLock config, restore DHCP and firewall, block 1.0.0.0, wait until online."""
    print("Closing: removing NetLock configuration...")
    try:
        import vpn_server
        print(vpn_server.stop_server()[1])
    except Exception as exc:
        print(f"VPN stop skipped: {exc}")
    try:
        import guard
        print(guard.stop()[1])
    except Exception as exc:
        print(f"Guard stop skipped: {exc}")
    try:
        import app_proxy
        print(app_proxy.stop())
    except Exception as exc:
        print(f"Proxy stop skipped: {exc}")
    try:
        import parallel_processor
        parallel_processor.stop()
        print("Parallel binds closed.")
    except Exception as exc:
        print(f"Parallel stop skipped: {exc}")
    try:
        import dns_force
        print(dns_force.stop())
    except Exception as exc:
        print(f"DNS force stop skipped: {exc}")
    try:
        import wintun_tun
        print(wintun_tun.stop())
    except Exception as exc:
        print(f"Wintun stop skipped: {exc}")
    try:
        import blocker
        blocker.apply_unblock(blocker.hosts_path())
        data = blocker.load_filter()
        data["protected_dns"] = [x for x in data.get("protected_dns") or [] if x != "1.0.0.0"]
        blocker.add_ip("1.0.0.0")
        blocker.save_filter(data)
        print("Hosts configuration removed. 1.0.0.0 disabled and guarded.")
    except Exception as exc:
        print(f"Blocker cleanup skipped: {exc}")
    try:
        import netlock
        state = netlock.load_state()
        netlock.delete_netlock_rules()
        if os.name == "nt":
            for profile in ("domain", "private", "public"):
                _run(["netsh", "advfirewall", "set", profile + "profile", "state", "on"])
                _run(["netsh", "advfirewall", "set", profile + "profile", "firewallpolicy", "blockinbound,allowoutbound"])
            _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=NetLock - guard 1.0.0.0", "dir=in", "action=block",
                "remoteip=1.0.0.0", "enable=yes",
            ])
            _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=NetLock - guard 1.0.0.0 out", "dir=out", "action=block",
                "remoteip=1.0.0.0", "enable=yes",
            ])
        state["mode"] = "off"
        netlock.save_state(state)
        print("Firewall restored to original inbound-block / outbound-allow.")
    except Exception as exc:
        print(f"Firewall restore skipped: {exc}")
    reset_to_default()
    if os.name == "nt":
        print("Renewing DHCP...")
        _run(["ipconfig", "/renew"], timeout=60)
    try:
        import persist
        persist.write_applied_and_save({
            "firewall_mode": "off",
            "vpn_running": False,
            "vpn_public_running": False,
            "http_guard": False,
            "wildcard": False,
            "protected_dns": [],
        })
    except Exception:
        pass
    print("Waiting until the connection is live...")
    for _ in range(12):
        ok, detail = probe_internet(timeout=3.0)
        print(detail)
        if ok:
            print("Connection is live.")
            return True
        time.sleep(2)
    print("Connection was not confirmed live.")
    return False


def lan_safe_ips() -> set[str]:
    rec = persist.load_applied()
    out = {"127.0.0.1", "::1", "0.0.0.0", "*", ""}
    for key in ("local_ip", "gateway", "bind", "dhcp_ip", "dhcp_gateway"):
        val = (rec.get(key) or "").strip()
        if val:
            out.add(val)
    for d in rec.get("dhcp_dns") or rec.get("protected_dns") or []:
        if d:
            out.add(str(d).strip())
    # Whole 192.x LAN is treated as the local path, not a NIC identity.
    for val in list(out):
        if _is_192(val):
            parts = val.split(".")
            if len(parts) == 4:
                prefix = ".".join(parts[:3]) + "."
                out.add(prefix + "0")
                out.add(prefix + "1")
                out.add(prefix + "255")
    return out


if __name__ == "__main__":
    boot_network()
    raise SystemExit(0)
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
