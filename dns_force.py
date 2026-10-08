#!/usr/bin/env python3
"""Force Windows DNS toward the tunnel DNS list and run a local UDP DNS forwarder."""

from __future__ import annotations

import os
import socket
import subprocess
import threading

import persist
import vpn_server

LISTEN = ("127.0.0.1", "0.0.0.0", 53)
_stop = threading.Event()
_thread = None


def upstream() -> str:
    rec = persist.load_applied()
    dhcp_dns = rec.get("dhcp_dns") or rec.get("protected_dns") or []
    if dhcp_dns:
        return str(dhcp_dns[0])
    state = vpn_server.load_state()
    dns = state.get("dns") or ["1.1.1.1"]
    return dns[0]


def set_windows_dns() -> str:
    if os.name != "nt":
        return "DNS skip (not Windows)"
    target = upstream()
    cmd = (
        "Get-DnsClient | ForEach-Object { "
        f"Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses '{target}' "
        "-ErrorAction SilentlyContinue }"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True)
    persist.write_applied_and_save({"forced_dns": target, "upstream_dns": upstream()})
    return f"Windows NIC DNS set to {target} (forwarded to {upstream()})"


def restore_windows_dns() -> str:
    if os.name != "nt":
        return "DNS skip"
    cmd = (
        "$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue); "
        "foreach ($a in $adapters) { "
        "Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue; "
        "netsh interface ipv4 set dnsservers name=\"$($a.Name)\" source=dhcp | Out-Null; "
        "netsh interface ipv6 set dnsservers name=\"$($a.Name)\" source=dhcp | Out-Null "
        "}; "
        "Get-DnsClient -ErrorAction SilentlyContinue | ForEach-Object { "
        "Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue }"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True)
    return "Windows DNS reset to DHCP/automatic"


def _forward() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(LISTEN)
    except OSError:
        try:
            sock.bind(("127.0.0.1", "0.0.0.0", 53, 5353))
        except OSError:
            return
    sock.settimeout(1.0)
    up = upstream()
    while not _stop.is_set():
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            fwd.settimeout(3)
            fwd.sendto(data, (up, 53))
            resp, _ = fwd.recvfrom(4096)
            sock.sendto(resp, addr)
            fwd.close()
        except OSError:
            pass
    sock.close()


def start() -> str:
    global _thread
    if _thread is not None and _thread.is_alive():
        return set_windows_dns()
    _stop.clear()
    _thread = threading.Thread(target=_forward, name="dns-force", daemon=True)
    _thread.start()
    return set_windows_dns()


def stop() -> str:
    _stop.set()
    return restore_windows_dns()
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
