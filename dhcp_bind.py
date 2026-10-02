#!/usr/bin/env python3
"""Read DHCP-assigned IPv4/DNS and auto-bind NetLock to those settings."""

from __future__ import annotations

import os
import re
import subprocess

import persist

BROADBAND_PORT = 8000


def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.stdout or res.stderr or ""
    except Exception as exc:
        return str(exc)


def _ps(script: str) -> str:
    return _run(["powershell", "-NoProfile", "-Command", script])


def read_dhcp() -> dict:
    """DHCP lease address, gateway, and the DNS servers that established broadband."""
    info = {
        "ip": "",
        "gateway": "",
        "dns": [],
        "adapter": "",
        "dhcp_enabled": True,
        "lease_server": "",
    }
    if os.name == "nt":
        script = (
            "$cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4Address }; "
            "foreach ($c in $cfg) { "
            "  $ip = ($c.IPv4Address | Select-Object -First 1).IPAddress; "
            "  $gw = ($c.IPv4DefaultGateway | Select-Object -First 1).NextHop; "
            "  $dns = @($c.DNSServer.ServerAddresses) -join ','; "
            "  $dhcp = (Get-NetIPInterface -InterfaceIndex $c.InterfaceIndex -AddressFamily IPv4 "
            "           -ErrorAction SilentlyContinue).Dhcp; "
            "  Write-Output ('IP=' + $ip); "
            "  Write-Output ('GATEWAY=' + $gw); "
            "  Write-Output ('DNS=' + $dns); "
            "  Write-Output ('ADAPTER=' + $c.InterfaceAlias); "
            "  Write-Output ('DHCP=' + $dhcp); "
            "  Write-Output '---'; "
            "}"
        )
        raw = _ps(script)
        blocks = raw.split("---")
        best = None
        for block in blocks:
            row = {}
            for line in block.splitlines():
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                row[k.strip()] = v.strip()
            ip = row.get("IP") or ""
            if ip.startswith("192."):
                best = row
                break
            if ip and best is None:
                best = row
        if best:
            info["ip"] = best.get("IP") or ""
            info["gateway"] = best.get("GATEWAY") or ""
            info["adapter"] = best.get("ADAPTER") or ""
            info["dhcp_enabled"] = str(best.get("DHCP") or "").lower() in {"enabled", "true", "1"}
            info["dns"] = [p.strip() for p in (best.get("DNS") or "").split(",") if p.strip()]
        ipcfg = _run(["ipconfig", "/all"])
        m = re.search(r"DHCP Server[^\d]*(\d+\.\d+\.\d+\.\d+)", ipcfg, re.I)
        if m:
            info["lease_server"] = m.group(1)
        if not info["dns"]:
            for m in re.finditer(r"DNS Servers[^\d]*((\d+\.\d+\.\d+\.\d+\s*)+)", ipcfg, re.I):
                info["dns"].extend(re.findall(r"\d+\.\d+\.\d+\.\d+", m.group(1)))
    else:
        try:
            import socket

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("1.1.1.1", 80))
            info["ip"] = s.getsockname()[0]
            s.close()
        except OSError:
            pass
        resolv = "/etc/resolv.conf"
        if os.path.exists(resolv):
            for line in open(resolv, encoding="utf-8", errors="replace"):
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        info["dns"].append(parts[1])
    # unique dns
    seen, dns = set(), []
    for d in info["dns"]:
        if d not in seen and d not in {"0.0.0.0"}:
            seen.add(d)
            dns.append(d)
    info["dns"] = dns
    return info


def protect_dhcp_dns(dns: list[str]) -> list[str]:
    """Keep the DNS that established broadband off the kill/block lists."""
    import blocker

    data = blocker.load_filter()
    protected = list(data.get("protected_dns") or [])
    for server in dns:
        if server and server not in protected:
            protected.append(server)
        # DNS hostnames are IPs; also keep them off the IP blacklist.
        if server in data.get("ip_blacklist", []):
            data["ip_blacklist"] = [x for x in data["ip_blacklist"] if x != server]
    data["protected_dns"] = protected
    blocker.save_filter(data)
    persist.write_applied_and_save({"protected_dns": protected, "dhcp_dns": dns})
    return protected


def detect_firewall() -> dict:
    """Read current Windows firewall profile state."""
    state = {"profiles": {}, "raw": ""}
    if os.name != "nt":
        return state
    raw = _run(["netsh", "advfirewall", "show", "allprofiles"])
    state["raw"] = raw
    current = None
    for line in raw.splitlines():
        low = line.strip()
        if low.endswith("Profile Settings:"):
            current = low.split("Profile", 1)[0].strip().lower()
            state["profiles"][current] = {}
        elif current and ":" in low:
            k, v = low.split(":", 1)
            state["profiles"][current][k.strip().lower()] = v.strip()
    persist.write_applied_and_save({"firewall_detected": {k: v for k, v in state["profiles"].items()}})
    return state


def apply_http_https_vpn(tunnel_port: int = 51821) -> str:
    """Firewall mode that keeps HTTP/HTTPS outbound and protects them with the AES VPN."""
    import netlock

    state = netlock.load_state()
    state["tunnel_port"] = tunnel_port
    netlock.mode_http_https_vpn(state)
    # HTTP/HTTPS stay direct through 127.0.0.1:8080. VPN only monitors.
    netlock.add_allow_out("TCP", "80", "HTTP outbound")
    netlock.add_allow_out("TCP", "443", "HTTPS outbound")
    netlock.add_allow_out("UDP", "53", "DNS that established broadband")
    netlock.add_allow_out("TCP", "53", "DNS TCP")
    netlock.add_allow_out("TCP", "8080", "Local HTTP filter proxy")
    netlock.add_allow_out("TCP", "1080", "Private SOCKS monitor")
    persist.write_applied_and_save(
        {
            "firewall_mode": "http-https-vpn",
            "tunnel_port": tunnel_port,
            "http_https_vpn": True,
            "vpn_monitors_only": True,
            "http_proxy": "127.0.0.1:8080",
        }
    )
    return "HTTP/HTTPS on 127.0.0.1:8080; VPN monitors connectivity in parallel"


def auto_bind_and_save() -> dict:
    """Detect DHCP address/DNS, protect that DNS, bind the tunnel, save everything."""
    import vpn_server

    dhcp = read_dhcp()
    fw = detect_firewall()
    dns = dhcp.get("dns") or []
    protected = protect_dhcp_dns(dns)
    ip = dhcp.get("ip") or ""
    if ip.startswith("192.") or ip:
        vpn_state = vpn_server.load_state()
        vpn_state["bind"] = ip
        if dns:
            vpn_state["dns"] = dns
        vpn_server.save_state(vpn_state)
    rec = persist.write_applied_and_save(
        {
            "dhcp_ip": ip,
            "dhcp_gateway": dhcp.get("gateway"),
            "dhcp_dns": dns,
            "dhcp_adapter": dhcp.get("adapter"),
            "dhcp_enabled": dhcp.get("dhcp_enabled"),
            "dhcp_lease_server": dhcp.get("lease_server"),
            "bind": ip,
            "http_proxy": "127.0.0.1:8080",
            "vpn_monitors_only": True,
            "protected_dns": protected,
            "broadband_port": BROADBAND_PORT,
            "auto_bind": True,
            "firewall_profiles": list((fw.get("profiles") or {}).keys()),
        }
    )
    return rec
