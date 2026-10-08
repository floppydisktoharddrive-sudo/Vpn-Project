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
        adapter = info.get("adapter") or ""
        if adapter:
            for block in re.split(r"\r?\n(?=\S)", ipcfg):
                if adapter.lower() not in block.lower():
                    continue
                am = re.search(r"DHCP Server[^\d]*(\d+\.\d+\.\d+\.\d+)", block, re.I)
                if am:
                    info["lease_server"] = am.group(1)
                break
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
        low = str(d).strip().lower()
        if d not in seen and d not in {"0.0.0.0"} and not low.startswith("fec0:"):
            seen.add(d)
            dns.append(d)
    info["dns"] = dns
    return info


def _protected_dns_keep(server: str) -> bool:
    host = (server or "").strip().lower()
    if not host or host.startswith("fec0:"):
        return False
    return True


def _same_subnet(ip: str, gateway: str) -> bool:
    try:
        a = [int(x) for x in ip.split(".")]
        b = [int(x) for x in gateway.split(".")]
    except ValueError:
        return False
    return len(a) == 4 and len(b) == 4 and a[:3] == b[:3]


def _dns_answers(server: str, timeout: float = 1.5) -> bool:
    """Ask the server a short A query. A reply means this DNS is live."""
    import socket

    query = bytes.fromhex(
        "000101000001000000000000076578616d706c6503636f6d0000010001"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(512)
        return len(data) >= 12
    except OSError:
        return False
    finally:
        sock.close()


def verify_gateway_dns(gateway: str, servers: list[str]) -> dict:
    """Keep only DNS servers that answer, and require the gateway DNS to answer."""
    gw = (gateway or "").strip()
    ordered: list[str] = []
    for server in [gw] + list(servers or []):
        if not server or server in ordered or server in {"0.0.0.0", "1.0.0.0"}:
            continue
        if server.lower().startswith("fec0:"):
            continue
        ordered.append(server)
    live = [server for server in ordered if _dns_answers(server)]
    gateway_ok = bool(gw) and gw in live
    verified = [gw] + [server for server in live if server != gw] if gateway_ok else live
    return {"ok": gateway_ok, "gateway": gw, "dns": verified, "live": live}


def verify_dhcp_binding(info: dict) -> dict:
    """The leased address, gateway, and DHCP server must belong to the same binding."""
    ip = (info.get("ip") or "").strip()
    gateway = (info.get("gateway") or "").strip()
    lease = (info.get("lease_server") or "").strip()
    ok = bool(ip) and bool(gateway) and _same_subnet(ip, gateway)
    if lease and lease != gateway:
        ok = False
    if ip.startswith("192.") and gateway and _same_subnet(ip, gateway):
        ok = True
    return {
        "ok": ok,
        "ip": ip,
        "gateway": gateway,
        "lease_server": lease,
        "adapter": info.get("adapter") or "",
    }


def protect_dhcp_dns(dns: list[str]) -> list[str]:
    """Keep the DNS that established broadband off the kill/block lists."""
    import blocker

    data = blocker.load_filter()
    protected: list[str] = []
    for server in list(dns or []):
        if not _protected_dns_keep(server) or server in protected or server in {"0.0.0.0", "127.0.0.1"}:
            continue
        protected.append(server)
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


def clear_old_bind_config() -> None:
    """Drop the saved bind, DNS, and lease so a failed binding is not reused."""
    import blocker
    import vpn_server

    vpn = vpn_server.load_state()
    vpn["bind"] = ""
    vpn["dns"] = []
    vpn_server.save_state(vpn)
    data = blocker.load_filter()
    data["protected_dns"] = []
    blocker.save_filter(data)
    persist.write_applied_and_save(
        {
            "bind": "",
            "dhcp_ip": "",
            "dhcp_gateway": "",
            "dhcp_dns": [],
            "protected_dns": [],
            "dhcp_binding_ok": False,
            "dhcp_lease_server": "",
            "dhcp_adapter": "",
        }
    )


def auto_bind_and_save(retry: bool = True) -> dict:
    """Detect DHCP address/DNS, protect that DNS, bind the tunnel, save everything."""
    import vpn_server

    dhcp = read_dhcp()
    fw = detect_firewall()
    binding = verify_dhcp_binding(dhcp)
    checked = verify_gateway_dns(dhcp.get("gateway") or "", dhcp.get("dns") or [])
    dns = checked["dns"] if checked["ok"] and binding["ok"] else []
    protected = protect_dhcp_dns(dns)
    ip = dhcp.get("ip") or ""
    if binding["ok"] and ip:
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
            "dhcp_dns_verified": checked["ok"],
            "dhcp_binding_ok": binding["ok"],
            "dhcp_adapter": dhcp.get("adapter"),
            "dhcp_enabled": dhcp.get("dhcp_enabled"),
            "dhcp_lease_server": dhcp.get("lease_server"),
            "bind": ip if binding["ok"] else "",
            "http_proxy": "127.0.0.1:8080",
            "vpn_monitors_only": True,
            "protected_dns": protected,
            "broadband_port": BROADBAND_PORT,
            "auto_bind": True,
            "firewall_profiles": list((fw.get("profiles") or {}).keys()),
        }
    )
    if retry and not binding["ok"]:
        print("binding=fail — clearing old configurations and trying again")
        clear_old_bind_config()
        return auto_bind_and_save(retry=False)
    return rec
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
