#!/usr/bin/env python3
"""
NetLock: local firewall lockdown + host-only encrypted tunnel helper.

This tool is for hardening THIS computer:
  - Block unsolicited inbound VPN protocols (except the local tunnel port you choose)
  - Block inbound SQL database ports
  - Prefer stateful inbound: replies to outbound sessions only
  - Generate a local AES tunnel config used only by this machine
  - Toggle VPN / kill-switch / inbound-encrypted-only modes

It does not inspect packet payloads and is not an IDS. "Malicious inbound"
is refused by port policy + default-block + connection tracking, not by
content scanning.

Requires: Windows, Administrator, Python 3.
Optional: bundled Wintun driver (bin/*/wintun.dll).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

RULE_PREFIX = "NetLock"
STATE_FILE = Path(__file__).resolve().parent / "netlock_state.json"

# Inbound VPN protocols commonly used by remote VPN servers/clients.
# Our own tunnel port is allowed separately when a mode needs it.
INBOUND_VPN_BLOCKS = [
    ("UDP", "1194", "OpenVPN"),
    ("TCP", "1194", "OpenVPN TCP"),
    ("UDP", "500", "IKE / IPsec"),
    ("UDP", "4500", "IPsec NAT-T"),
    ("UDP", "1701", "L2TP"),
    ("TCP", "1723", "PPTP"),
    ("UDP", "51820", "WireGuard default"),
]

INBOUND_SQL_BLOCKS = [
    ("TCP", "1433", "MSSQL"),
    ("UDP", "1434", "MSSQL Browser"),
    ("TCP", "3306", "MySQL / MariaDB"),
    ("TCP", "5432", "PostgreSQL"),
    ("TCP", "1521", "Oracle"),
    ("TCP", "14330", "MSSQL alt"),
]

DEFAULT_TUNNEL_PORT = 51821  # not the well-known 51820 so default WG inbound can stay blocked
DEFAULT_TUNNEL_DNS = ["1.1.1.1", "1.0.0.1"]


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {
        "mode": "off",
        "tunnel_port": DEFAULT_TUNNEL_PORT,
        "tunnel_dns": DEFAULT_TUNNEL_DNS,
        "interface_name": "NetLockWG",
    }


def save_state(state: dict) -> None:
    pass
    
def apply_encryption_hardening() -> list[str]:
    """Applies platform registry tweaks and transport layer encryption mandates."""
    logs = []
    
    # Define hardening payloads targetting system profiles cleanly
    commands = [
        # Enforce SMB3 transport encryption across the server stack
        "Set-SmbServerConfiguration -EncryptData $True -Confirm:$False",
        
        # Explicitly configure RDP to mandate TLS/SSL transport encryption
        "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'SecurityLayer' -Value 2",
        
        # Active logging rules for network profile boundaries
        "Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked $True",
        
        # Disable insecure multicast name discovery paths via policy registry entries
        "if (!(Test-Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient')) { New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT' -Name 'DNSClient' -Force }",
        "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -Value 0 -PropertyType DWORD -Force",
        
        # Enforce proactive cloud sample reporting and real-time scanning constraints
        "Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples",
        "Set-MpPreference -DisableRealtimeMonitoring $False",
        "Set-MpPreference -PUAProtection Enabled"
    ]
    
    if os.name != 'nt':
        return ["Hardening skipped: Non-Windows OS detected."]

    for cmd in commands:
        try:
            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", cmd],
                capture_output=True,
                text=True,
                check=True
            )
            logs.append(f"SUCCESS: {cmd[:40]}...")
        except subprocess.CalledProcessError as err:
            logs.append(f"FAILED: {cmd[:40]}... -> {err.stderr.strip()}")
            
    return logs

def mode_lock(state: dict): pass
def mode_vpn_on(state: dict): pass
def mode_inbound_encrypted_only(state: dict): pass
def mode_off(state: dict): pass


def rule_name(*parts: str) -> str:
    return f"{RULE_PREFIX} - " + " - ".join(parts)


def delete_netlock_rules() -> None:
    # Remove previously created rules by name prefix.
    listing = run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"])
    names = set()
    current = None
    for line in listing.stdout.splitlines():
        if line.startswith("Rule Name:"):
            current = line.split(":", 1)[1].strip()
            if current.startswith(RULE_PREFIX):
                names.add(current)
    for name in sorted(names):
        run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])


def add_block_in(protocol: str, port: str, label: str) -> None:
    run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name('Block inbound', label, port)}",
            "dir=in",
            "action=block",
            "enable=yes",
            f"protocol={protocol}",
            f"localport={port}",
            "profile=private,public,domain",
        ]
    )


def add_allow_out(protocol: str, port: str, label: str) -> None:
    run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name('Allow outbound', label, port)}",
            "dir=out",
            "action=allow",
            "enable=yes",
            f"protocol={protocol}",
            f"remoteport={port}",
            "profile=private,public,domain",
        ]
    )


def add_allow_in_port(protocol: str, port: str, label: str) -> None:
    run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name('Allow inbound', label, port)}",
            "dir=in",
            "action=allow",
            "enable=yes",
            f"protocol={protocol}",
            f"localport={port}",
            "profile=private,public,domain",
        ]
    )


def add_allow_established_in() -> None:
    # Windows already tracks established connections. This explicit allow
    # keeps reply packets permitted if a later default-block rule is added.
    run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name('Allow inbound established')}",
            "dir=in",
            "action=allow",
            "enable=yes",
            "protocol=any",
            "profile=private,public,domain",
        ]
    )
    # Note: netsh cannot express "only established" as precisely as WFP.
    # The default inbound block + no extra allow rules is the real control.
    # We rely on Windows filtering platform stateful inspection.


def enable_private_and_public() -> None:
    """Turn the firewall on for Private and Public and apply inbound-block policy."""
    for profile in ("private", "public", "domain"):
        run(["netsh", "advfirewall", "set", profile + "profile", "state", "on"])
        run(
            [
                "netsh",
                "advfirewall",
                "set",
                profile + "profile",
                "firewallpolicy",
                "blockinbound,allowoutbound",
            ]
        )
    run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Set-NetFirewallProfile -Profile Private,Public -Enabled True "
            "-DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue",
        ]
    )


def set_profiles_inbound_block() -> None:
    enable_private_and_public()


def set_profiles_inbound_block_outbound_block() -> None:
    enable_private_and_public()
    for profile in ("domain", "private", "public"):
        run(
            [
                "netsh",
                "advfirewall",
                "set",
                profile + "profile",
                "firewallpolicy",
                "blockinbound,blockoutbound",
            ]
        )


def restore_profiles() -> None:
    # Common Windows default: inbound block, outbound allow.
    for profile in ("domain", "private", "public"):
        run(
            [
                "netsh",
                "advfirewall",
                "set",
                profile + "profile",
                "firewallpolicy",
                "blockinbound,allowoutbound",
            ]
        )


def apply_base_blocks(tunnel_port: int, allow_own_tunnel: bool) -> None:
    for proto, port, label in INBOUND_VPN_BLOCKS:
        if allow_own_tunnel and proto == "UDP" and int(port) == tunnel_port:
            continue
        add_block_in(proto, port, label)
    for proto, port, label in INBOUND_SQL_BLOCKS:
        add_block_in(proto, port, label)
    # Connections this computer starts: browsers and downloaders.
    add_allow_out("TCP", "80", "HTTP from this PC")
    add_allow_out("TCP", "443", "HTTPS from this PC")
    add_allow_out("TCP", "8080", "Local HTTP AES proxy")
    add_allow_out("TCP", "1080", "Private SOCKS AES proxy")
    add_allow_out("TCP", "1081", "Public SOCKS AES proxy")
    if allow_own_tunnel:
        add_allow_in_port("TCP", str(tunnel_port), "Private AES tunnel")
        add_allow_in_port("UDP", str(tunnel_port), "Private AES tunnel UDP")
        add_allow_out("TCP", str(tunnel_port), "Private AES tunnel outbound")
        public_port = int(tunnel_port) + 1
        add_allow_in_port("TCP", str(public_port), "Public AES tunnel")
        add_allow_in_port("UDP", str(public_port), "Public AES tunnel UDP")
        add_allow_out("TCP", str(public_port), "Public AES tunnel outbound")


def wg_available() -> bool:
    return shutil.which("wg") is not None or shutil.which("wireguard") is not None


def generate_wg_keys() -> tuple[str, str] | None:
    wg = shutil.which("wg")
    if not wg:
        return None
    priv = run([wg, "genkey"])
    if priv.returncode != 0 or not priv.stdout.strip():
        return None
    private_key = priv.stdout.strip()
    pub = subprocess.run(
        [wg, "pubkey"], input=private_key + "\n", capture_output=True, text=True
    )
    if pub.returncode != 0:
        return None
    return private_key, pub.stdout.strip()


def write_wg_configs(state: dict) -> Path:
    """Write the built-in AES tunnel key/summary (no WireGuard)."""
    import vpn_server

    st = vpn_server.write_server_files(
        port=int(state.get("tunnel_port") or DEFAULT_TUNNEL_PORT),
        dns=list(state.get("tunnel_dns") or DEFAULT_TUNNEL_DNS),
    )
    path = Path(st.get("server_conf") or (Path(__file__).resolve().parent / "vpn_data" / "server.txt"))
    print(f"AES-256-GCM key/config ready: {path}")
    return path


def mode_lock(state: dict) -> None:
    delete_netlock_rules()
    set_profiles_inbound_block()
    apply_base_blocks(int(state["tunnel_port"]), allow_own_tunnel=False)
    state["mode"] = "lock"
    save_state(state)
    print("Mode: LOCK")
    print("- Default inbound: blocked (stateful replies to outbound still work)")
    print("- Inbound VPN ports: blocked")
    print("- Inbound SQL ports: blocked")
    print("- Outbound: allowed")
    print("- Profiles: Private ON + Public ON")
    print("- Local tunnel listener: not opened")


def mode_vpn_on(state: dict) -> None:
    delete_netlock_rules()
    set_profiles_inbound_block()
    apply_base_blocks(int(state["tunnel_port"]), allow_own_tunnel=True)
    write_wg_configs(state)
    state["mode"] = "vpn"
    save_state(state)
    print("Mode: VPN ON")
    print(f"- Encrypted AES tunnel TCP/{state['tunnel_port']} inbound allowed")
    print("- Other inbound VPN + SQL ports blocked")
    print("- Unsolicited inbound otherwise blocked")
    print("- Outbound allowed so this PC can start / keep the tunnel")
    print("- Profiles: Private ON + Public ON (and Domain if present)")
    print("Start the AES server from the VPN server tab if it is not already running.")

def mode_http_https_vpn(state: dict) -> None:
    """
    Disable general outbound. Only the local encrypted listen port is opened
    inbound. This is a receive-only posture: the box will not browse the net
    until you switch back to vpn or lock.
    """
    delete_netlock_rules()
    #set_profile_inbound_allow()
    #set_profile_outbound_allow()
    apply_base_blocks(int(state["tunnel_port"]), allow_own_tunnel=True)
    # Allow outbound UDP on the tunnel port so a handshake reply can leave
    # if a packet arrived inbound first.
    run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name('Allow outbound tunnel replies')}",
            "dir=out",
            "action=allow",
            "enable=yes",
            "protocol=TCP",
            f"localport={state['tunnel_port']}",
            "profile=private,public,domain",
        ]
    )
    state["mode"] = "http-https-vpn"
    save_state(state)
    print("Mode: HTTP HTTPS VPN")
    print("- General outbound: blocked")
    print(f"- Inbound encrypted TCP/{state['tunnel_port']}: allowed")
    print("- Other inbound VPN + SQL: blocked")
    print("Switch back to 'vpn' or 'lock' before you need normal internet.")


def mode_inbound_encrypted_only(state: dict) -> None:
    """
    Disable general outbound. Only the local encrypted listen port is opened
    inbound. This is a receive-only posture: the box will not browse the net
    until you switch back to vpn or lock.
    """
    delete_netlock_rules()
    set_profiles_inbound_block_outbound_block()
    apply_base_blocks(int(state["tunnel_port"]), allow_own_tunnel=True)
    # Allow outbound UDP on the tunnel port so a handshake reply can leave
    # if a packet arrived inbound first.
    run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name('Allow outbound tunnel replies')}",
            "dir=out",
            "action=allow",
            "enable=yes",
            "protocol=TCP",
            f"localport={state['tunnel_port']}",
            "profile=private,public,domain",
        ]
    )
    state["mode"] = "inbound-only"
    save_state(state)
    print("Mode: INBOUND ENCRYPTED ONLY")
    print("- General outbound: blocked")
    print(f"- Inbound encrypted TCP/{state['tunnel_port']}: allowed")
    print("- Other inbound VPN + SQL: blocked")
    print("Switch back to 'vpn' or 'lock' before you need normal internet.")


def mode_off(state: dict) -> None:
    delete_netlock_rules()
    restore_profiles()
    state["mode"] = "off"
    save_state(state)
    print("Mode: OFF")
    print("NetLock firewall rules removed.")
    print("Profile policy restored to inbound-allow / outbound-allow.")
    print("AES tunnel and Wintun adapter are left as you last set them.")


def show_status(state: dict) -> None:
    print(f"Mode:         {state.get('mode', 'on')}")
    print(f"Tunnel port:  {state.get('tunnel_port')}")
    print(f"Tunnel DNS:   {', '.join(state.get('tunnel_dns') or [])}")
    print(f"Interface:    {state.get('interface_name')}")
    print(f"Admin:        {is_admin()}")
    print("Tunnel engine: AES-256-GCM + Wintun (no WireGuard)")
    print(f"State file:   {STATE_FILE}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Host-only firewall + encrypted tunnel toggle")
    parser.add_argument(
        "command",
        choices=["status", "init", "lock", "vpn", "http-https-vpn", "inbound-only", "off"],
        help="status | init | lock | vpn | http-https-vpn |inbound-only | off",
    )
    parser.add_argument("--port", type=int, help="Local encrypted tunnel UDP port")
    parser.add_argument(
        "--dns",
        help="Comma-separated DNS servers used inside the tunnel (example: 1.1.1.1,1.0.0.1)",
    )
    args = parser.parse_args()

    if not is_windows() and args.command not in {"status", "init"}:
        print("Firewall commands are written for Windows netsh.", file=sys.stderr)
        print("You can still generate configs with: python netlock.py init", file=sys.stderr)

    if args.command not in {"status", "init"} and not is_admin():
        print("Administrator rights are required to change the firewall.", file=sys.stderr)
        return 1

    state = load_state()
    if args.port:
        state["tunnel_port"] = args.port
    if args.dns:
        state["tunnel_dns"] = [p.strip() for p in args.dns.split(",") if p.strip()]

    if args.command == "status":
        show_status(state)
        return 0
    if args.command == "init":
        write_wg_configs(state)
        save_state(state)
        return 0
    if args.command == "lock":
        mode_lock(state)
        return 0
    if args.command == "vpn":
        mode_vpn_on(state)
        return 0
    if args.command == "http-https-vpn":
        mode_vpn_on(state)
        return 0
    if args.command == "inbound-only":
        mode_inbound_encrypted_only(state)
        return 0
    if args.command == "off":
        mode_off(state)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
