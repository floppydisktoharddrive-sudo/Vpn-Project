# NetLock
# FREE TO USE LICENCE OPEN SOURCE CODE.
# THE FINAL VERSION WILL BE .EXE TO BE PURCHASED FOR $1.00 
# IF YOU CAN DONATE IT WILL BE GREATLY APPRECIATED.
# LINKS FOR DONATION:
#

Windows host toolkit: site blocker, firewall modes, AES-256-GCM tunnel.

## Images and C helper

- `netlock_net.c` + `netlock_net.py` — C networking helper and Python wrapper. Builds `libnetlock_net.so` (Linux) or `libnetlock_net.dll` (Windows). Prefers 192.x and port 8000. Named with a lib prefix so Python does not import the shared object instead of netlock_net.py.
- `netlock.pak` — packed program tree
- `netlock.img` — 8 MiB hard-disk image (PAK at LBA 1)
- `netlock.iso` — disc image with `README.TXT` and `NETLOCK.PAK`

```
make
make images
python netlock_net.py
```

Windows DLL: `gcc -O2 -shared -o libnetlock_net.dll netlock_net.c -lws2_32 -liphlpapi`

## Run

1. Install Python 3 and check **Add python.exe to PATH**.
2. Right-click `start.bat` → **Run as administrator** (or double-click; it self-elevates).
3. Use the GUI tabs.

## Tabs

- **Site blocker** — writes a marked block in the hosts file.
- **Firewall** — LOCK / VPN ON / INBOUND-ONLY / OFF via Windows Firewall.
- **VPN server** — built-in AES-256-GCM listener + SOCKS5 on `127.0.0.1:1080`.

## AES tunnel

Does **not** use WireGuard and does not need placeholder keys.

- Key: `vpn_data/aes256.key` (32 random bytes)
- Encrypted TCP: `127.0.0.1:51821`
- Local SOCKS5: `127.0.0.1:1080`

Point apps at that SOCKS port to send traffic through this process.

Needs the Python package `cryptography`. If it is missing, Start tries `pip install cryptography`.

This is not a full-system TUN adapter. `bin/*/wintun.dll` is included for a future adapter path; the running server is the AES/SOCKS engine.

## CLI

```
python blocker.py
python blocker.py --unblock
python netlock.py status|lock|vpn|inbound-only|off
python vpn_server.py generate|start|stop|status
```

## Boot reset

`start.bat` first resets proxy/DNS to default, prints local IPv4 + gateway, and probes the Internet. If the probe fails it renews DHCP and resets the TCP/IP catalog, then the GUI starts the VPN+SQL HTTP/HTTPS shield bound to those LAN addresses.

## Launch posture

VPN server starts OFF. Boot installs the bundled Wintun kernel driver, detects PdaNet or modem/router, assigns NetLockTUN an address on that 192.x LAN, sets the browser proxy to 127.0.0.1:8080, and opens a temporary local proxy for each open desktop app (closed when the app exits). Press Start VPN server to turn encryption on.
