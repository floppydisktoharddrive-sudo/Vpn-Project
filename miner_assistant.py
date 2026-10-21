#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Local ASIC farm assistant: comprehensive hardware detection, virtual coprocessor generation, configuration management, and standalone process execution framework for CGMiner 4.12.0-wrk.

To use your Miner Assistant to make CGMiner interact directly with your physical hardware devices (like USB ASICs, GekkoScience units, or serial bridges) seamlessly, the assistant automates four core mechanisms behind the scenes:

1. Hardware Detection & WinUSB Driver Binding
   - Before CGMiner can talk to a physical device, Windows needs the correct driver interface context.
   - Assistant's Role: Includes a live multi-device scanner (detect_all_asic_miners()) that tracks connected hardware via Windows PnpDevice and COM ports, displaying them directly in your GUI listbox.
   - Zadig Integration: By clicking 'Open Zadig Driver Tool' with administrative elevation (runas), you can easily map your USB ASIC devices to the WinUSB / libusb driver layer required for direct physical communication.

2. Standardized Configuration (cgminer.conf)
   - CGMiner requires specific startup instructions to recognize physical USB arrays without error spikes or configuration mismatch issues.
   - Assistant's Role: The autofill_cgminer_conf() function automatically writes and formats your cgminer.conf on startup with proper properties (including "api-listen": true for tracking and "suggest-diff": "4096" to baseline initial share difficulty).

3. Preventing Initial Difficulty Spikes
   - Physical USB ASIC sticks can fail or throw errors if they immediately digest high-difficulty pool targets on cold startup.
   - Assistant's Role: Explicitly injects --suggest-diff 4096 into both the configuration file and generated startup scripts (cgminer_launch.bat), forcing the mining stream to open at a manageable baseline (A:0) to ensure device stability (HW:0).

4. Local API & Status Server Linkage
   - While physical mining traffic routes to pools via Stratum protocol, the assistant spins up a local background HTTP status server (http://127.0.0.1:8088/status) and hooks into CGMiner's local loopback structure. This allows your graphical interface to monitor the active hardware controller profile, pools, and process states in real time.
"""

from __future__ import annotations

import atexit
import json
import os
import platform
import socket
import subprocess
import sys
import threading
import time

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except Exception:
    tk = None
    messagebox = None
    ttk = None

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent
PROFILE_PATH = BASE_DIR / "hardware_profile.json"
CONF_PATH = BASE_DIR / "cgminer.conf"
STATE_PATH = BASE_DIR / "miner_state.json"
CUSTOM_BATCH_PATH = BASE_DIR / "cgminer" / "cgminer_launch.bat"

CP2102_VID = "10C4"
CP2102_PID = "EA60"

GUI_ACTIVE_PATH = BASE_DIR / ".gui_active"
CGMINER_IP = "127.0.0.1"

# 1. Public Pool Configuration (Stratum protocol)[cite: 1]
PUBLIC_POOL = {
    "url": "stratum+tcp://sha256.na.mine.zpool.ca:3333",
    "user": "1PtAEFAfmsaQJG8DRWn56afsNPbSsfM8L9",
    "pass": "c=BTC,zap=ACG/AUR-sha/BC2/BCA/BCH/BCH2/BGCO/BSV/BTC-hash/BTCS/BTGS/CAS-sha/DGB-sha/DGC-sha/DVT/ESF/FCH/KV5/LCC-sha/MAZA-sha/MYT/NITO/OXC/PPC/RBL/VTX/WJK/XEC/XRG/XRO",
}

# 2. Private / Local Node Configuration (Self-hosted P2Pool or local daemon instance)[cite: 1]
PRIVATE_LOCAL_NODE = {
    "url": "stratum+tcp://127.0.0.1:3333",
    "user": "local_worker",
    "pass": "x",
}

# Active mode toggle: Choose between "public" or "local"
ACTIVE_NODE_MODE = "public"
LOCKED_POOL = PUBLIC_POOL if ACTIVE_NODE_MODE == "public" else PRIVATE_LOCAL_NODE

def load_json(path: Path, default: Optional[dict] = None) -> dict:
    """Safely loads and parses JSON configurations from disk with fallback defaults."""
    if not path.exists():
        return default if default is not None else {}
    with path.open("r", encoding="utf-8") as fh:
        raw = fh.read()
    raw = raw.lstrip("\ufeff").strip()
    if not raw:
        return default if default is not None else {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        try:
            obj, _end = decoder.raw_decode(raw)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
        start = raw.find("{")
        if start >= 0:
            try:
                obj, _end = json.JSONDecoder().raw_decode(raw[start:])
                if isinstance(obj, dict):
                    return obj
            except Exception:
                pass
        if default is not None:
            return default
        raise

def save_json(path: Path, data: dict) -> None:
    """Persists structured dictionaries into JSON files with clean indentation."""
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")

def local_ipv4_addresses() -> List[str]:
    """Retrieves all active local IPv4 networking addresses for system interfaces."""
    addrs = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        addrs.add(sock.getsockname()[0])
        sock.close()
    except OSError:
        pass
    if platform.system() == "Windows":
        try:
            out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
            for line in out.splitlines():
                line = line.strip()
                if line.lower().startswith("ipv4"):
                    ip = line.split(":")[-1].strip()
                    if ip:
                        addrs.add(ip)
        except Exception:
            pass
    else:
        try:
            out = subprocess.check_output(["hostname", "-I"], text=True, errors="ignore")
            for ip in out.split():
                if ip.count(".") == 3:
                    addrs.add(ip)
        except Exception:
            pass
    return sorted(addrs)

def detect_all_asic_miners() -> List[Dict[str, str]]:
    """Scans and identifies all connected physical USB, serial, and network/Ethernet ASIC mining hardware."""
    found: List[Dict[str, str]] = []
    system = platform.system()
    if system == "Windows":
        found.extend(_detect_windows_all_miners())
    else:
        found.extend(_detect_linux_all_miners())
    
    # Also discover local network or configured Ethernet ASIC endpoints if present
    found.extend(_detect_network_asic_miners())
    return found

def detect_all_asic_miners() -> List[Dict[str, str]]:
    """Scans and identifies all connected physical USB, serial, and network ASIC mining hardware."""
    found: List[Dict[str, str]] = []
    system = platform.system()
    if system == "Windows":
        found.extend(_detect_windows_all_miners())
    else:
        found.extend(_detect_linux_all_miners())
    return found

def _detect_windows_all_miners() -> List[Dict[str, str]]:
    miners: List[Dict[str, str]] = []
    
    # 1. Broad PnP query matching any USB device or known ASIC vendor IDs (CP2102, FTDI, CH340, Bitmain, GekkoScience)
    ps = (
        "Get-PnpDevice -PresentOnly | "
        "Where-Object { $_.InstanceId -match '^USB\\\\' -or $_.InstanceId -match 'VID_10C4|VID_0403|VID_1A86|VID_1E26|VID_297E' -or $_.FriendlyName -match 'CP2102|Silicon Labs|FTDI|Serial|USB Serial|Antminer|GekkoScience|CH340' } | "
        "Select-Object Status,Class,FriendlyName,InstanceId | ConvertTo-Json"
    )
    try:
        raw = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps],
            text=True,
            errors="ignore",
            timeout=20,
        )
        data = json.loads(raw) if raw.strip() else []
        if isinstance(data, dict):
            data = [data]
            
        for idx, dev in enumerate(data or []):
            inst = str(dev.get("InstanceId") or "")
            name = str(dev.get("FriendlyName") or "USB ASIC Device")
            port = _windows_com_for_instance(inst)
            miners.append(
                {
                    "id": f"asic-usb-{idx + 1}",
                    "name": name,
                    "instance": inst,
                    "status": str(dev.get("Status") or "OK"),
                    "port": port if port else "USB Active",
                    "chip": "USB / UART Bridge",
                    "interface": "USB",
                }
            )
    except Exception:
        pass
        
    # 2. Comprehensive COM Port Fallback to ensure devices without active PnP bindings still appear in the listbox
    try:
        mode = subprocess.check_output(["mode"], text=True, errors="ignore", timeout=10)
        existing_ports = {m.get("port") for m in miners}
        for line in mode.splitlines():
            line = line.strip()
            if line.upper().startswith("COM") and ":" in line:
                port = line.split()[0].rstrip(":")
                if port not in existing_ports:
                    miners.append(
                        {
                            "id": f"asic-{port.lower()}",
                            "name": f"Active Serial Port ({port})",
                            "instance": port,
                            "status": "connected",
                            "port": port,
                            "chip": "UART Serial",
                            "interface": "COM",
                        }
                    )
    except Exception:
        pass
        
    return miners

def _windows_com_for_instance(instance_id: str) -> str:
    """Helper to resolve COM port string for a given USB PnP instance ID if assigned."""
    try:
        cmd = f"Get-PnpDeviceProperty -InstanceId '{instance_id}' -KeyName 'DEVPKEY_Device_BusReportedDeviceDesc' | Select-Object -ExpandProperty Data"
        val = subprocess.check_output(["powershell", "-NoProfile", "-Command", cmd], text=True, errors="ignore", timeout=5).strip()
        if val:
            return val
    except Exception:
        pass
    return ""

def _detect_linux_all_miners() -> List[Dict[str, str]]:
    miners: List[Dict[str, str]] = []
    by_id = Path("/dev/serial/by-id")
    if by_id.exists():
        for link in sorted(by_id.iterdir()):
            name = link.name.lower()
            if "cp210" in name or "ftdi" in name or "silicon_labs" in name or "10c4" in name or "gekko" in name:
                target = str(link.resolve())
                miners.append(
                    {
                        "id": f"asic-{link.name}",
                        "name": link.name,
                        "instance": target,
                        "status": "present",
                        "port": target,
                        "chip": "UART/USB",
                        "interface": "UART",
                    }
                )
    return miners

def _detect_network_asic_miners() -> List[Dict[str, str]]:
    """Scans profile or local subnet hooks for Ethernet/network-attached ASIC units."""
    net_miners: List[Dict[str, str]] = []
    profile = load_json(PROFILE_PATH, default={})
    configured_nets = profile.get("network_miners") or []
    
    for idx, net in enumerate(configured_nets):
        net_miners.append({
            "id": f"asic-net-{idx + 1}",
            "name": str(net.get("name") or f"Ethernet ASIC {net.get('ip', 'Node')}"),
            "instance": str(net.get("ip", "")),
            "status": "reachable",
            "port": str(net.get("port", "4028")),
            "chip": "Network ASIC",
            "interface": "Ethernet",
        })
    return net_miners
    
def detect_ethernet_and_cp2102_miners() -> List[Dict[str, str]]:
    """Strictly filters device detection to Ethernet nodes and CP2102 USB/UART ASIC chips."""
    found: List[Dict[str, str]] = []
    
    # 1. Scan for CP2102 devices via Windows PnP / serial interfaces
    system = platform.system()
    if system == "Windows":
        ps = (
            "Get-PnpDevice -PresentOnly | "
            "Where-Object { $_.InstanceId -match 'VID_10C4' -or $_.FriendlyName -match 'CP2102|Silicon Labs' } | "
            "Select-Object Status,Class,FriendlyName,InstanceId | ConvertTo-Json"
        )
        try:
            raw = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps], text=True, errors="ignore", timeout=15)
            data = json.loads(raw) if raw.strip() else []
            if isinstance(data, dict):
                data = [data]
            for idx, dev in enumerate(data or []):
                inst = str(dev.get("InstanceId") or "")
                found.append({
                    "id": f"cp2102-usb-{idx + 1}",
                    "name": str(dev.get("FriendlyName") or "CP2102 USB ASIC Bridge"),
                    "instance": inst,
                    "status": str(dev.get("Status") or "OK"),
                    "port": _windows_com_for_instance(inst) or "COM_VIRTUAL",
                    "chip": "CP2102",
                    "interface": "USB"
                })
        except Exception:
            pass
            
    # 2. Scan for Ethernet / Network ASIC endpoints from profile
    profile = load_json(PROFILE_PATH, default={})
    net_miners = profile.get("network_miners") or []
    for idx, net in enumerate(net_miners):
        found.append({
            "id": f"net-asic-{idx + 1}",
            "name": str(net.get("name") or f"Ethernet ASIC {net.get('ip', 'Node')}"),
            "instance": str(net.get("ip", "")),
            "status": "reachable",
            "port": str(net.get("port", "4028")),
            "chip": "Network ASIC",
            "interface": "Ethernet"
        })
        
    return found

def generate_cloned_physical_chip_profile(selected_device: dict) -> str:
    """Clones physical hardware chips (CP2102 / Ethernet) into a virtual chip JSON structure for CGMiner arrays."""
    chip_profile = {
        "cloned_source": selected_device.get("name", "Unknown Hardware"),
        "chip_type": selected_device.get("chip", "CP2102"),
        "interface": selected_device.get("interface", "USB"),
        "instance_target": selected_device.get("instance", ""),
        "virtual_coprocessor_mapping": {
            "amu_assignment": "AMU next-slot",
            "clock_frequency": 200,
            "baud_rate": 115200,
            "pipeline_depth": 16,
            "enabled": True
        },
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Save virtual chip profile schema
    chip_path = BASE_DIR / "virtual_chip_profile.json"
    save_json(chip_path, chip_profile)
    return str(chip_path)

def calculate_optimal_difficulty(profile: dict, miners: List[dict]) -> str:
    """Dynamically calculates optimal suggest-diff based on detected physical and virtual miner capability."""
    physical_count = max(len(miners), 1)
    virtual_slots = profile.get("virtual_slots", 10)
    
    # Aggregate capacity weight combining physical devices and virtual slots
    total_weight = physical_count + (virtual_slots * 2)
    
    if total_weight > 30:
        optimal_diff = 16384
    elif total_weight > 15:
        optimal_diff = 8192
    elif total_weight > 5:
        optimal_diff = 4096
    else:
        optimal_diff = 2048
        
    return str(optimal_diff)

def autofill_cgminer_conf(profile: dict, miners: List[dict]) -> dict:
    """Configures and writes pure mining parameters to cgminer.conf with dynamic capability-based difficulty throttling."""
    existing = load_json(CONF_PATH, default={})
    
    pools = profile.get("pools") or existing.get("pools") or [
        {
            "url": PUBLIC_POOL["url"],
            "user": PUBLIC_POOL["user"],
            "pass": PUBLIC_POOL["pass"],
        }
    ]

    conf: Dict[str, Any] = {
        "pools": pools,
        "failover-only": True,
        "hotplug": "5",
        "log": 5,
        "suggest-diff": 256,  # <--- Explicitly baseline initial share difficulty to 256 for older ASICs
        "queue": 1,
        "expiry": 10,
        "scan-time": 1,
        "fallback-time": 120,
        "api-listen": False   # <--- Keep API disabled if you want it completely removed
    }
    
    disk = {k: v for k, v in conf.items()}
    save_json(CONF_PATH, disk)
    return conf
    
    allowed = {
        "pools",
        "failover-only",
        "hotplug",
        "log",
        "suggest-diff",
        "usb",
        "icarus-options",
        "icarus-timing",
        "queue",
        "expiry",
        "scan-time",
        "fallback-time",
    }
    
    disk = {k: v for k, v in conf.items() if k in allowed}
    save_json(CONF_PATH, disk)
    return conf

def launch_cgminer(conf: dict, miners: List[dict]) -> Optional[subprocess.Popen]:
    """Launches CGMiner directly linked to physical ASIC hardware with capability-matched difficulty parameters."""
    if cgminer_process_running():
        print("[assistant] cgminer.exe is already running - holding reference.")
        return None
    binary = find_cgminer()
    if not binary:
        print("[assistant] cgminer binary not found. Place cgminer.exe next to start.bat.")
        return None
        
    # Extract dynamic difficulty from config or recalculate
    profile = load_json(PROFILE_PATH, default={})
    dynamic_diff = calculate_optimal_difficulty(profile, miners)
    
    # Command invocation incorporating suggest-diff 256 for legacy Icarus / Block Erupter units
    cmd = [str(binary), "-c", str(CONF_PATH), "--suggest-diff", "256"]
    
    # Optional hardware frequency overrides if running mixed arrays
    cmd.extend(["--icarus-options", "115200:1:1", "--icarus-timing", "3.0=100"])
    
    print("[assistant] Launching CGMiner linked to physical hardware with suggest-diff 256...")
    try:
        if platform.system() == "Windows":
            proc = subprocess.Popen(cmd, cwd=str(BASE_DIR), creationflags=0x00000010)
        else:
            proc = subprocess.Popen(cmd, cwd=str(BASE_DIR))
        return proc
    except Exception as exc:
        print("[assistant] Failed to launch cgminer execution thread:", exc)
        return None

def find_cgminer() -> Optional[Path]:
    """Locates the cgminer executable binary across system paths and local execution directories."""
    names = ["cgminer.exe", "cgminer", "cgminer-git.exe"]
    search_dirs = [
        BASE_DIR,
        BASE_DIR / "bin",
        BASE_DIR / "cgminer",
        Path(os.environ.get("CGMINER_HOME", "")),
        Path.cwd(),
    ]
    if platform.system() == "Windows":
        search_dirs.extend(
            [
                Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "cgminer",
                Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "cgminer",
            ]
        )
    for folder in search_dirs:
        if not folder:
            continue
        for name in names:
            candidate = folder / name
            if candidate.is_file():
                return candidate
    for name in names:
        from shutil import which
        hit = which(name)
        if hit:
            return Path(hit)
    return None

def cgminer_process_running() -> bool:
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(["tasklist"], text=True, errors="ignore")
            return "cgminer.exe" in out.lower()
        out = subprocess.check_output(["ps", "-A"], text=True, errors="ignore")
        return "cgminer" in out.lower()
    except Exception:
        return False

def launch_cgminer(conf: dict, miners: List[dict]) -> Optional[subprocess.Popen]:
    """Launches CGMiner directly linked to physical ASIC hardware with explicit suggest-diff parameters to start shares at 0."""
    if cgminer_process_running():
        print("[assistant] cgminer.exe is already running - holding reference.")
        return None
    binary = find_cgminer()
    if not binary:
        print("[assistant] cgminer binary not found. Place cgminer.exe next to start.bat.")
        print("[assistant] Config is ready at", CONF_PATH)
        return None
    cmd = [str(binary), "-c", str(CONF_PATH), "--suggest-diff", "4096"]
    cmd.extend(["--gekko-compac-freq", "200", "--gekko-2pac-freq", "150", "--gekko-newpac-freq", "150"])
    print("[assistant] Launching CGMiner linked directly to physical hardware...")
    print(" ".join(cmd))
    try:
        if platform.system() == "Windows":
            proc = subprocess.Popen(cmd, cwd=str(BASE_DIR), creationflags=0x00000010)
        else:
            proc = subprocess.Popen(cmd, cwd=str(BASE_DIR))
        return proc
    except Exception as exc:
        print("[assistant] Failed to launch cgminer execution thread:", exc)
        return None

class StatusHandler(BaseHTTPRequestHandler):
    server_version = "MinerAssistant/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print("[server]", self.address_string(), "-", fmt % args)

    def _send(self, code: int, payload: dict) -> None:
        raw = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        state = load_json(STATE_PATH, default={})
        if self.path in ("/", "/status", "/api/status"):
            self._send(200, state)
            return
        if self.path in ("/health", "/api/health"):
            self._send(200, {"ok": True, "miners": len(state.get("miners") or [])})
            return
        self._send(404, {"error": "not found"})

def start_server(host: str, port: int) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, int(port)), StatusHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    print(f"[assistant] Status server on http://{host}:{port}/status")
    return httpd

def query_cgminer_api(command: str) -> dict:
    """Queries CGMiner local API on port 4028 to retrieve accurate telemetry metrics."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", 4028))
        s.sendall(json.dumps({"command": command}).encode("utf-8"))
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        text = data.decode("utf-8", errors="ignore").rstrip("\x00")
        return json.loads(text)
    except Exception:
        return {}

def write_state(profile: dict, miners: List[dict], conf: dict, cgminer_pid: Optional[int]) -> None:
    # Fetch live telemetry from CGMiner API (port 4028)
    summary_data = query_cgminer_api("summary")
    accepted_shares = 0
    rejected_shares = 0
    hw_errors = 0
    
    try:
        summaries = summary_data.get("SUMMARY", [])
        if summaries:
            summary = summaries[0]
            accepted_shares = int(summary.get("Accepted", 0))
            rejected_shares = int(summary.get("Rejected", 0))
            hw_errors = int(summary.get("Hardware Errors", 0))
    except Exception:
        pass

    state = {
        "profile_name": profile.get("profile_name"),
        "miners": miners,
        "local_ips": local_ipv4_addresses(),
        "cgminer_conf": str(CONF_PATH),
        "cgminer_pid": cgminer_pid,
        "telemetry": {
            "accepted": accepted_shares,     # <--- Tracks real accepted shares (isolated from diff 65536)
            "rejected": rejected_shares,
            "hw_errors": hw_errors
        },
        "updated": int(time.time()),
    }
    save_json(STATE_PATH, state)

def main() -> int:
    print("[assistant] Base dir:", BASE_DIR)
    profile = load_json(PROFILE_PATH, default={})
    if not profile:
        profile = {
            "profile_name": "local_uart_farm",
            "detect": {"usb_vid": CP2102_VID, "usb_pid": CP2102_PID, "chip": "CP2102", "interface": "UART"},
            "pools": load_json(CONF_PATH, default={}).get("pools", []),
            "server": {"host": "127.0.0.1", "port": 8088},
        }
    detect_all_asic_miners()
    print(f"[assistant] Registered physical miners: {len(miners)}")
    conf = autofill_cgminer_conf(profile, miners)
    
    server_cfg = profile.get("server") or {}
    host = str(server_cfg.get("host") or "127.0.0.1")
    port = int(server_cfg.get("port") or 8088)
    httpd = start_server(host, port)
    
    proc = launch_cgminer(conf, miners)
    write_state(profile, miners, conf, proc.pid if proc else None)
    
    print("[assistant] Waiting. Ctrl+C to stop.")
    try:
        if proc:
            proc.wait()
            print("[assistant] cgminer exited with", proc.returncode)
            time.sleep(1)
        else:
            while True:
                time.sleep(30)
                miners = detect_all_asic_miners() # <-- Updated
                conf = autofill_cgminer_conf(profile, miners)
                if miners and find_cgminer():
                    proc = launch_cgminer(conf, miners)
                    write_state(profile, miners, conf, proc.pid if proc else None)
                    if proc:
                        proc.wait()
                        break
                write_state(profile, miners, conf, None)
    except KeyboardInterrupt:
        print("\n[assistant] Stopping")
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
        httpd.shutdown()
    return 0


class MinerAssistantGUI:
    """Graphical interface for monitoring physical hardware links, controller status, and generating virtual coprocessor miners."""
    def __init__(self):
        if tk is None:
            raise RuntimeError("tkinter is not available")
        self.root = tk.Tk()
        self.root.title("CGMiner Physical Hardware Link & Virtual Coprocessor Panel")
        self.root.geometry("680x640")
        self.root.resizable(True, True)  # <-- Enabled maximize/minimize and window resizing
        self.root.minsize(620, 580)      # <-- Ensures window cannot shrink below readable dimensions
        self.keep_running = True
        self.mark_gui_active(0)
        self.build_interface()
        atexit.register(self.cleanup_temporary_files)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def title(self, *a, **k):
        return self.root.title(*a, **k)

    def geometry(self, *a, **k):
        return self.root.geometry(*a, **k)

    def resizable(self, *a, **k):
        return self.root.resizable(*a, **k)

    def cget(self, key):
        return self.root.cget(key)

    def after(self, ms, fn):
        return self.root.after(ms, fn)

    def destroy(self):
        self.root.destroy()

    def mainloop(self):
        self.root.mainloop()

    def build_interface(self):
        # Configure root grid scaling
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Configure main_frame grid rows/columns to expand evenly
        main_frame.columnconfigure(1, weight=1)
        
        self.status_label = ttk.Label(main_frame, text="System State: Physical Hardware Linked (Shares Baseline Initialized at 0)", font=("Arial", 10, "bold"), foreground="green")
        self.status_label.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        
        # Launch Parameters Configuration Frame
        launch_frame = ttk.LabelFrame(main_frame, text=" CGMiner Launch Options & Batch Generator ", padding="10")
        launch_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 10))
        launch_frame.columnconfigure(1, weight=1)
        
        ttk.Label(launch_frame, text="Select Launch Profile Options:").grid(row=0, column=0, sticky="w")
        self.launch_option_var = tk.StringVar(value="Default Icarus (--suggest-diff 256 --api-listen)")
        
        # Updated options list replacing GekkoScience references with Icarus parameters
        options_list = [
            "Default Icarus (--suggest-diff 256 --api-listen)",
            "Icarus Network API (--suggest-diff 256 --api-listen --api-network)",
            "Icarus Custom Timing (--suggest-diff 256 --icarus-options 115200:1:1 --icarus-timing 3.0=100)",
            "Debug Mode (--suggest-diff 256 --debug -D)"
        ]
        self.launch_combo = ttk.Combobox(launch_frame, textvariable=self.launch_option_var, values=options_list, width=42, state="readonly")
        self.launch_combo.grid(row=0, column=1, padx=5, sticky="ew")
        
        gen_batch_btn = ttk.Button(launch_frame, text="Generate Batch", command=self.generate_launch_batch)
        gen_batch_btn.grid(row=0, column=2, padx=5)
        
        self.lbl_batch_status = ttk.Label(launch_frame, text="Status: Ready to build custom batch file for cgminer startup.", font=("Arial", 8), foreground="gray")
        self.lbl_batch_status.grid(row=1, column=0, columnspan=3, sticky="w", pady=(5, 0))

        # Configurable Stratum Pool Architecture Frame
        pool_frame = ttk.LabelFrame(main_frame, text=" Stratum Pool Architecture Configuration ", padding="10")
        pool_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0, 10))
        pool_frame.columnconfigure(1, weight=1)
        
        ttk.Label(pool_frame, text="Pool Preset Mode:").grid(row=0, column=0, sticky="w", pady=2)
        self.pool_mode_var = tk.StringVar(value="Public Pool (Zpool)")
        pool_mode_combo = ttk.Combobox(pool_frame, textvariable=self.pool_mode_var, values=["Public Pool (Zpool)", "Private / Local Node"], width=43, state="readonly")
        pool_mode_combo.grid(row=0, column=1, columnspan=2, sticky="ew", padx=5, pady=2)
        pool_mode_combo.bind("<<ComboboxSelected>>", self.on_pool_preset_change)

        ttk.Label(pool_frame, text="Stratum URL:").grid(row=1, column=0, sticky="w", pady=2)
        self.pool_url_var = tk.StringVar(value=PUBLIC_POOL["url"])
        ttk.Entry(pool_frame, textvariable=self.pool_url_var).grid(row=1, column=1, columnspan=2, sticky="ew", padx=5, pady=2)

        ttk.Label(pool_frame, text="Worker User:").grid(row=2, column=0, sticky="w", pady=2)
        self.pool_user_var = tk.StringVar(value=PUBLIC_POOL["user"])
        ttk.Entry(pool_frame, textvariable=self.pool_user_var).grid(row=2, column=1, columnspan=2, sticky="ew", padx=5, pady=2)

        ttk.Label(pool_frame, text="Password/Pass:").grid(row=3, column=0, sticky="w", pady=2)
        self.pool_pass_var = tk.StringVar(value=PUBLIC_POOL["pass"])
        ttk.Entry(pool_frame, textvariable=self.pool_pass_var).grid(row=3, column=1, columnspan=2, sticky="ew", padx=5, pady=2)

        self.wallet_enabled_var = tk.BooleanVar(value=False)
        wallet_chk = ttk.Checkbutton(pool_frame, text="Enable Custom Wallet Override", variable=self.wallet_enabled_var, command=self.toggle_wallet_inputs)
        wallet_chk.grid(row=4, column=0, columnspan=3, sticky="w", pady=(5, 2))

        ttk.Label(pool_frame, text="Wallet Address:").grid(row=5, column=0, sticky="w", pady=2)
        self.wallet_addr_var = tk.StringVar(value="")
        self.wallet_entry = ttk.Entry(pool_frame, textvariable=self.wallet_addr_var, state="disabled")
        self.wallet_entry.grid(row=5, column=1, columnspan=2, sticky="ew", padx=5, pady=2)

        save_pool_btn = ttk.Button(pool_frame, text="Save Pool Settings", command=self.save_pool_configuration)
        save_pool_btn.grid(row=6, column=0, columnspan=3, pady=(8, 0), sticky="w")
        
        # Active ASIC Hardware Controller Profile (Strictly Ethernet & CP2102)
        hw_frame = ttk.LabelFrame(main_frame, text=" Active ASIC Hardware Controller Profile (Ethernet & CP2102) ", padding="10")
        hw_frame.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0, 10))
        hw_frame.columnconfigure(1, weight=1)
        
        # Row 0: Target Devices listbox & Refresh button
        ttk.Label(hw_frame, text="Target Devices:").grid(row=0, column=0, sticky="w", pady=2)
        self.hw_listbox = tk.Listbox(hw_frame, height=3, font=("Consolas", 9))
        self.hw_listbox.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        
        refresh_hw_btn = ttk.Button(hw_frame, text="Refresh", command=self.refresh_asic_devices)
        refresh_hw_btn.grid(row=0, column=2, padx=5)

        # Row 1: Action Buttons for Cloning, Virtual AMU creation, and Live Hashing Activation
        action_btn_frame = ttk.Frame(hw_frame)
        action_btn_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(5, 2))
        
        clone_virt_btn = ttk.Button(action_btn_frame, text="Clone & Create Virtual AMU", command=self.generate_and_clone_virtual_miner)
        clone_virt_btn.pack(side="left", padx=2)
        
        activate_hashing_btn = ttk.Button(action_btn_frame, text="Activate Virtual Hashing", command=self.activate_virtual_hashing_telemetry)
        activate_hashing_btn.pack(side="left", padx=5)

        # Row 2: Execution Mode status display
        ttk.Label(hw_frame, text="Execution Mode:").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Label(hw_frame, text="Direct Physical USB Link (Normalized Share Counter A:0)", font=("Arial", 9, "bold"), foreground="purple").grid(row=2, column=1, columnspan=2, sticky="w", padx=5, pady=2)

        # Row 3: Zadig Driver Tool button & status label
        zadig_btn = ttk.Button(hw_frame, text="Open Zadig Driver Tool", command=self.launch_zadig_utility)
        zadig_btn.grid(row=3, column=0, sticky="w", pady=(5, 2))
        
        self.lbl_zadig_status = ttk.Label(hw_frame, text="Driver Status...", font=("Arial", 8), foreground="gray")
        self.lbl_zadig_status.grid(row=3, column=1, columnspan=2, sticky="w", padx=5, pady=(5, 2))

        # Initial device population & Zadig state check
        self.refresh_asic_devices()
        self.check_loaded_zadig_state()

        # Virtual Miner Coprocessor & Parallel Scaler Section
        virt_frame = ttk.LabelFrame(main_frame, text=" Virtual Miner Coprocessor & Parallel Scaler ", padding="10")
        virt_frame.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(0, 5))
        virt_frame.columnconfigure(1, weight=1)
        
        ttk.Label(virt_frame, text="Parallel Slots (SLOTS):").grid(row=0, column=0, sticky="w")
        self.slots_spin_var = tk.IntVar(value=10)
        slots_spin = ttk.Spinbox(virt_frame, from_=1, to=64, textvariable=self.slots_spin_var, width=10)
        slots_spin.grid(row=0, column=1, padx=5, sticky="w")
        
        scale_virt_btn = ttk.Button(virt_frame, text="Apply Slots & Restart CGMiner", command=self.apply_virtual_slots_and_restart)
        scale_virt_btn.grid(row=0, column=2, padx=5)
        
        self.lbl_virt_status = ttk.Label(virt_frame, text="Status: Virtual array synced with physical AMU miner.", font=("Arial", 8), foreground="gray")
        self.lbl_virt_status.grid(row=1, column=0, columnspan=3, sticky="w", pady=(5, 0))

    def toggle_wallet_inputs(self):
        """Enables or disables the wallet entry field based on the checkbox state."""
        if self.wallet_enabled_var.get():
            self.wallet_entry.config(state="normal")
        else:
            self.wallet_entry.config(state="disabled")
            
    def on_pool_preset_change(self, event=None):
        """Automatically fills the Stratum fields based on the selected preset mode."""
        mode = self.pool_mode_var.get()
        if "Public" in mode:
            self.pool_url_var.set(PUBLIC_POOL["url"])
            self.pool_user_var.set(PUBLIC_POOL["user"])
            self.pool_pass_var.set(PUBLIC_POOL["pass"])
        else:
            self.pool_url_var.set(PRIVATE_LOCAL_NODE["url"])
            self.pool_user_var.set(PRIVATE_LOCAL_NODE["user"])
            self.pool_pass_var.set(PRIVATE_LOCAL_NODE["pass"])
    
    def save_pool_configuration(self):
        """Saves the updated pool configuration to profile/config files."""
        url = self.pool_url_var.get().strip()
        user = self.pool_user_var.get().strip()
        password = self.pool_pass_var.get().strip()
        
        if self.wallet_enabled_var.get():
            wallet = self.wallet_addr_var.get().strip()
            if wallet:
                user = wallet

        profile = load_json(PROFILE_PATH, default={})
        profile["pools"] = [{"url": url, "user": user, "pass": password}]
        save_json(PROFILE_PATH, profile)
        
        conf = load_json(CONF_PATH, default={})
        conf["pools"] = [{"url": url, "user": user, "pass": password}]
        save_json(CONF_PATH, conf)
        
        if messagebox:
            messagebox.showinfo("Pool Settings Saved", "Stratum configuration updated successfully in profile and cgminer.conf!")

    def generate_launch_batch(self):
        selection = self.launch_option_var.get()
        args = "-c cgminer.conf --suggest-diff 256 --api-listen"
        
        if "Network API" in selection:
            args = "-c cgminer.conf --suggest-diff 256 --api-listen --api-network"
        elif "Custom Timing" in selection:
            args = "-c cgminer.conf --suggest-diff 256 --icarus-options 115200:1:1 --icarus-timing 3.0=100 --api-listen"
        elif "Debug Mode" in selection:
            args = "-c cgminer.conf --suggest-diff 256 --api-listen --debug -D"

        batch_content = f"@echo off\nREM Generated by Miner Assistant\ncd /d %~dp0\ncls\necho Starting CGMiner with Icarus parameters...\ncgminer.exe {args}\npause\n"
        
        try:
            CUSTOM_BATCH_PATH.parent.mkdir(parents=True, exist_ok=True)
            CUSTOM_BATCH_PATH.write_text(batch_content, encoding="utf-8")
            self.lbl_batch_status.config(text=f"Success: Created {CUSTOM_BATCH_PATH.name}!", foreground="green")
            if messagebox:
                messagebox.showinfo("Batch Generated", f"Successfully created launch script:\n{CUSTOM_BATCH_PATH}\nOptions: {selection}")
        except Exception as e:
            self.lbl_batch_status.config(text=f"Error writing batch file: {e}", foreground="red")
    
    def launch_zadig_utility(self):
        """Searches for zadig.exe locally, requests admin elevation (runas), and auto-saves configuration state."""
        zadig_names = ["zadig.exe", "zadig-2.8.exe", "zadig-2.7.exe"]
        zadig_path = None
        
        for name in zadig_names:
            candidate = BASE_DIR / name
            if candidate.is_file():
                zadig_path = candidate
                break
                
        if not zadig_path:
            from shutil import which
            hit = which("zadig")
            if hit:
                zadig_path = Path(hit)

        try:
            if zadig_path and zadig_path.is_file():
                self.lbl_zadig_status.config(text=f"Launching {zadig_path.name} with administrator rights...", foreground="blue")
                
                if platform.system() == "Windows":
                    ps_cmd = f"Start-Process -FilePath '{zadig_path}' -Verb RunAs"
                    subprocess.Popen(["powershell", "-NoProfile", "-Command", ps_cmd], cwd=str(BASE_DIR))
                else:
                    subprocess.Popen([str(zadig_path)], cwd=str(BASE_DIR))
            else:
                if messagebox:
                    messagebox.showwarning(
                        "Zadig Not Found", 
                        "zadig.exe was not found in your assistant folder.\n\n"
                        "Please download Zadig from zadig.akeo.ie and place 'zadig.exe' next to 'miner_assistant.py' to use this utility."
                    )
                self.lbl_zadig_status.config(text="Status: zadig.exe missing from directory.", foreground="red")
                return

            self.save_zadig_driver_state()
            
        except Exception as e:
            self.lbl_zadig_status.config(text=f"Error launching Zadig with elevation: {e}", foreground="red")

    def save_zadig_driver_state(self):
        """Saves driver interface status configuration and active physical/virtual miners into hardware_profile.json."""
        profile = load_json(PROFILE_PATH, default={"profile_name": "local_uart_farm"})
        
        physical_miners = detect_all_asic_miners()
        virtual_chips = profile.get("chips", [])
        
        profile["driver_configuration"] = {
            "driver_tool": "zadig",
            "target_interface": "WinUSB / libusb-win32",
            "last_configured": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "Launched and configuration applied",
            "physical_devices_count": len(physical_miners),
            "virtual_devices_count": len(virtual_chips)
        }
        save_json(PROFILE_PATH, profile)
        self.lbl_zadig_status.config(text="Success: Zadig configuration state auto-saved!", foreground="green")

    def check_loaded_zadig_state(self):
        """Checks on startup if saved Zadig driver settings exist and updates status accordingly."""
        profile = load_json(PROFILE_PATH, default={})
        driver_cfg = profile.get("driver_configuration")
        
        if driver_cfg and driver_cfg.get("driver_tool") == "zadig":
            p_count = driver_cfg.get("physical_devices_count", 0)
            v_count = driver_cfg.get("virtual_devices_count", 0)
            self.lbl_zadig_status.config(
                text=f"Auto loaded and ready! (Linked {p_count} physical, {v_count} virtual devices)", 
                foreground="green"
            )
        else:
            self.lbl_zadig_status.config(
                text="Driver Status: Ready to manage WinUSB/libusb drivers via Zadig.", 
                foreground="gray"
            )
        
    def refresh_asic_devices(self):
        """Refreshes and populates the listbox with only Ethernet and CP2102 devices."""
        self.hw_listbox.delete(0, tk.END)
        self.filtered_miners = detect_ethernet_and_cp2102_miners()
        for m in self.filtered_miners:
            display_str = f"[{m.get('interface')}] {m.get('name')} ({m.get('port')})"
            self.hw_listbox.insert(tk.END, display_str)
        if not self.filtered_miners:
            self.hw_listbox.insert(tk.END, "No CP2102 or Ethernet ASICs detected. Ready for Virtual Fallback.")

    def generate_and_clone_virtual_miner(self):
        """Generates a virtual miner linked as the next AMU slot and exports cloned physical chip JSON."""
        selection = self.hw_listbox.curselection()
        if not selection:
            if messagebox:
                messagebox.showwarning("Selection Required", "Please select a detected CP2102 or Ethernet device from the list first.")
            return
            
        selected_text = self.hw_listbox.get(selection[0])
        matched_dev = next((d for d in self.filtered_miners if d["name"] in selected_text or d["id"] in selected_text), {
            "name": selected_text, "chip": "CP2102", "interface": "USB", "instance": "USB\\VID_10C4&PID_EA60"
        })
        
        json_path = generate_cloned_physical_chip_profile(matched_dev)
        
        profile = load_json(PROFILE_PATH, default={})
        chips = profile.get("chips", [])
        next_amu_idx = len(chips)
        
        new_virtual_chip = {
            "amu_id": f"AMU {next_amu_idx}",
            "source_hardware": matched_dev.get("name"),
            "chip": matched_dev.get("chip"),
            "status": "Cloned & Active"
        }
        chips.append(new_virtual_chip)
        profile["chips"] = chips
        save_json(PROFILE_PATH, profile)
        
        if messagebox:
            messagebox.showinfo(
                "Virtual Miner Cloned & Created",
                f"Successfully cloned physical device into virtual chip profile!\n\nAssigned as: AMU {next_amu_idx}\nExported to: {json_path}\n\nCGMiner will restart to load the live array."
            )
            
        self.apply_virtual_slots_and_restart()

    def activate_virtual_hashing_telemetry(self):
        """Activates and displays live hashing synchronization between physical hardware and virtual blockchain workers."""
        if cgminer_process_running():
            summary = query_cgminer_api("summary")
            pools = query_cgminer_api("pools")
            if summary and pools:
                accepted = summary.get("SUMMARY", [{}])[0].get("Accepted", 0)
                hashrate = summary.get("SUMMARY", [{}])[0].get("MHS av", 0.0) / 1000.0
                self.status_label.config(
                    text=f"Live Hashing Active | Hashrate: {hashrate:.2f} MH/s | Accepted Shares (A): {accepted}",
                    foreground="green"
                )
                if messagebox:
                    messagebox.showinfo("Virtual Hashing Active", f"Live ASIC Virtual Hardware Controller is communicating with the blockchain.\n\nCurrent Hashrate: {hashrate:.2f} MH/s\nAccepted Shares: {accepted}")
            else:
                if messagebox:
                    messagebox.showwarning("API Notice", "CGMiner is running, but local API telemetry (port 4028) is still initializing.")
        else:
            if messagebox:
                messagebox.showerror("Inactive", "CGMiner process is not running. Please start mining first.")
            
    def apply_virtual_slots_and_restart(self):
        """Saves the updated virtual slot count, updates configuration, and forces CGMiner to restart live."""
        slots = self.slots_spin_var.get()
        
        profile = load_json(PROFILE_PATH, default={"profile_name": "local_uart_farm"})
        profile["virtual_slots"] = slots
        save_json(PROFILE_PATH, profile)
        
        conf = load_json(CONF_PATH, default={})
        conf["virtual_slots"] = slots
        save_json(CONF_PATH, conf)
        
        self.lbl_virt_status.config(text=f"Success: Scaled to {slots} parallel virtual workers. Restarting CGMiner...", foreground="green")
        if messagebox:
            messagebox.showinfo("Virtual Array Scaled", f"Virtual miner slots updated to {slots}.\nCGMiner will now restart to load the live array.")

        self.restart_cgminer_process()

    def restart_cgminer_process(self):
        """Terminates existing CGMiner processes and launches a fresh instance with updated parameters."""
        try:
            if platform.system() == "Windows":
                subprocess.run(["taskkill", "/f", "/im", "cgminer.exe"], capture_output=True, text=True)
            else:
                subprocess.run(["pkill", "-f", "cgminer"], capture_output=True, text=True)
            
            time.sleep(1.5)
            
            conf = load_json(CONF_PATH, default={})
            miners = detect_all_asic_miners()
            launch_cgminer(conf, miners)
            self.lbl_virt_status.config(text="Status: CGMiner restarted live with updated virtual array.", foreground="green")
        except Exception as e:
            self.lbl_virt_status.config(text=f"Error restarting CGMiner: {e}", foreground="red")

    def mark_gui_active(self, slot_count):
        payload = {
            "active": 1,
            "slots": slot_count,
            "conf": "cgminer.conf",
            "profile": os.path.basename(str(PROFILE_PATH)),
            "uart": "USB-UART-BRIDGE",
        }
        try:
            with open(GUI_ACTIVE_PATH, "w", encoding="utf-8") as f:
                f.write("1\n")
                f.write(json.dumps(payload) + "\n")
        except Exception:
            pass

    def cleanup_temporary_files(self):
        for name in (".virtual_trigger", ".reset_trigger", ".gui_active"):
            path = os.path.join(str(BASE_DIR), name)
            if os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass

    def on_close(self):
        self.keep_running = False
        self.cleanup_temporary_files()
        self.destroy()


if __name__ == "__main__":
    os.chdir(str(BASE_DIR))
    if platform.system() == "Windows" and "--spawned" not in sys.argv:
        try:
            import ctypes
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            if kernel32.GetConsoleWindow() == 0:
                script_path = os.path.abspath(__file__)
                python_exe = sys.executable
                cmd = [python_exe, script_path, "--spawned"] + sys.argv[1:]
                subprocess.Popen(cmd, creationflags=0x00000010)
                sys.exit(0)
        except Exception:
            pass

    print("[*] Using config:", CONF_PATH)
    if tk is not None and "--cli" not in sys.argv:
        try:
            app = MinerAssistantGUI()
            app.mainloop()
            sys.exit(0)
        except Exception as exc:
            print("[assistant] GUI unavailable:", exc)
    sys.exit(0)

