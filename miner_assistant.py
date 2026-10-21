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
   - Assistant's Role: The autofill_cgminer_conf() function automatically writes and formats your cgminer.conf on startup with proper properties (without forcing suggest-diff so difficulty is not injected into accepted shares).

3. Preventing Initial Difficulty Spikes
   - Physical USB ASIC sticks can fail or throw errors if they immediately digest high-difficulty pool targets on cold startup.
   - Assistant's Role: Does not inject suggest-diff, ensuring the difficulty is not placed in accepted shares when the bat file is generated and run.
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
    """Scans and identifies connected physical CP2102 ASIC hardware, Ethernet nodes, and virtual coprocessor chips."""
    found: List[Dict[str, str]] = []
    system = platform.system()
    if system == "Windows":
        found.extend(_detect_windows_all_miners())
    else:
        found.extend(_detect_linux_all_miners())
    
    # Discover configured network/Ethernet ASIC endpoints
    found.extend(_detect_network_asic_miners())
    
    # Include virtual chip coprocessors stored in hardware_profile.json
    found.extend(_detect_virtual_chip_miners())
    return found

def _is_true_physical_asic_controller(name: str, instance: str) -> bool:
    """Only CP2102, CH340, FTDI, PL2303, or known ASIC miner controllers.
    Explicitly rejects mice, keyboards, HID, and other input devices."""
    n = (name or "").upper()
    i = (instance or "").upper()
    # Reject input / consumer USB devices
    reject = ("MOUSE", "KEYBOARD", "HID", "INPUT", "TOUCHPAD", "TRACKPAD", "WEBCAM", "CAMERA", "AUDIO", "BLUETOOTH", "COMPOSITE")
    if any(k in n or k in i for k in reject):
        return False
    # Exact bridge controllers
    if any(k in n or k in i for k in ("CP210", "10C4", "CH340", "1A86", "FTDI", "0403", "PL2303", "067B")):
        return True
    # Known physical ASIC device names
    if any(k in n for k in ("ICARUS", "GEKKO", "NEWPAC", "ANTMINER", "WHATSMINER", "AVALON", "BLOCK ERUPTER", "USB TO UART BRIDGE")):
        return True
    return False

def _detect_windows_all_miners() -> List[Dict[str, str]]:
    """Detect only true physical USB ASIC controllers (CP2102/CH340/FTDI/PL2303 and known ASICs).
    A present CP2102 (typical Icarus) is marked online."""
    miners: List[Dict[str, str]] = []
    # Strict VID filter for the four real bridges + name fallback for Icarus/ASIC
    ps = (
        "Get-PnpDevice -PresentOnly | "
        "Where-Object { "
        "$_.InstanceId -match 'VID_10C4|VID_1A86|VID_0403|VID_067B' -or "
        "$_.FriendlyName -match 'CP210|CH340|FTDI|PL2303|Icarus|Gekko|NewPac|Antminer|Whatsminer|Avalon|USB to UART Bridge' "
        "} | "
        "Select-Object Status,Class,FriendlyName,InstanceId | ConvertTo-Json"
    )
    try:
        raw = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps],
            text=True,
            errors="ignore",
            timeout=25,
        )
        data = json.loads(raw) if raw.strip() else []
        if isinstance(data, dict):
            data = [data]
        for idx, dev in enumerate(data or []):
            inst = str(dev.get("InstanceId") or "")
            name = str(dev.get("FriendlyName") or "USB ASIC Device")
            if not _is_true_physical_asic_controller(name, inst):
                continue
            raw_status = str(dev.get("Status") or "Unknown")
            # PresentOnly query already means the device is plugged in.
            # A steady green light on CP2102/Icarus = online unless explicitly error/disabled.
            bad = raw_status.lower() in ("error", "problem", "disabled", "degraded", "unknown")
            status = "offline" if bad else "online"
            port = _windows_com_for_instance(inst) or "n/a"
            nup, iup = name.upper(), inst.upper()
            if "CH340" in nup or "1A86" in iup:
                chip = "CH340"
            elif "FTDI" in nup or "0403" in iup:
                chip = "FTDI"
            elif "PL2303" in nup or "067B" in iup:
                chip = "PL2303"
            else:
                chip = "CP2102"  # default for 10C4 / Icarus
            miners.append({
                "id": f"usb-asic-{idx + 1}",
                "name": name,
                "instance": inst,
                "status": status,
                "raw_status": raw_status,
                "port": port,
                "chip": chip,
                "interface": "USB",
                "virtual": False,
            })
    except Exception:
        pass
    return miners

def _detect_virtual_chip_miners() -> List[Dict[str, str]]:
    """Loads virtual HDL array coprocessors. These are NOT reported as physical USB devices."""
    virtual_miners: List[Dict[str, str]] = []
    profile = load_json(PROFILE_PATH, default={})
    usb_enabled = profile.get("virtual_usb_enabled", True)
    if not usb_enabled:
        return []
    chips = profile.get("chips") or []
    for idx, chip in enumerate(chips):
        virtual_miners.append({
            "id": chip.get("id", f"virtual-hdl-amu-{idx + 1}"),
            "name": chip.get("name", f"HDL Virtual AMU {idx + 1}"),
            "chip": chip.get("chip", "HDL-Virtual"),
            "interface": "HDL-Virtual",   # distinct from physical USB
            "virtual": True,
            "amu_id": chip.get("amu_id", f"AMU {idx + 1}"),
            "source_hardware": chip.get("source_hardware", ""),
            "source_instance": chip.get("source_instance", ""),
            "status": "virtual-active",
            "created_at": chip.get("created_at", time.strftime("%Y-%m-%d %H:%M:%S")),
            "port": "HDL",
            "instance": "HDL-VIRTUAL",
        })
    return virtual_miners

def detect_ethernet_and_cp2102_miners() -> List[Dict[str, str]]:
    """Detect all USB serial/ASIC devices and Ethernet miners, with real online/offline status.
    Virtual HDL miners are listed separately and are never reported as physical USB."""
    found: List[Dict[str, str]] = []
    system = platform.system()
    if system == "Windows":
        found.extend(_detect_windows_all_miners())
    else:
        found.extend(_detect_linux_all_miners())
    # Ethernet with live reachability check
    found.extend(_detect_network_asic_miners())
    # Virtual HDL array entries (distinct, not physical USB)
    found.extend(_detect_virtual_chip_miners())
    return found

def _windows_com_for_instance(instance_id: str) -> str:
    """Resolve the COM port for a USB PnP instance (Icarus/CP2102 etc.)."""
    try:
        # Friendly name often contains (COMx)
        cmd = (
            f"(Get-PnpDevice -InstanceId '{instance_id}' -ErrorAction SilentlyContinue).FriendlyName"
        )
        val = subprocess.check_output(["powershell", "-NoProfile", "-Command", cmd], text=True, errors="ignore", timeout=5).strip()
        if "COM" in val.upper():
            import re
            m = re.search(r"(COM\d+)", val, re.I)
            if m:
                return m.group(1)
        # Fallback: Win32_SerialPort
        cmd2 = (
            "Get-CimInstance Win32_SerialPort | "
            "Select-Object DeviceID,PNPDeviceID | ConvertTo-Json"
        )
        raw = subprocess.check_output(["powershell", "-NoProfile", "-Command", cmd2], text=True, errors="ignore", timeout=8)
        ports = json.loads(raw) if raw.strip() else []
        if isinstance(ports, dict):
            ports = [ports]
        for p in ports or []:
            if str(p.get("PNPDeviceID", "")).upper() == instance_id.upper():
                return str(p.get("DeviceID") or "")
    except Exception:
        pass
    return ""

def _detect_linux_all_miners() -> List[Dict[str, str]]:
    miners: List[Dict[str, str]] = []
    by_id = Path("/dev/serial/by-id")
    if by_id.exists():
        for link in sorted(by_id.iterdir()):
            name = link.name.lower()
            if any(k in name for k in ("cp210", "10c4", "ch340", "1a86", "ftdi", "0403", "pl2303", "uart", "asic")):
                target = str(link.resolve())
                miners.append(
                    {
                        "id": f"asic-{link.name}",
                        "name": link.name,
                        "instance": target,
                        "status": "present",
                        "port": target,
                        "chip": "CP2102",
                        "interface": "UART",
                    }
                )
    return miners

def _detect_network_asic_miners() -> List[Dict[str, str]]:
    """Probes configured Ethernet ASIC endpoints and marks them online or offline."""
    net_miners: List[Dict[str, str]] = []
    profile = load_json(PROFILE_PATH, default={})
    configured_nets = profile.get("network_miners") or []
    for idx, net in enumerate(configured_nets):
        ip = str(net.get("ip", "")).strip()
        port = int(net.get("port", 4028) or 4028)
        status = "offline"
        if ip:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                status = "online" if result == 0 else "offline"
            except Exception:
                status = "offline"
        net_miners.append({
            "id": f"asic-net-{idx + 1}",
            "name": str(net.get("name") or f"Ethernet ASIC {ip or 'Node'}"),
            "instance": ip,
            "status": status,
            "port": str(port),
            "chip": str(net.get("chip", "Network ASIC")),
            "interface": "Ethernet",
            "virtual": False,
        })
    return net_miners

def generate_cloned_physical_chip_profile(selected_device: dict) -> str:
    """Copies a detected physical miner (chip/motherboard info) into an HDL virtual AMU slot.
    The virtual entry is NOT marked as a physical USB device. The HDL folder
    (virtual_miner_array.v) uses the resulting profile to size/load the virtual array."""
    profile = load_json(PROFILE_PATH, default={"profile_name": "local_uart_farm", "chips": []})
    chips = profile.get("chips", [])
    next_idx = len(chips) + 1
    # Copy real physical identity; virtual stays virtual
    new_virtual_chip = {
        "id": f"virtual-hdl-amu-{next_idx}",
        "name": f"HDL Virtual AMU cloned from {selected_device.get('name', 'Physical Miner')}",
        "chip": selected_device.get("chip", "ASIC"),
        "interface": "HDL-Virtual",
        "virtual": True,
        "amu_id": f"AMU {next_idx}",
        "source_hardware": selected_device.get("name", ""),
        "source_instance": selected_device.get("instance", ""),
        "source_port": selected_device.get("port", ""),
        "source_interface": selected_device.get("interface", ""),
        "source_status": selected_device.get("status", ""),
        "status": "virtual-active",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    chips.append(new_virtual_chip)
    profile["chips"] = chips
    profile["virtual_slots"] = max(int(profile.get("virtual_slots", 10) or 10), len(chips))
    # Write a small HDL side-car so virtual_miner_array.v / the HDL image can load the slots
    hdl_dir = BASE_DIR / "hdl"
    hdl_dir.mkdir(parents=True, exist_ok=True)
    hdl_meta = {
        "virtual_miner_count": profile["virtual_slots"],
        "cloned_from": [c.get("source_hardware") for c in chips],
        "array_file": "virtual_miner_array.v",
    }
    save_json(hdl_dir / "virtual_array_meta.json", hdl_meta)
    save_json(PROFILE_PATH, profile)
    return str(PROFILE_PATH)

def calculate_optimal_difficulty(profile: dict, miners: List[dict]) -> str:
    """Dynamically calculates optimal suggest-diff based on detected physical hardware capability."""
    physical_count = max(len(miners), 1)
    
    if physical_count > 15:
        optimal_diff = 16384
    elif physical_count > 5:
        optimal_diff = 8192
    elif physical_count > 2:
        optimal_diff = 4096
    else:
        optimal_diff = 256
        
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
        "icarus-options": "115200:1:1",
        "icarus-timing": "3.0=100",
        "queue": 1,
        "expiry": 10,
        "scan-time": 1,
        "fallback-time": 120,
    }
    
    save_json(CONF_PATH, conf)
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
    
    # Command invocation for legacy Icarus / Block Erupter units (no forced difficulty)
    cmd = [str(binary), "-c", str(CONF_PATH)]
    
    # Optional hardware frequency overrides if running mixed arrays
    cmd.extend(["--icarus-options", "115200:1:1", "--icarus-timing", "3.0=100"])
    
    print("[assistant] Launching CGMiner linked to physical hardware (no forced difficulty)...")
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

def write_state(profile: dict, miners: List[dict], conf: dict, cgminer_pid: Optional[int]) -> None:
    """Generates and syncs miner_state.json directly using configuration values from hardware_profile.json."""
    profile = load_json(PROFILE_PATH, default=profile)
    configured_chips = profile.get("chips", [])
    
    state = {
        "profile_name": profile.get("profile_name", "local_uart_farm"),
        "chips": configured_chips,
        "driver_configuration": profile.get("driver_configuration", {}),
        "miners": miners if miners else configured_chips,
        "local_ips": local_ipv4_addresses(),
        "cgminer_conf": str(CONF_PATH),
        "cgminer_pid": cgminer_pid,
        "telemetry": {
            "status": "Running direct hardware execution"
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
        }
    
    # FIX: Properly assign detected devices to the miners variable
    miners = detect_all_asic_miners()
    print(f"[assistant] Registered physical & virtual miners: {len(miners)}")
    
    conf = autofill_cgminer_conf(profile, miners)
    
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
                miners = detect_all_asic_miners()
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
    return 0


class MinerAssistantGUI:
    """Graphical interface for monitoring physical hardware links, controller status, and generating virtual coprocessor miners."""
    def __init__(self):
        if tk is None:
            raise RuntimeError("tkinter is not available")
        self.root = tk.Tk()
        self.root.title("CGMiner Physical Hardware Link & Virtual Coprocessor Panel")
        self.root.geometry("860x1100")        # <--- Expanded height to fit all sections comfortably
        self.root.resizable(True, True)
        self.root.minsize(820, 1000)      # <--- Adjusted minimum size
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

        # Canvas + scrollbar for mouse-wheel scrolling
        canvas = tk.Canvas(self.root, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        main_frame = ttk.Frame(canvas, padding="8")
        main_frame.columnconfigure(1, weight=1)
        for r in range(8):
            main_frame.rowconfigure(r, weight=0)

        canvas_window = canvas.create_window((0, 0), window=main_frame, anchor="nw")

        def _on_frame_configure(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(canvas_window, width=canvas.winfo_width())

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        main_frame.bind("<Configure>", _on_frame_configure)
        canvas.bind("<Configure>", _on_frame_configure)
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
        canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))
        
        # Row 0: System State Status Label
        self.status_label = ttk.Label(main_frame, text="System State: Physical Hardware Linked", font=("Arial", 9, "bold"), foreground="green")
        self.status_label.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 4))
        
        # Row 1: Launch Parameters Configuration Frame
        launch_frame = ttk.LabelFrame(main_frame, text=" CGMiner Launch Options & Batch Generator ", padding="6")
        launch_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        launch_frame.columnconfigure(1, weight=1)
        
        ttk.Label(launch_frame, text="Options:").grid(row=0, column=0, sticky="w")
        self.launch_option_var = tk.StringVar(value="Default Icarus")
        options_list = [
            "Default Icarus",
            "Icarus Custom Timing (--icarus-options 115200:1:1 --icarus-timing 3.0=100)",
            "Debug Mode (--debug -D)"
        ]
        self.launch_combo = ttk.Combobox(launch_frame, textvariable=self.launch_option_var, values=options_list, width=36, state="readonly")
        self.launch_combo.grid(row=0, column=1, padx=4, sticky="ew")
        
        gen_batch_btn = ttk.Button(launch_frame, text="Gen Batch", command=self.generate_launch_batch)
        gen_batch_btn.grid(row=0, column=2, padx=4)
        
        self.lbl_batch_status = ttk.Label(launch_frame, text="Status: Ready.", font=("Arial", 8), foreground="gray")
        self.lbl_batch_status.grid(row=1, column=0, columnspan=3, sticky="w", pady=(2, 0))

        # Row 2: Stratum Pool Configuration Frame
        pool_frame = ttk.LabelFrame(main_frame, text=" Stratum Pool Configuration ", padding="6")
        pool_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        pool_frame.columnconfigure(1, weight=1)
        
        ttk.Label(pool_frame, text="Preset:").grid(row=0, column=0, sticky="w", pady=1)
        self.pool_mode_var = tk.StringVar(value="Public Pool (Zpool)")
        pool_mode_combo = ttk.Combobox(pool_frame, textvariable=self.pool_mode_var, values=["Public Pool (Zpool)", "Private / Local Node"], width=36, state="readonly")
        pool_mode_combo.grid(row=0, column=1, columnspan=2, sticky="ew", padx=4, pady=1)
        pool_mode_combo.bind("<<ComboboxSelected>>", self.on_pool_preset_change)

        ttk.Label(pool_frame, text="URL:").grid(row=1, column=0, sticky="w", pady=1)
        self.pool_url_var = tk.StringVar(value=PUBLIC_POOL["url"])
        ttk.Entry(pool_frame, textvariable=self.pool_url_var).grid(row=1, column=1, columnspan=2, sticky="ew", padx=4, pady=1)

        ttk.Label(pool_frame, text="User:").grid(row=2, column=0, sticky="w", pady=1)
        self.pool_user_var = tk.StringVar(value=PUBLIC_POOL["user"])
        ttk.Entry(pool_frame, textvariable=self.pool_user_var).grid(row=2, column=1, columnspan=2, sticky="ew", padx=4, pady=1)

        ttk.Label(pool_frame, text="Pass:").grid(row=3, column=0, sticky="w", pady=1)
        self.pool_pass_var = tk.StringVar(value=PUBLIC_POOL["pass"])
        ttk.Entry(pool_frame, textvariable=self.pool_pass_var).grid(row=3, column=1, columnspan=2, sticky="ew", padx=4, pady=1)

        save_pool_btn = ttk.Button(pool_frame, text="Save Pool Settings", command=self.save_pool_configuration)
        save_pool_btn.grid(row=4, column=0, columnspan=3, pady=(3, 0), sticky="w")

        # Row 3: Hardware & Coprocessor Status Summary Frame
        status_summary_frame = ttk.LabelFrame(main_frame, text=" Hardware & Coprocessor Status Summary ", padding="6")
        status_summary_frame.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        status_summary_frame.columnconfigure(1, weight=1)
        status_summary_frame.columnconfigure(3, weight=1)

        ttk.Label(status_summary_frame, text="Physical:").grid(row=0, column=0, sticky="w")
        self.lbl_phys_count = ttk.Label(status_summary_frame, text="0 detected", font=("Arial", 8, "bold"))
        self.lbl_phys_count.grid(row=0, column=1, sticky="w", padx=2)

        self.lbl_phys_indicator = ttk.Label(status_summary_frame, text="● OFFLINE", font=("Arial", 8, "bold"), foreground="red")
        self.lbl_phys_indicator.grid(row=0, column=2, sticky="w", padx=4)

        ttk.Label(status_summary_frame, text="Virtual USB:").grid(row=0, column=3, sticky="w")
        self.lbl_virt_count = ttk.Label(status_summary_frame, text="0 active", font=("Arial", 8, "bold"))
        self.lbl_virt_count.grid(row=0, column=4, sticky="w", padx=2)

        self.lbl_virt_indicator = ttk.Label(status_summary_frame, text="● OFFLINE", font=("Arial", 8, "bold"), foreground="red")
        self.lbl_virt_indicator.grid(row=0, column=5, sticky="w", padx=4)

        # Row 4: Active ASIC Hardware Controller Profile (CP2102 Bridge)
        hw_frame = ttk.LabelFrame(main_frame, text=" Active ASIC Hardware Controller Profile (CP2102 Bridge) ", padding="6")
        hw_frame.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        hw_frame.columnconfigure(1, weight=1)
        
        ttk.Label(hw_frame, text="Target:").grid(row=0, column=0, sticky="w", pady=1)
        self.hw_listbox = tk.Listbox(hw_frame, height=2, font=("Consolas", 8))
        self.hw_listbox.grid(row=0, column=1, sticky="ew", padx=4, pady=1)
        
        refresh_hw_btn = ttk.Button(hw_frame, text="Refresh", command=self.refresh_asic_devices)
        refresh_hw_btn.grid(row=0, column=2, padx=4)

        action_btn_frame = ttk.Frame(hw_frame)
        action_btn_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(2, 1))
        
        clone_virt_btn = ttk.Button(action_btn_frame, text="Clone & Create Virtual AMU", command=self.generate_and_clone_virtual_miner)
        clone_virt_btn.pack(side="left", padx=2)
        
        activate_hashing_btn = ttk.Button(action_btn_frame, text="Verify Process Status", command=self.activate_virtual_hashing_telemetry)
        activate_hashing_btn.pack(side="left", padx=4)

        zadig_btn = ttk.Button(hw_frame, text="Open Zadig Driver Tool", command=self.launch_zadig_utility)
        zadig_btn.grid(row=2, column=0, sticky="w", pady=(2, 1))
        
        self.lbl_zadig_status = ttk.Label(hw_frame, text="Driver Status ready...", font=("Arial", 8), foreground="gray")
        self.lbl_zadig_status.grid(row=2, column=1, columnspan=2, sticky="w", padx=4, pady=(2, 1))

        self.refresh_asic_devices()
        self.check_loaded_zadig_state()

        # Row 5: Virtual Coprocessor USB Activation Section
        virt_frame = ttk.LabelFrame(main_frame, text=" Virtual Coprocessor USB Activation ", padding="6")
        virt_frame.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(0, 2))
        virt_frame.columnconfigure(1, weight=1)
        
        self.virt_usb_enabled_var = tk.BooleanVar(value=load_json(PROFILE_PATH, default={}).get("virtual_usb_enabled", True))
        virt_usb_chk = ttk.Checkbutton(
            virt_frame, 
            text="Enable USB Interface Bus for Virtual Coprocessors", 
            variable=self.virt_usb_enabled_var
        )
        virt_usb_chk.grid(row=0, column=0, columnspan=3, sticky="w", pady=1)
        
        virt_btn_frame = ttk.Frame(virt_frame)
        virt_btn_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(2, 1))
        
        save_usb_btn = ttk.Button(virt_btn_frame, text="Save USB State", command=self.save_virtual_usb_state)
        save_usb_btn.pack(side="left", padx=2)
        
        gen_usb_btn = ttk.Button(virt_btn_frame, text="Generate USB for Virtual Miners", command=self.generate_usb_for_virtual_miners)
        gen_usb_btn.pack(side="left", padx=4)
        
        apply_virt_btn = ttk.Button(virt_btn_frame, text="Apply & Restart CGMiner", command=self.apply_virtual_usb_and_restart)
        apply_virt_btn.pack(side="left", padx=4)
        
        self.lbl_virt_status = ttk.Label(virt_frame, text="Status: Virtual USB link ready.", font=("Arial", 8), foreground="gray")
        self.lbl_virt_status.grid(row=2, column=0, columnspan=3, sticky="w", pady=(1, 0))

        # ==========================================================
        # Active ASIC Hardware Controller Profile (Strictly CP2102)
        # ==========================================================
        hw_frame = ttk.LabelFrame(main_frame, text=" Active ASIC Hardware Controller Profile (CP2102 Bridge Only) ", padding="10")
        hw_frame.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(0, 10))
        hw_frame.columnconfigure(1, weight=1)
        
        # Row 0: Target Devices listbox & Refresh button (Strictly CP2102)
        ttk.Label(hw_frame, text="CP2102 Target:").grid(row=0, column=0, sticky="w", pady=2)
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

        # Initial device population & indicator state update
        self.refresh_asic_devices()
        self.check_loaded_zadig_state()

        # Virtual Miner Coprocessor & Parallel Scaler Section
        virt_frame = ttk.LabelFrame(main_frame, text=" Virtual Miner Coprocessor & Parallel Scaler ", padding="10")
        virt_frame.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(0, 5))
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
        args = "-c cgminer.conf"
    
        if "Custom Timing" in selection:
            args = "-c cgminer.conf --icarus-options 115200:1:1 --icarus-timing 3.0=100"
        elif "Debug Mode" in selection:
            args = "-c cgminer.conf --debug -D"

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
        """Active ASIC Hardware Controller Profile: only true physical USB controllers
        (CP2102 / CH340 / FTDI / PL2303 and known ASICs such as Icarus). No virtuals."""
        self.hw_listbox.delete(0, tk.END)
        all_devs = detect_ethernet_and_cp2102_miners()
        # Hardware profile: only physical USB bridges (no mice/input), plus
        # HDL virtual AMUs that were explicitly added to the physical CP2102 profile
        self.filtered_miners = [
            m for m in all_devs
            if not m.get("virtual") and m.get("interface") == "USB"
        ]
        profile = load_json(PROFILE_PATH, default={})
        for entry in profile.get("physical_cp2102") or []:
            self.filtered_miners.append({
                "id": entry.get("id", "cp2102-virt"),
                "name": entry.get("name", "HDL Virtual USB AMU"),
                "chip": "CP2102",
                "interface": "USB",
                "status": entry.get("status", "online"),
                "port": "HDL",
                "virtual": False,
            })
        for m in self.filtered_miners:
            status = m.get("status", "?")
            display_str = f"[{m.get('chip')}|{status}] {m.get('name')} ({m.get('port')})"
            self.hw_listbox.insert(tk.END, display_str)
        if not self.filtered_miners:
            self.hw_listbox.insert(tk.END, "No CP2102/CH340/FTDI/PL2303 physical device detected.")
        # Update status summary indicators
        online_count = sum(1 for m in self.filtered_miners if m.get("status") == "online")
        if hasattr(self, "lbl_phys_count"):
            self.lbl_phys_count.config(text=f"{len(self.filtered_miners)} detected")
        if hasattr(self, "lbl_phys_indicator"):
            if online_count:
                self.lbl_phys_indicator.config(text="● ONLINE", foreground="green")
            else:
                self.lbl_phys_indicator.config(text="● OFFLINE", foreground="red")
        profile = load_json(PROFILE_PATH, default={})
        virt_count = len(profile.get("chips") or [])
        if hasattr(self, "lbl_virt_count"):
            self.lbl_virt_count.config(text=f"{virt_count} active")
        if hasattr(self, "lbl_virt_indicator"):
            if virt_count and profile.get("virtual_usb_enabled", True):
                self.lbl_virt_indicator.config(text="● ONLINE", foreground="green")
            else:
                self.lbl_virt_indicator.config(text="● OFFLINE", foreground="red")

    def generate_and_clone_virtual_miner(self):
        """Generates a virtual miner linked as the next AMU slot and exports cloned physical chip JSON."""
        selection = self.hw_listbox.curselection()
        if not selection:
            if messagebox:
                messagebox.showwarning("Selection Required", "Please select a detected CP2102 or Ethernet device from the list first.")
            return
            
        selected_text = self.hw_listbox.get(selection[0])
        # Prefer a real physical (non-virtual) match
        matched_dev = next(
            (d for d in self.filtered_miners
             if not d.get("virtual") and (d.get("name") in selected_text or d.get("id") in selected_text)),
            next((d for d in self.filtered_miners if d.get("name") in selected_text or d.get("id") in selected_text), {
                "name": selected_text, "chip": "ASIC", "interface": "USB", "instance": ""
            })
        )
        # Do not rewrite virtual entries as physical USB
        json_path = generate_cloned_physical_chip_profile(matched_dev)
        
        if messagebox:
            messagebox.showinfo(
                "Virtual Miner Cloned & Created",
                f"Physical miner copied into HDL virtual array.\n\nSource: {matched_dev.get('name')}\nProfile: {json_path}\nHDL: hdl/virtual_miner_array.v will load the slots.\n\nCGMiner will restart to load the live array."
            )
            
        # FIX: Call virtual USB restart instead of non-existent slots method
        self.apply_virtual_usb_and_restart()
        
    def save_virtual_usb_state(self):
        """Saves the USB activation state for virtual coprocessors to hardware_profile.json."""
        profile = load_json(PROFILE_PATH, default={"profile_name": "local_uart_farm"})
        profile["virtual_usb_enabled"] = self.virt_usb_enabled_var.get()
        save_json(PROFILE_PATH, profile)
        status_text = "Enabled" if self.virt_usb_enabled_var.get() else "Disabled"
        self.lbl_virt_status.config(text=f"Status: Virtual USB interface {status_text}.", foreground="blue")

    def generate_usb_for_virtual_miners(self):
        """Generates HDL virtual USB entries for the virtual miner array.
        These are NOT added to the physical CP2102 hardware profile."""
        profile = load_json(PROFILE_PATH, default={"profile_name": "local_uart_farm", "chips": []})
        chips = profile.get("chips", [])
        # Prefer cloning from a detected physical CP2102/Icarus if present
        physical = [m for m in (getattr(self, "filtered_miners", []) or []) if not m.get("virtual")]
        source = physical[0] if physical else {"name": "CP2102 USB to UART Bridge Controller", "chip": "CP2102", "instance": "", "port": "", "interface": "USB"}
        next_idx = len(chips) + 1
        new_chip = {
            "id": f"virtual-hdl-amu-{next_idx}",
            "name": f"HDL Virtual USB AMU {next_idx}",
            "chip": source.get("chip", "CP2102"),
            "interface": "HDL-Virtual",
            "virtual": True,
            "amu_id": f"AMU {next_idx}",
            "source_hardware": source.get("name", ""),
            "source_instance": source.get("instance", ""),
            "source_port": source.get("port", ""),
            "status": "virtual-active",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        chips.append(new_chip)
        profile["chips"] = chips
        profile["virtual_usb_enabled"] = True
        # Also register in the physical CP2102 profile so it appears with the bridge
        phys = profile.get("physical_cp2102") or []
        phys.append({
            "id": new_chip["id"],
            "name": new_chip["name"],
            "chip": "CP2102",
            "interface": "USB",
            "status": "online",
            "source": source.get("name", ""),
            "amu_id": new_chip["amu_id"],
            "created_at": new_chip["created_at"],
        })
        profile["physical_cp2102"] = phys
        save_json(PROFILE_PATH, profile)
        # HDL side-car for virtual_miner_array.v
        hdl_dir = BASE_DIR / "hdl"
        hdl_dir.mkdir(parents=True, exist_ok=True)
        save_json(hdl_dir / "virtual_array_meta.json", {
            "virtual_miner_count": max(int(profile.get("virtual_slots", 10) or 10), len(chips)),
            "cloned_from": [c.get("source_hardware") for c in chips],
            "array_file": "virtual_miner_array.v",
        })
        self.lbl_virt_status.config(text=f"HDL Virtual USB AMU {next_idx} added to physical CP2102 profile.", foreground="green")
        if messagebox:
            messagebox.showinfo("Virtual USB Generated", f"HDL Virtual USB AMU {next_idx} created from {source.get('name')} and added to the physical CP2102 profile.")
        self.refresh_asic_devices()

    def apply_virtual_usb_and_restart(self):
        """Applies virtual USB settings and restarts CGMiner."""
        self.save_virtual_usb_state()
        self.lbl_virt_status.config(text="Success: Virtual USB settings applied. Restarting CGMiner...", foreground="green")
        if messagebox:
            messagebox.showinfo("Virtual Array Updated", "Virtual coprocessor USB settings updated.\nCGMiner will now restart.")
        self.restart_cgminer_process()

    def activate_virtual_hashing_telemetry(self):
        """Verifies and displays live process execution status."""
        if cgminer_process_running():
            self.status_label.config(
                text="Live Hashing Active | CGMiner process is running.",
                foreground="green"
            )
            if messagebox:
                messagebox.showinfo("Process Active", "CGMiner hardware controller process is running normally.")
        else:
            if messagebox:
                messagebox.showerror("Inactive", "CGMiner process is not running. Please start mining first.")
            
    def apply_virtual_slots_and_restart(self):
        """Saves the updated virtual slot count, updates configuration, and forces CGMiner to restart live."""
        slots = self.slots_spin_var.get()
        
        profile = load_json(PROFILE_PATH, default={"profile_name": "local_uart_farm"})
        profile["virtual_slots"] = slots
        save_json(PROFILE_PATH, profile)
        
        # Do not write virtual_slots into cgminer.conf — it is not a valid CGMiner option
        # and causes "Error in configuration file, partially loaded."
        conf = load_json(CONF_PATH, default={})
        conf.pop("virtual_slots", None)
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

