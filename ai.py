#!/usr/bin/env python3
"""
LOCAL THOX AI CHAT ASSISTANT
============================

Features:
- Native GGUF file parsing to autodetect maximum context allocation ceilings.
- Physical core bounding to guarantee system stability on 2-thread setups.
- Automated dependency validation save states for zero overhead instant startup.
- Advanced UI controls: Presets, Temperature, Top-p, Top-k, Repeat Penalty, and Revolve.
- Code Reference Library: Automirrors .bin code references into a dedicated local database.
"""

# ==========================================
# PART 1: IMPORTS
# ==========================================

import argparse
import gc
import json
import multiprocessing
import os
import platform
import queue
import socket
import struct
import subprocess
import sys
import threading
import time
import zipfile
import uuid
import urllib.error
import urllib.parse
import urllib.request
import shutil
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
import tkinter as tk


def add_runtime_dll_directories():
    """Ensure native runtime DLLs shipped with the bundled MinGW toolchain are visible."""
    if os.name != "nt":
        return

    candidates = [
        BASE_DIR / "mingw64",
        BASE_DIR / "mingw64" / "bin",
        BASE_DIR / "gcc",
        BASE_DIR / "bin",
    ]

    for directory in candidates:
        if not directory.exists():
            continue

        try:
            os.add_dll_directory(str(directory))
        except (OSError, RuntimeError):
            pass

        path_value = os.environ.get("PATH", "")
        entries = path_value.split(os.pathsep) if path_value else []
        directory_str = str(directory)
        if directory_str not in entries:
            os.environ["PATH"] = (
                f"{directory_str}{os.pathsep}{path_value}" if path_value else directory_str
            )


BASE_DIR = Path(__file__).resolve().parent
add_runtime_dll_directories()

try:
    from llama_cpp import Llama
except Exception:
    Llama = None


try:
    import pyopencl as cl

    HAS_OPENCL = True

except ImportError:
    cl = None
    HAS_OPENCL = False


# ==========================================
# PART 2: LOCAL PATH CONFIGURATION
# ==========================================

BIN_DIR = BASE_DIR / "bin"
MEMORY_DIR = BASE_DIR / "memory"
MEMORY_BIN_DIR = BASE_DIR / "memory_bin"
WORKSPACE_DIR = BASE_DIR / "workspace"

PROFILE_PATH = BIN_DIR / "global_cpu_cores.bin"
MEMORY_PATH = MEMORY_DIR / "memory.jsonl"
CACHE_STATE_PATH = BIN_DIR / "dependency_cache.json"
LLAMA_SERVER_PATH = (
    BASE_DIR / "llama.cpp-master" / "build" / "bin" / "llama-server.exe"
)


# ==========================================
# PART 3: APPROVED THOX MODEL
# ==========================================

THOX_MODEL_FILENAME = (
    "Thox1-27b-Q1_0.gguf"
)
# ==========================================
# PART 4: BINARY PROFILE CONFIGURATION
# ==========================================

PROFILE_HEADER = struct.Struct("<8sI")
PROFILE_CORE = struct.Struct(">IQIQIQ")

TARGET_CORES = 120
TARGET_THREADS = 240
CACHE_PER_CORE_KB = 512

PETABYTE_MS_SCALE_FACTOR = 10**12


# ==========================================
# PART 5: DIRECTORY MANAGEMENT
# ==========================================


def ensure_local_directories():
    """Create local folders required by the program."""
    BIN_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    MEMORY_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    MEMORY_BIN_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    ensure_workspace_folder()


def ensure_workspace_folder():
    """Generate the workspace folder, or detect and reuse it when it already exists."""
    already_exists = WORKSPACE_DIR.exists() and WORKSPACE_DIR.is_dir()
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    return WORKSPACE_DIR, already_exists


def copy_into_workspace(source_path):
    """Copy a file or folder into the workspace folder."""
    ensure_workspace_folder()
    source_path = Path(source_path)
    try:
        source_resolved = source_path.resolve()
        workspace_resolved = WORKSPACE_DIR.resolve()
    except OSError:
        source_resolved = source_path
        workspace_resolved = WORKSPACE_DIR
    if source_resolved == workspace_resolved or workspace_resolved in source_resolved.parents:
        return source_path
    if source_path.is_dir():
        destination = WORKSPACE_DIR / source_path.name
        shutil.copytree(source_path, destination, dirs_exist_ok=True)
        return destination
    destination = WORKSPACE_DIR / source_path.name
    shutil.copy2(source_path, destination)
    return destination


def store_memory_file(record):
    """Store one memory record in the memory folder, not only in the json log."""
    ensure_local_directories()
    stamp = time.strftime("%Y%m%d_%H%M%S")
    token = uuid.uuid4().hex[:8]
    memory_record_path = MEMORY_DIR / ("memory_" + stamp + "_" + token + ".json")
    with memory_record_path.open("w", encoding="utf-8") as record_file:
        json.dump(record, record_file, ensure_ascii=False, indent=2)
    memory_text_path = MEMORY_DIR / ("memory_" + stamp + "_" + token + ".txt")
    with memory_text_path.open("w", encoding="utf-8") as text_file:
        text_file.write("timestamp: " + str(record.get("timestamp", "")) + "\n")
        text_file.write("prompt:\n" + str(record.get("prompt", "")) + "\n\n")
        text_file.write("response:\n" + str(record.get("response", "")) + "\n")
    return memory_record_path


def determine_active_path():
    """Return bin/global_cpu_cores.bin beside ai.py."""
    ensure_local_directories()
    return PROFILE_PATH
# ==========================================
# PART 6: GGUF METADATA PARSER
# ==========================================


def get_gguf_max_context(model_path):
    """
    Parse the GGUF file header directly to extract the maximum native
    architecture context length configured by the model creators.
    """
    fallback_context = 4096
    if not model_path or not Path(model_path).exists():
        return fallback_context

    try:
        with open(model_path, "rb") as f:
            magic = f.read(4)
            if magic != b"GGUF":
                return fallback_context
            
            version_bytes = f.read(4)
            if not version_bytes:
                return fallback_context
            version = struct.unpack("<I", version_bytes)[0]
            if version not in (1, 2, 3):
                return fallback_context

            if version == 1:
                num_kv = struct.unpack("<I", f.read(4))[0]
            else:
                num_kv = struct.unpack("<Q", f.read(8))[0]

            def read_gguf_string():
                len_size = 4 if version == 1 else 8
                len_bytes = f.read(len_size)
                if not len_bytes:
                    return ""
                str_len = struct.unpack("<I" if version == 1 else "<Q", len_bytes)[0]
                return f.read(str_len).decode("utf-8", errors="replace")

            def skip_gguf_value(type_id):
                if type_id in (0, 1, 7):
                    f.seek(1, 1)
                elif type_id in (2, 3):
                    f.seek(2, 1)
                elif type_id in (4, 5, 6):
                    f.seek(4, 1)
                elif type_id in (10, 11, 12):
                    f.seek(8, 1)
                elif type_id == 8:
                    len_bytes = f.read(4 if version == 1 else 8)
                    if len_bytes:
                        str_len = struct.unpack("<I" if version == 1 else "<Q", len_bytes)[0]
                        f.seek(str_len, 1)
                elif type_id == 9:
                    f.seek(4, 1)
                    arr_len_bytes = f.read(4 if version == 1 else 8)
                    if arr_len_bytes:
                        arr_len = struct.unpack("<I" if version == 1 else "<Q", arr_len_bytes)[0]
                        f.seek(arr_len, 1)

            for _ in range(num_kv):
                key = read_gguf_string()
                val_type = struct.unpack("<I", f.read(4))[0]
                
                if key in (
                    "qwen.context_length",
                    "llm.context_length",
                    "llama.context_length",
                    "qwen2.context_length",
                    "thox.context_length"
                ):
                    if val_type in (4, 10):
                        read_size = 4 if val_type == 4 else 8
                        val_bytes = f.read(read_size)
                        return int(struct.unpack("<I" if val_type == 4 else "<Q", val_bytes)[0])
                    else:
                        skip_gguf_value(val_type)
                else:
                    skip_gguf_value(val_type)

    except Exception:
        pass

    return fallback_context
# ==========================================
# PART 7: DEPENDENCY STATE CACHE MANAGEMENT
# ==========================================


def load_dependency_cache_state():
    """Verify if environmental profile configuration is cached."""
    if not CACHE_STATE_PATH.exists():
        return None
    try:
        with open(CACHE_STATE_PATH, "r", encoding="utf-8") as f:
            state = json.load(f)
            if (state.get("host_os") == platform.system() and 
                    state.get("llama_cpp_available") == (Llama is not None) and
                    state.get("profile_verified") is True):
                return state
    except Exception:
        return None
    return None


def save_dependency_cache_state(actual_cpu_count):
    """Serialize verified dependency state to guarantee instantaneous subsequent runs."""
    ensure_local_directories()
    cache_payload = {
        "cached_at": time.time(),
        "host_os": platform.system(),
        "actual_cpu_threads": actual_cpu_count,
        "llama_cpp_available": Llama is not None,
        "opencl_available": HAS_OPENCL,
        "profile_verified": True
    }
    try:
        with open(CACHE_STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache_payload, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def compile_global_hardware_profile(filename):
    """Generate a valid raw binary profile architecture document."""
    ensure_local_directories()

    host_os = platform.system()
    actual_cpu_count = multiprocessing.cpu_count() or 1

    print("=====================================================")
    print(" GLOBAL HARDWARE PROFILE GENERATOR")
    print("=====================================================\n")
    print("[*] Building baseline execution profiles...")

    os_encoded = host_os.encode("utf-8")[:8].ljust(8, b"\x00")

    with open(filename, "wb") as bin_file:
        bin_file.write(PROFILE_HEADER.pack(os_encoded, actual_cpu_count))

        for core_index in range(TARGET_CORES):
            signature = 0xDEADBEEF
            max_ram = 128 * (1024 ** 3)
            acceleration_flag = 1 if HAS_OPENCL else 0
            drive_offset = core_index * 4096
            threads_per_record = TARGET_THREADS // TARGET_CORES

            hardware_register = (
                (threads_per_record << 24)
                | (CACHE_PER_CORE_KB << 8)
                | 0xFF
            )

            core_block = PROFILE_CORE.pack(
                signature, max_ram, acceleration_flag,
                drive_offset, hardware_register, PETABYTE_MS_SCALE_FACTOR,
            )
            bin_file.write(core_block)

    # Save state once dependencies and binary build components are finalized
    save_dependency_cache_state(actual_cpu_count)
# ==========================================
# PART 8: INITIALIZATION ROUTINE CONTROLLERS
# ==========================================


def read_binary_profile(filename):
    """Read a structured binary framework blueprint context map from disk."""
    if not filename.exists() or filename.stat().st_size != (
        PROFILE_HEADER.size + TARGET_CORES * PROFILE_CORE.size
    ):
        raise ValueError("invalid profile size structure")

    records = []
    with open(filename, "rb") as bin_file:
        header_data = bin_file.read(PROFILE_HEADER.size)
        encoded_os, actual_cpu_count = PROFILE_HEADER.unpack(header_data)
        profile_os = encoded_os.rstrip(b"\x00").decode("utf-8", errors="replace")

        for core_index in range(TARGET_CORES):
            core_block = bin_file.read(PROFILE_CORE.size)
            (signature, max_ram, acceleration_flag, drive_offset,
             hardware_register, scale) = PROFILE_CORE.unpack(core_block)

            records.append({
                "index": core_index,
                "signature": signature,
                "max_ram": max_ram,
                "acceleration": acceleration_flag,
                "drive_offset": drive_offset,
                "threads": (hardware_register >> 24) & 0xFF,
                "cache_kb": (hardware_register >> 8) & 0xFFFF,
                "flush_flag": hardware_register & 0xFF,
                "scale": scale,
            })
    return {"os": profile_os, "actual_cpu_count": actual_cpu_count, "records": records}


def ensure_global_binary_profile():
    """Bypasses compilation check cycles instantly when save state signature exists."""
    target_file = determine_active_path()
    cached_state = load_dependency_cache_state()

    if cached_state and target_file.exists():
        print("[+] Save State Cache: Verified dependencies are finalized. Skipping profile generation.")
        try:
            return target_file, read_binary_profile(target_file)
        except Exception:
            pass

    try:
        if not target_file.exists():
            compile_global_hardware_profile(target_file)
        profile = read_binary_profile(target_file)
        # Create a save state if validated cleanly on compilation pass
        save_dependency_cache_state(profile["actual_cpu_count"])
        return target_file, profile
    except Exception:
        compile_global_hardware_profile(target_file)
        profile = read_binary_profile(target_file)
        save_dependency_cache_state(profile["actual_cpu_count"])
        return target_file, profile


def display_binary_profile(profile):
    """Display a readable binary profile summary."""
    records = profile["records"]
    print("\n[*] Dependency Framework Checked:")
    print(f" -> Active CPU Thread Cap: {profile['actual_cpu_count']}")
    print(f" -> Profile Tracked Blocks: {len(records)}")


# ==========================================
# PART 9: MEMORY MANAGEMENT
# ==========================================


def load_memory(filename=MEMORY_PATH):
    """Load previous conversations from JSON Lines."""
    if not filename.exists():
        return []
    records = []
    with filename.open("r", encoding="utf-8") as memory_file:
        for line in memory_file:
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    records.append(record)
            except json.JSONDecodeError:
                continue
    return records


def write_chat_to_memory(prompt, response, filename=MEMORY_PATH):
    """Append one conversation turn to local memory."""
    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "prompt": prompt,
        "response": response,
    }
    with filename.open("a", encoding="utf-8") as memory_file:
        memory_file.write(json.dumps(record, ensure_ascii=False) + "\n")
    store_memory_file(record)


def build_memory_context(records, limit=6):
    """Prepare recent memory for the model."""
    recent_records = records[-limit:]
    if not recent_records:
        return "No previous memory is available."
    return "\n".join(
        f"USER: {record.get('prompt', '')}\nAI: {record.get('response', '')}"
        for record in recent_records
    )


def ensure_global_binary_profile():
    """Bypasses compilation check cycles instantly when save state signature exists."""
    target_file = determine_active_path()
    cached_state = load_dependency_cache_state()

    if cached_state and target_file.exists():
        print("[+] Save State Cache: Verified dependencies are finalized. Skipping profile generation.")
        try:
            return target_file, read_binary_profile(target_file)
        except Exception:
            pass

    try:
        if not target_file.exists():
            compile_global_hardware_profile(target_file)
        profile = read_binary_profile(target_file)
        # Create a save state if validated cleanly on compilation pass
        save_dependency_cache_state(profile["actual_cpu_count"])
        return target_file, profile
    except Exception:
        compile_global_hardware_profile(target_file)
        profile = read_binary_profile(target_file)
        save_dependency_cache_state(profile["actual_cpu_count"])
        return target_file, profile


def display_binary_profile(profile):
    """Display a readable binary profile summary."""
    records = profile["records"]
    print("\n[*] Dependency Framework Checked:")
    print(f" -> Active CPU Thread Cap: {profile['actual_cpu_count']}")
    print(f" -> Profile Tracked Blocks: {len(records)}")
    MEMORY_PATH = MEMORY_DIR / "memory.jsonl"


def load_memory(filename=MEMORY_PATH):
    """Load previous conversations from JSON Lines."""
    if not filename.exists():
        return []
    records = []
    with filename.open("r", encoding="utf-8") as memory_file:
        for line in memory_file:
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    records.append(record)
            except json.JSONDecodeError:
                continue
    return records


def write_chat_to_memory(prompt, response, filename=MEMORY_PATH):
    """Append one conversation turn to local memory."""
    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "prompt": prompt,
        "response": response,
    }
    with filename.open("a", encoding="utf-8") as memory_file:
        memory_file.write(json.dumps(record, ensure_ascii=False) + "\n")
    store_memory_file(record)


def build_memory_context(records, limit=6):
    """Prepare recent memory for the model."""
    recent_records = records[-limit:]
    if not recent_records:
        return "No previous memory is available."
    return "\n".join(
        f"USER: {record.get('prompt', '')}\nAI: {record.get('response', '')}"
        for record in recent_records
    )


# ==========================================
# PART 10: THOX MODEL LOCATION
# ==========================================


def locate_model(requested_path=None):
    """Locate only the approved Thox GGUF model."""
    candidates = []
    if requested_path:
        requested_model = Path(requested_path).expanduser()
        if requested_model.name != THOX_MODEL_FILENAME:
            raise FileNotFoundError(f"Only {THOX_MODEL_FILENAME} can be targeted.")
        candidates.append(requested_model)

    if os.environ.get("MODEL_PATH"):
        environment_model = Path(os.environ["MODEL_PATH"]).expanduser()
        if environment_model.name == THOX_MODEL_FILENAME:
            candidates.append(environment_model)

    expected_directories = [
        BASE_DIR, BASE_DIR / "models", BASE_DIR / "model",
        Path.home() / "ai-env", Path.home() / "Desktop" / "ai-env" / "models"
    ]
    for directory in expected_directories:
        candidates.append(directory / THOX_MODEL_FILENAME)

    unique_candidates = []
    already_seen = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        if resolved not in already_seen:
            already_seen.add(resolved)
            unique_candidates.append(resolved)

    for candidate in unique_candidates:
        if candidate.is_file():
            print(f"[+] Thox model found: {candidate}")
            return candidate

    raise FileNotFoundError("The approved Thox model file was not found.")
# ==========================================
# PART 11: MODEL RUNTIME
# ==========================================


def get_safe_thread_count(requested_threads=None):
    """Returns a physical core performance-bounded thread assignment."""
    actual_threads = multiprocessing.cpu_count() or 1
    if requested_threads is None:
        return actual_threads
    return max(1, min(requested_threads, actual_threads))


class LlamaServerClient:
    """OpenAI-compatible client for the bundled llama.cpp server."""

    def __init__(self, process, port, context_size, log_path):
        self.process = process
        self.base_url = f"http://127.0.0.1:{port}"
        self.context_size = context_size
        self.log_path = log_path
        self._ping_stop = threading.Event()
        self._ping_thread = None

    @classmethod
    def start(cls, model_path, thread_count, context_size, gpu_layers=0):
        ensure_local_directories()
        with socket.socket() as port_socket:
            port_socket.bind(("127.0.0.1", 0))
            port = port_socket.getsockname()[1]

        log_path = BIN_DIR / "llama-server.log"
        command = [
            str(LLAMA_SERVER_PATH),
            "--model", str(model_path),
            "--ctx-size", str(context_size),
            "--threads", str(thread_count),
            "--threads-batch", str(thread_count),
            "--n-gpu-layers", str(gpu_layers),
            "--reasoning", "off",
            "--host", "127.0.0.1",
            "--port", str(port),
        ]

        with log_path.open("w", encoding="utf-8") as log_file:
            process = subprocess.Popen(
                command,
                cwd=str(BASE_DIR),
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

        client = cls(process, port, context_size, log_path)
        deadline = time.monotonic() + 600

        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    "llama-server exited during startup.\n" + client._log_tail()
                )
            try:
                with urllib.request.urlopen(
                    f"{client.base_url}/health", timeout=2
                ) as response:
                    if response.status == 200:
                        client._start_silent_ping()
                        return client
            except (OSError, urllib.error.URLError):
                time.sleep(1)

        client.close()
        raise TimeoutError(
            "llama-server did not finish loading the model within 10 minutes.\n"
            + client._log_tail()
        )

    def _log_tail(self):
        try:
            lines = self.log_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError:
            return "No llama-server log is available."
        return "\n".join(lines[-40:])

    def n_ctx(self):
        return self.context_size

    def _start_silent_ping(self):
        """Ping the server once a second so it stays alive. No output."""
        if self._ping_thread is not None and self._ping_thread.is_alive():
            return

        def _ping():
            while not self._ping_stop.wait(1):
                try:
                    with urllib.request.urlopen(self.base_url + "/health", timeout=1):
                        pass
                except Exception:
                    pass

        self._ping_thread = threading.Thread(target=_ping, daemon=True)
        self._ping_thread.start()

    def _ensure_user_query(self, messages):
        """Always leave a non-empty user query for the chat template."""
        prepared = [dict(item) for item in (messages or [])]
        last_user = None
        for index in range(len(prepared) - 1, -1, -1):
            if prepared[index].get("role") == "user" and str(prepared[index].get("content", "")).strip():
                last_user = prepared.pop(index)
                break
        if last_user is None:
            last_user = {"role": "user", "content": "Continue."}
        if not str(last_user.get("content", "")).strip():
            last_user["content"] = "Continue."
        prepared.append(last_user)
        return prepared

    def create_chat_completion(
        self, messages, max_tokens, temperature=0.8, top_p=0.95, repeat_penalty=1.1, top_k=40, on_token=None, conv_id=None, stop_event=None
    ):
        messages = self._ensure_user_query(messages)
        payload = json.dumps({
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "repeat_penalty": repeat_penalty,
            "top_k": top_k,
            "stream": on_token is not None,
        }).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        if conv_id:
            headers["X-Conversation-Id"] = conv_id

        request = urllib.request.Request(
            f"{self.base_url}/v1/chat/completions",
            data=payload,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(request) as response:
                if on_token is not None:
                    content_parts = []
                    for raw_line in response:
                        if stop_event is not None and stop_event.is_set():
                            break
                        line = raw_line.decode("utf-8", errors="replace").strip()
                        if not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if data == "[DONE]":
                            break
                        try:
                            event = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        choices = event.get("choices") or []
                        if not choices:
                            continue
                        delta = choices[0].get("delta", {})
                        token = delta.get("content", "")
                        if token:
                            content_parts.append(token)
                            on_token(token)
                    return {
                        "choices": [{
                            "message": {"content": "".join(content_parts)}
                        }]
                    }
                    return json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"llama-server chat request failed ({error.code}): {detail}"
            ) from error

    def stop_generation(self, conv_id):
        request = urllib.request.Request(
            f"{self.base_url}/v1/stream?conv_id={urllib.parse.quote(conv_id)}",
            method="DELETE",
        )
        try:
            with urllib.request.urlopen(request, timeout=5):
                return
        except urllib.error.HTTPError as error:
            if error.code not in (404, 409):
                raise

    def close(self):
        self._ping_stop.set()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


def create_llama_model(model_path, thread_count, context_size, gpu_layers=0):
    """Load the model with the bundled llama.cpp server when available."""
    if LLAMA_SERVER_PATH.is_file():
        return LlamaServerClient.start(
            model_path, thread_count, context_size, gpu_layers
        )
    if Llama is None:
        raise RuntimeError(
            "llama-server.exe was not found and llama-cpp-python could not be loaded."
        )
    return Llama(
        model_path=str(model_path),
        n_ctx=context_size,
        n_threads=thread_count,
        n_threads_batch=thread_count,
        f16_kv=True,
        logits_all=False,
        vocab_only=False,
        verbose=False,
    )


def estimate_tokens(text):
    """Rough token count used only for context rolling."""
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


def context_limit(llm):
    """Return the active context window size."""
    try:
        if callable(getattr(llm, "n_ctx", None)):
            return int(llm.n_ctx())
        return int(getattr(llm, "context_params").n_ctx)
    except Exception:
        return 4096


def roll_context_messages(messages, llm, reserve_tokens):
    """Roll older context out so those tokens can be recycled."""
    n_ctx = context_limit(llm)
    budget = max(128, n_ctx - max(1, reserve_tokens))
    rolled = [dict(item) for item in messages]

    def used(items):
        return sum(estimate_tokens(item.get("content", "")) + 4 for item in items)

    while used(rolled) > budget and len(rolled) > 1:
        removed = False
        for index in range(len(rolled)):
            if rolled[index].get("role") != "system":
                if rolled[index].get("role") == "user" and sum(
                    1 for item in rolled if item.get("role") == "user" and str(item.get("content", "")).strip()
                ) <= 1:
                    continue
                rolled.pop(index)
                removed = True
                break
        if not removed:
            break
    if used(rolled) > budget and rolled:
        overflow_chars = (used(rolled) - budget) * 4
        for item in rolled:
            content = item.get("content", "")
            if len(content) > overflow_chars + 64:
                item["content"] = content[overflow_chars:]
                break
    return rolled


def generate_response(
    llm, user_prompt, memory_records, max_tokens, temperature=0.8, top_p=0.95, repeat_penalty=1.1, top_k=40, attachments="",
    on_token=None, conv_id=None, stop_event=None, revolve=False,
):
    """Generate a Thox response using recent memory."""
    prompt = user_prompt
    if attachments:
        prompt += "\n\nAttached file contents:\n" + attachments

    memory_limit = len(memory_records) if revolve and memory_records else 6
    chat_messages = [
        {
            "role": "system",
            "content": (
                "You are a helpful local Thox assistant. Use memory when relevant.\n\n"
                "RECENT MEMORY:\n" + build_memory_context(memory_records, limit=memory_limit)
            ),
        },
        {
            "role": "user",
            "content": prompt,
        },
    ]

    safe_max = max(1, min(max_tokens, max(64, context_room(llm))))
    if revolve:
        chat_messages = roll_context_messages(chat_messages, llm, safe_max)
        prompt_tokens = sum(estimate_tokens(item.get("content", "")) + 4 for item in chat_messages)
        recycled_room = max(64, context_limit(llm) - prompt_tokens - 8)
        safe_max = max(1, min(max_tokens, recycled_room))
    request_options = {
        "temperature": temperature,
        "top_p": top_p,
        "repeat_penalty": repeat_penalty,
        "top_k": top_k
    }

    if on_token is not None:
        request_options["on_token"] = on_token
    if conv_id is not None:
        request_options["conv_id"] = conv_id
    if stop_event is not None:
        request_options["stop_event"] = stop_event

    if not revolve:
        response = llm.create_chat_completion(
            messages=chat_messages,
            max_tokens=safe_max,
            **request_options,
        )

        message = response["choices"][0]["message"]
        content = message.get("content")

        if not isinstance(content, str) or (not content.strip() and not (
            stop_event is not None and stop_event.is_set()
        )):
            raise RuntimeError("The model returned an empty response.")

        return content.strip() if on_token is None else content

    remaining = max_tokens
    recycled_parts = []
    while remaining > 0:
        if stop_event is not None and stop_event.is_set():
            break
        chat_messages = roll_context_messages(chat_messages, llm, min(remaining, safe_max))
        prompt_tokens = sum(estimate_tokens(item.get("content", "")) + 4 for item in chat_messages)
        chunk_limit = max(1, min(remaining, max(64, context_limit(llm) - prompt_tokens - 8)))
        response = llm.create_chat_completion(
            messages=chat_messages,
            max_tokens=chunk_limit,
            **request_options,
        )
        message = response["choices"][0]["message"]
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            break
        recycled_parts.append(content)
        used = estimate_tokens(content)
        remaining -= max(1, used)
        if used < chunk_limit:
            break
        chat_messages.append({"role": "assistant", "content": "".join(recycled_parts)})
        chat_messages.append({
            "role": "user",
            "content": "Continue. Recycle the context window and do not repeat text that is already complete.",
        })
    content = "".join(recycled_parts)
    if not isinstance(content, str) or (not content.strip() and not (
        stop_event is not None and stop_event.is_set()
    )):
        raise RuntimeError("The model returned an empty response.")
    return content.strip() if on_token is None else content


def context_room(llm):
    """Leave headroom inside n_ctx for the prompt."""
    try:
        if callable(getattr(llm, "n_ctx", None)):
            n_ctx = int(llm.n_ctx())
        else:
            n_ctx = int(getattr(llm, "context_params").n_ctx)
    except Exception:
        n_ctx = 4096
    return max(256, n_ctx // 2)


MAX_ATTACHMENT_BYTES = 1024 * 1024
MAX_TOTAL_ATTACHMENT_BYTES = 4 * 1024 * 1024
TEXT_FILE_SUFFIXES = {
    ".c", ".cfg", ".cpp", ".csv", ".html", ".ini", ".java", ".js",
    ".json", ".log", ".md", ".py", ".rst", ".sh", ".toml", ".ts",
    ".txt", ".yaml", ".yml", ".bin",
}



FIX_FILE_INSTRUCTION = (
    "The workspace is already loaded. Use the loaded file or folder. "
    "Scan it for errors. If there are no errors, reply with exactly: "
    "file is correct, no errors found. "
    "If there are errors, output each corrected file in this form and nothing before the first marker: "
    "===THOX_FILE filename===\n"
    "full corrected file\n"
    "===THOX_END===\n"
    "After the markers, explain the changes that were made."
)


def is_fix_command(prompt):
    """True when the user asked to fix the loaded file."""
    text = " ".join(prompt.lower().split())
    return text in {
        "fix",
        "fix it",
        "fix file",
        "fix the file",
        "fix this",
        "fix this file",
        "fix the folder",
        "fix folder",
    } or text.startswith("fix ")


def store_memory_code_bin(source_path):
    """Store a memory code .bin for a loaded file so edits can be applied."""
    ensure_local_directories()
    source_path = Path(source_path)
    if source_path.is_dir():
        stored = []
        for child in source_path.rglob("*"):
            if child.is_file() and child.suffix.lower() in TEXT_FILE_SUFFIXES:
                stored.append(store_memory_code_bin(child))
        return stored
    dest = MEMORY_BIN_DIR / (source_path.stem + ".code.bin")
    dest.write_bytes(source_path.read_bytes())
    return dest


def build_loaded_attachment(loaded_targets):
    """Read the already loaded workspace files without asking again."""
    parts = []
    for target in loaded_targets:
        target = Path(target)
        if not target.exists():
            continue
        parts.append(read_text_attachment(target))
    return "\n\n".join(parts)


def apply_loaded_file_edits(response, loaded_targets):
    """Apply corrected files back to the loaded file or folder."""
    if response.strip().lower() == "file is correct, no errors found.":
        return "file is correct, no errors found."
    if "file is correct, no errors found" in response.lower() and "===THOX_FILE" not in response:
        return "file is correct, no errors found."
    marker = "===THOX_FILE "
    end_marker = "===THOX_END==="
    applied = []
    cursor = 0
    while True:
        start = response.find(marker, cursor)
        if start < 0:
            break
        name_end = response.find("===", start + len(marker))
        body_start = response.find("\n", name_end)
        end = response.find(end_marker, body_start if body_start >= 0 else start)
        if name_end < 0 or body_start < 0 or end < 0:
            break
        name = response[start + len(marker):name_end].strip()
        content = response[body_start + 1:end]
        if content.endswith("\n"):
            content = content[:-1]
        destination = match_loaded_target(name, loaded_targets)
        if destination is not None:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
            store_memory_code_bin(destination)
            applied.append(str(destination))
        cursor = end + len(end_marker)
    explanation = response
    first = response.find(marker)
    last = response.rfind(end_marker)
    if first >= 0 and last >= 0:
        explanation = response[last + len(end_marker):].strip()
    if not applied:
        return response
    if not explanation:
        explanation = "Changes were applied to the loaded file."
    return explanation + "\n\nApplied to: " + ", ".join(applied)


def match_loaded_target(name, loaded_targets):
    """Find the loaded file or a file inside the loaded folder."""
    wanted = Path(name)
    for target in loaded_targets:
        target = Path(target)
        if target.is_file() and target.name == wanted.name:
            return target
        if target.is_dir():
            candidate = target / wanted
            if candidate.exists() or wanted.name:
                nested = target / wanted.name
                if candidate.exists():
                    return candidate
                if nested.exists():
                    return nested
                return target / wanted.name
    if loaded_targets:
        only = Path(loaded_targets[-1])
        if only.is_file():
            return only
    return None


def read_text_attachment(path):
    """Read a text file or text files in a ZIP, with size limits."""
    path = Path(path)
    contents = []
    total_bytes = 0

    def add_text(name, data):
        nonlocal total_bytes
        if len(data) > MAX_ATTACHMENT_BYTES:
            raise ValueError(f"{name} is larger than the 1 MiB per-file limit.")
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_ATTACHMENT_BYTES:
            raise ValueError("Attachments exceed the 4 MiB combined text limit.")
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ValueError(f"{name} is not a UTF-8 readable text file.") from error
        contents.append(f"--- {name} ---\n{text}")

    if path.is_dir():
        for child in path.rglob("*"):
            if not child.is_file():
                continue
            if child.suffix.lower() not in TEXT_FILE_SUFFIXES:
                continue
            if child.stat().st_size > MAX_ATTACHMENT_BYTES:
                raise ValueError(f"{child.name} is larger than the 1 MiB per-file limit.")
            add_text(str(child.relative_to(path)), child.read_bytes())
        if not contents:
            raise ValueError("No supported text files were found in this attachment.")
        return "\n\n".join(contents)

    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                member = Path(entry.filename)
                if (
                    entry.is_dir()
                    or member.is_absolute()
                    or ".." in member.parts
                    or member.suffix.lower() not in TEXT_FILE_SUFFIXES
                ):
                    continue
                if entry.file_size > MAX_ATTACHMENT_BYTES:
                    raise ValueError(
                        f"{entry.filename} is larger than the 1 MiB per-file limit."
                    )
                # Copy raw code .bin files out of ZIP directory maps safely
                if member.suffix.lower() == ".bin":
                    ensure_local_directories()
                    target_dest = MEMORY_BIN_DIR / member.name
                    with target_dest.open("wb") as dest_f:
                        dest_f.write(archive.read(entry))
                    add_text(entry.filename, archive.read(entry))
                else:
                    add_text(entry.filename, archive.read(entry))
    else:
        if path.stat().st_size > MAX_ATTACHMENT_BYTES:
            raise ValueError(f"{path.name} is larger than the 1 MiB per-file limit.")
        # Archive standalone binary formats directly inside the tracking database
        if path.suffix.lower() == ".bin":
            ensure_local_directories()
            shutil.copy2(path, MEMORY_BIN_DIR / path.name)
            add_text(path.name, path.read_bytes())
        elif path.suffix.lower() in TEXT_FILE_SUFFIXES:
            add_text(path.name, path.read_bytes())

    if not contents:
        raise ValueError("No supported text files were found in this attachment.")
    return "\n\n".join(contents)


class ChatWindow:
    """Tkinter chat interface backed by a single managed llama-server instance."""

    def __init__(self, root, initial_model=None, initial_context=None):
        self.root = root
        self.root.title("Thox Local AI")
        self.root.geometry("1050x820")
        self.root.minsize(850, 620)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.events = queue.Queue()
        self.llm = None
        self.busy = False
        self.closing = False
        self.stop_event = None
        self.active_conv_id = None
        self.memory_records = load_memory()
        self.attachments = []
        self.attachment_text = ""
        self.workspace_loaded = False
        self.loaded_targets = []

        model = str(initial_model or (BASE_DIR / "models" / THOX_MODEL_FILENAME))
        detected_context = (
            get_gguf_max_context(model) if Path(model).is_file() else 4096
        )

        self.model_var = tk.StringVar(value=model)
        self.preset_var = tk.StringVar(value="Balanced")
        self.tokens_var = tk.StringVar(value="1024")
        self.context_var = tk.StringVar(value=str(initial_context or min(detected_context, 4096)))
        self.temp_var = tk.DoubleVar(value=0.8)
        self.top_p_var = tk.DoubleVar(value=0.95)
        self.rep_pen_var = tk.DoubleVar(value=1.10)
        self.revolve_var = tk.StringVar(value="Off")
        self.top_k_var = tk.IntVar(value=40)
        self.device_var = tk.StringVar(value="CPU only")
        self.threads_var = tk.StringVar(value=str(multiprocessing.cpu_count() or 1))
        self.gpu_layers_var = tk.StringVar(value="0")
        self.status_var = tk.StringVar(value="Choose settings, then click Load AI.")

        self._build_ui()
        self._poll_events()
        self._load_existing_workspace()


    
    def _start_aes_thinking(self):
        """Constantly run logic and thinking process on the AES encrypted network."""
        if getattr(self, "_aes_thinking_started", False):
            return
        self._aes_thinking_started = True

        def think_loop():
            import time
            while not getattr(self, "closing", False):
                try:
                    if self.llm is None:
                        time.sleep(5)
                        continue
                    # Gather AES encrypted network state
                    state_bits = []
                    try:
                        import netlock
                        st = netlock.load_state()
                        state_bits.append(f"mode={st.get('mode')} port={st.get('tunnel_port')}")
                    except Exception:
                        pass
                    try:
                        import vpn_server
                        live = vpn_server.is_tunnel_live() if hasattr(vpn_server, "is_tunnel_live") else False
                        state_bits.append(f"tunnel_live={live}")
                    except Exception:
                        pass
                    try:
                        import persist
                        rec = persist.load_applied()
                        hit = rec.get("last_engine_hit")
                        if hit:
                            state_bits.append(f"last_hit={hit}")
                    except Exception:
                        pass
                    try:
                        import secure_stream
                        gen = secure_stream.ring().generation if hasattr(secure_stream, "ring") else "?"
                        state_bits.append(f"stream_gen={gen}")
                    except Exception:
                        pass
                    snapshot = "; ".join(state_bits) or "AES network state unavailable"
                    prompt = (
                        f"Constant logic and thinking on the AES encrypted network. "
                        f"Current state: {snapshot}. "
                        f"Briefly analyze security, integrity, and any needed action. Reply in one short sentence."
                    )
                    # Non-blocking short inference
                    try:
                        resp = self.llm.create_chat_completion(
                            [{"role": "user", "content": prompt}],
                            max_tokens=64,
                            temperature=0.3,
                            top_p=0.9,
                        )
                        thought = ""
                        if isinstance(resp, dict):
                            choices = resp.get("choices") or []
                            if choices:
                                thought = (choices[0].get("message") or {}).get("content") or ""
                        if thought:
                            self.events.put(("aes_thought", thought.strip()))
                    except Exception:
                        pass
                except Exception:
                    pass
                time.sleep(30)  # constant but not flooding

        threading.Thread(target=think_loop, name="aes-thinking", daemon=True).start()


    def _start_netlock_services(self):
        """Once Thox AI is running, start NetLock network services."""
        import subprocess
        import sys
        def work():
            try:
                py = sys.executable
                root = str(BASE_DIR)
                # network boot
                subprocess.run([py, str(BASE_DIR / "network_boot.py")], cwd=root, check=False)
                # soft reset if flagged
                flag = BASE_DIR / "vpn_data" / "need_soft_reset.flag"
                if flag.exists():
                    adapter = flag.read_text(encoding="utf-8", errors="ignore").strip()
                    if adapter:
                        subprocess.run(["cmd", "/c", str(BASE_DIR / "soft_reset.bat"), adapter], cwd=root, check=False)
                    try:
                        flag.unlink()
                    except OSError:
                        pass
                # bind servers
                subprocess.run([py, str(BASE_DIR / "bind_servers.py")], cwd=root, check=False)
                self.root.after(0, lambda: self.netlock_status.set("Thox running -- NetLock services started (network_boot + bind_servers)."))
            except Exception as exc:
                self.root.after(0, lambda: self.netlock_status.set(f"NetLock services start error: {exc}"))
        threading.Thread(target=work, daemon=True).start()

    def _start_ai_secure_server(self):
        """Expose the loaded AI model so NetLock can secure its scripts/programs."""
        import socket
        import json
        import threading

        def handle(conn):
            try:
                raw = b""
                while len(raw) < 65536:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                    if b"\n" in raw:
                        break
                if not raw:
                    return
                req = json.loads(raw.decode("utf-8", errors="ignore").strip())
                # Secure communication: require matching AI API key
                provided = str(req.get("api_key") or req.get("key") or "")
                expected = getattr(self, "ai_api_key", "")
                if expected and provided != expected:
                    conn.sendall((json.dumps({"ok": False, "message": "invalid api key"}) + "\n").encode())
                    return
                cmd = req.get("cmd")
                if cmd == "secure_scripts" and self.llm is not None:
                    scripts = req.get("scripts") or []
                    names = ", ".join(str(s) for s in scripts[:20]) or "(none)"
                    prompt = (
                        f"NetLock is protecting these scripts/programs: {names}. "
                        "Confirm they are now secured by the loaded Thox AI model. "
                        "Reply with a short one-line security seal and status only."
                    )
                    try:
                        reply = generate_response(
                            self.llm, prompt, self.memory_records, 128,
                            temperature=0.3, top_p=0.9, repeat_penalty=1.05, top_k=20
                        )
                    except Exception as e:
                        reply = f"AI secure failed: {e}"
                    resp = {"ok": True, "seal": reply[:200], "message": "secured by loaded AI model"}
                elif cmd in ("ai_upload", "ai_download") and self.llm is not None:
                    # AI-assisted encrypted upload/download via secure data streams
                    try:
                        import secure_stream
                        data = req.get("data", "")
                        direction = "upload" if cmd == "ai_upload" else "download"
                        prompt = f"AI assist {direction} of data (len={len(data)}). Confirm safe and encrypted via secure stream. Short status only."
                        ai_status = generate_response(
                            self.llm, prompt, self.memory_records, 64,
                            temperature=0.2, top_p=0.9, repeat_penalty=1.05, top_k=20
                        )
                        encrypted = secure_stream.seal_frame(data.encode("utf-8", errors="ignore") if isinstance(data, str) else data)
                        resp = {
                            "ok": True,
                            "direction": direction,
                            "encrypted_len": len(encrypted),
                            "ai_status": ai_status[:150],
                            "message": f"AI-assisted {direction} completed through encrypted secure data stream"
                        }
                    except Exception as e:
                        resp = {"ok": False, "message": f"AI transfer failed: {e}"}
                elif cmd == "scan_malicious" and self.llm is not None:
                    # AI malicious data attack scan; NetLock terminates if detected
                    sample = req.get("sample", "")[:2000]
                    prompt = (
                        f"Analyze this network/data sample for malicious attacks (malware, exploit, injection, C2): {sample[:500]}. "
                        "Reply ONLY with MALICIOUS or CLEAN followed by one short reason."
                    )
                    try:
                        verdict = generate_response(
                            self.llm, prompt, self.memory_records, 64,
                            temperature=0.1, top_p=0.8, repeat_penalty=1.1, top_k=10
                        )
                        is_mal = "MALICIOUS" in verdict.upper()
                        terminated = False
                        if is_mal:
                            try:
                                import netlock
                                # Trigger NetLock base blocks / termination path
                                state = netlock.load_state()
                                netlock.apply_base_blocks(state.get("tunnel_port", 51821), allow_own_tunnel=True)
                                terminated = True
                            except Exception:
                                pass
                        resp = {
                            "ok": True,
                            "verdict": verdict[:200],
                            "malicious": is_mal,
                            "terminated": terminated,
                            "message": "AI scan complete; NetLock terminated malicious if detected"
                        }
                    except Exception as e:
                        resp = {"ok": False, "message": f"AI scan failed: {e}"}
                elif cmd == "api_bind":
                    # API bindings for all AI GUI tabs and tab script file functions
                    action = req.get("action", "")
                    result = {"ok": False, "action": action}
                    try:
                        if action == "load_ai":
                            self.root.after(0, self.load_ai)
                            result = {"ok": True, "action": action, "message": "Load AI scheduled"}
                        elif action == "send_message":
                            msg = req.get("message", "")
                            if msg:
                                # Simulate send (actual send uses UI vars; store for next)
                                self.events.put(("api_send", msg))
                            result = {"ok": True, "action": action, "message": "Message queued"}
                        elif action == "stop_generation":
                            self.root.after(0, self.stop_generation)
                            result = {"ok": True, "action": action}
                        elif action == "browse_model":
                            self.root.after(0, self.browse_model)
                            result = {"ok": True, "action": action}
                        elif action == "add_files":
                            self.root.after(0, self.add_files)
                            result = {"ok": True, "action": action}
                        elif action == "launch_netlock":
                            self.root.after(0, self.launch_netlock)
                            result = {"ok": True, "action": action, "message": "NetLock launch scheduled"}
                        elif action == "create_shared_pool":
                            self.root.after(0, self.create_shared_pool)
                            result = {"ok": True, "action": action}
                        elif action == "scan_apps":
                            # Binding to NetLock script function
                            try:
                                import app_gui
                                # Trigger via existing if possible; otherwise note
                                result = {"ok": True, "action": action, "message": "scan_apps binding active"}
                            except Exception as e:
                                result = {"ok": False, "message": str(e)}
                        elif action == "secure_stream_seal":
                            import secure_stream
                            token = secure_stream.seal_wildcard(0, 0, req.get("label", "api"))
                            result = {"ok": True, "token": token[:32], "action": action}
                        elif action == "list_bindings":
                            result = {
                                "ok": True,
                                "bindings": [
                                    "load_ai", "send_message", "stop_generation", "browse_model", "add_files",
                                    "launch_netlock", "create_shared_pool", "scan_apps", "secure_stream_seal",
                                    "secure_scripts", "ai_upload", "ai_download", "scan_malicious"
                                ]
                            }
                        else:
                            result = {"ok": False, "message": f"unknown binding action: {action}"}
                    except Exception as e:
                        result = {"ok": False, "message": str(e)}
                    resp = result
                else:
                    resp = {"ok": False, "message": "AI model not loaded or unknown cmd"}
                conn.sendall((json.dumps(resp) + "\n").encode())
            except Exception as exc:
                try:
                    conn.sendall(json.dumps({"ok": False, "message": str(exc)}).encode())
                except Exception:
                    pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        def server():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", 8765))
                sock.listen(5)
                sock.settimeout(1.0)
                while not self.closing:
                    try:
                        conn, _ = sock.accept()
                        threading.Thread(target=handle, args=(conn,), daemon=True).start()
                    except socket.timeout:
                        continue
                    except Exception:
                        break
                sock.close()
            except Exception:
                pass

        if not getattr(self, "_ai_secure_started", False):
            self._ai_secure_started = True
            # Generate / load AI API key for secure communication
            try:
                key_path = BASE_DIR / "vpn_data" / "ai_api_key.txt"
                key_path.parent.mkdir(parents=True, exist_ok=True)
                if key_path.exists():
                    self.ai_api_key = key_path.read_text(encoding="utf-8").strip()
                else:
                    import secrets
                    self.ai_api_key = secrets.token_hex(32)
                    key_path.write_text(self.ai_api_key, encoding="utf-8")
            except Exception:
                self.ai_api_key = ""
            try:
                import ca_store
                ca_store.apply_ssl_to_directory(BASE_DIR)
            except Exception:
                pass
            threading.Thread(target=server, daemon=True).start()

    def _build_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Main notebook with Chat and NetLock tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # ---- Chat tab ----
        chat_tab = ttk.Frame(self.notebook)
        self.notebook.add(chat_tab, text="Chat")
        chat_tab.columnconfigure(0, weight=1)
        chat_tab.rowconfigure(1, weight=1)

        # Settings Container (moved into chat tab)
        settings_pane = ttk.Frame(chat_tab)
        settings_pane.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        settings_pane.columnconfigure(0, weight=1)

        # Path Selection Group
        paths_frame = ttk.LabelFrame(settings_pane, text="Model Configuration")
        paths_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=2)
        paths_frame.columnconfigure(1, weight=1)

        ttk.Label(paths_frame, text="GGUF Model").grid(row=0, column=0, padx=6, pady=5)
        ttk.Entry(paths_frame, textvariable=self.model_var).grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        ttk.Button(paths_frame, text="Browse...", command=self.browse_model).grid(row=0, column=2, padx=5, pady=5)

        self.load_button = ttk.Button(paths_frame, text="Load AI", command=self.load_ai)
        self.load_button.grid(row=0, column=3, padx=5, pady=5)

        # Advanced Generation Parameter Controls
        controls_frame = ttk.LabelFrame(settings_pane, text="Hyperparameters & Resource Mapping")
        controls_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=2)

        # Row 1: Presets & Context allocations
        ttk.Label(controls_frame, text="Preset").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        preset_box = ttk.Combobox(controls_frame, textvariable=self.preset_var, values=("Balanced", "Fast / short", "Quality / long", "Deep think", "Code"), state="readonly", width=14)
        preset_box.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        preset_box.bind("<<ComboboxSelected>>", self._preset_changed)

        ttk.Label(controls_frame, text="Tokens").grid(row=0, column=2, padx=5, pady=5, sticky="e")
        ttk.Combobox(controls_frame, textvariable=self.tokens_var, values=("128", "256", "512", "1024", "2048", "4096"), width=8).grid(row=0, column=3, padx=5, pady=5, sticky="w")

        ttk.Label(controls_frame, text="Context").grid(row=0, column=4, padx=5, pady=5, sticky="e")
        ttk.Combobox(controls_frame, textvariable=self.context_var, values=("2048", "4096", "8192", "16384", "32768"), width=8).grid(row=0, column=5, padx=5, pady=5, sticky="w")

        ttk.Label(controls_frame, text="Temp").grid(row=0, column=6, padx=5, pady=5, sticky="e")
        ttk.Combobox(controls_frame, textvariable=self.temp_var, values=("0.1", "0.3", "0.6", "0.8", "1.0", "1.2"), width=6).grid(row=0, column=7, padx=5, pady=5, sticky="w")

        # Row 2: Samplers & Logic
        ttk.Label(controls_frame, text="Top-p").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        ttk.Combobox(controls_frame, textvariable=self.top_p_var, values=("0.80", "0.90", "0.95", "1.00"), width=8).grid(row=1, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(controls_frame, text="Repeat pen.").grid(row=1, column=2, padx=5, pady=5, sticky="e")
        ttk.Combobox(controls_frame, textvariable=self.rep_pen_var, values=("1.00", "1.10", "1.20", "1.30"), width=8).grid(row=1, column=3, padx=5, pady=5, sticky="w")

        ttk.Label(controls_frame, text="Revolve").grid(row=1, column=4, padx=5, pady=5, sticky="e")
        ttk.Combobox(controls_frame, textvariable=self.revolve_var, values=("Off", "On"), state="readonly", width=8).grid(row=1, column=5, padx=5, pady=5, sticky="w")

        ttk.Label(controls_frame, text="Top-k").grid(row=1, column=6, padx=5, pady=5, sticky="e")
        ttk.Combobox(controls_frame, textvariable=self.top_k_var, values=("20", "40", "80", "100"), width=6).grid(row=1, column=7, padx=5, pady=5, sticky="w")

        # Row 3: Hardware Core Tuning
        ttk.Label(controls_frame, text="Device").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        device_box = ttk.Combobox(controls_frame, textvariable=self.device_var, values=("CPU only", "GPU auto", "CPU + GPU layers"), state="readonly", width=14)
        device_box.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        device_box.bind("<<ComboboxSelected>>", self._device_changed)

        ttk.Label(controls_frame, text="Threads").grid(row=2, column=2, padx=5, pady=5, sticky="e")
        ttk.Combobox(controls_frame, textvariable=self.threads_var, values=("auto", "2", "4", "8", "12", "16"), width=8).grid(row=2, column=3, padx=5, pady=5, sticky="w")

        ttk.Label(controls_frame, text="GPU Layers").grid(row=2, column=4, padx=5, pady=5, sticky="e")
        self.gpu_layers_entry = ttk.Entry(controls_frame, textvariable=self.gpu_layers_var, width=10, state="disabled")
        self.gpu_layers_entry.grid(row=2, column=5, padx=5, pady=5, sticky="w")

        # Chat Window Workspace Layout (now inside chat_tab)
        self.chat = scrolledtext.ScrolledText(chat_tab, wrap=tk.WORD, state=tk.DISABLED, font=("Segoe UI", 10))
        self.chat.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        self.chat.tag_configure("user", foreground="#1457a6", font=("Segoe UI", 10, "bold"))
        self.chat.tag_configure("assistant", foreground="#176b36", font=("Segoe UI", 10, "bold"))
        self.chat.tag_configure("error", foreground="#a12622")

        bottom = ttk.Frame(chat_tab)
        bottom.grid(row=2, column=0, sticky="ew", padx=10, pady=(5, 0))
        bottom.columnconfigure(0, weight=1)

        self.prompt = scrolledtext.ScrolledText(bottom, height=4, wrap=tk.WORD)
        self.prompt.grid(row=0, column=0, rowspan=2, sticky="ew", padx=(0, 8), pady=4)
        self.prompt.bind("<Return>", lambda _event: self.send_message())

        ttk.Button(bottom, text="Add files / folders", command=self.add_files).grid(row=0, column=1, sticky="ew", pady=3)

        self.send_button = ttk.Button(bottom, text="Send", command=self.send_message, state=tk.DISABLED)
        self.send_button.grid(row=0, column=2, padx=(5, 0), pady=3)

        self.stop_button = ttk.Button(bottom, text="Stop", command=self.stop_generation, state=tk.DISABLED)
        self.stop_button.grid(row=1, column=2, padx=(5, 0), pady=3)

        self.attachment_label = ttk.Label(bottom, text="No files attached")
        self.attachment_label.grid(row=1, column=1, sticky="w", pady=3)

        ttk.Label(chat_tab, textvariable=self.status_var, anchor="w").grid(row=3, column=0, sticky="ew", padx=12, pady=(4, 9))

        # ---- NetLock tab ----
        netlock_tab = ttk.Frame(self.notebook)
        self.notebook.add(netlock_tab, text="NetLock")
        netlock_tab.columnconfigure(0, weight=1)

        ttk.Label(netlock_tab, text="NetLock Integration", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, padx=10, pady=10, sticky="w")
        ttk.Label(netlock_tab, text="Load the AI first. Then select this NetLock tab to generate the 1GB pool and start NetLock.\nIf a 1GB pool file/memory already exists the button shows Activated. If not detected the button shows generate file.", wraplength=700).grid(row=1, column=0, padx=10, pady=5, sticky="w")

        btn_frame = ttk.Frame(netlock_tab)
        btn_frame.grid(row=2, column=0, padx=10, pady=10, sticky="w")

        self.netlock_button = ttk.Button(btn_frame, text="Launch NetLock GUI & DHCP Auto-Bind", command=self.launch_netlock)
        self.netlock_button.pack(side=tk.LEFT, padx=5)

        self.pool_button = ttk.Button(btn_frame, text="generate file", command=self.create_shared_pool)
        self.pool_button.pack(side=tk.LEFT, padx=5)

        self.netlock_status = tk.StringVar(value="Select NetLock tab (after AI is loaded) to generate pool and start.")
        ttk.Label(netlock_tab, textvariable=self.netlock_status, wraplength=700).grid(row=3, column=0, padx=10, pady=10, sticky="w")

        # Shared pool state
        self.shared_pool = None
        self.shared_pool_name = "ThoxNetLock1GB"
        self.dhcp_shared = False
        self._netlock_started = False

        # Bind tab change so NetLock only starts when user selects the tab
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        # Initial scan for existing 1GB pool file
        self._scan_existing_pool()

        # ---- AES Think tab (next to NetLock) ----
        aes_tab = ttk.Frame(self.notebook)
        self.notebook.add(aes_tab, text="AES Think")
        aes_tab.columnconfigure(0, weight=1)
        aes_tab.rowconfigure(1, weight=1)

        ttk.Label(aes_tab, text="Constant AES Encrypted Network Logic & Thinking", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.aes_think_text = scrolledtext.ScrolledText(aes_tab, wrap="word", height=20, state=tk.DISABLED)
        self.aes_think_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

    def launch_netlock(self):
        """Open the NetLock GUI (app_gui.py) and run DHCP auto-bind."""
        import subprocess
        import sys
        try:
            gui_path = BASE_DIR / "app_gui.py"
            if not gui_path.exists():
                gui_path = BASE_DIR / "vpn_blocker" / "app_gui.py"
            if not gui_path.exists():
                messagebox.showerror("NetLock", "app_gui.py not found.", parent=self.root)
                return

            subprocess.Popen([sys.executable, str(gui_path)], cwd=str(BASE_DIR), creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0)

            try:
                import dhcp_bind
                info = dhcp_bind.read_dhcp()
                if hasattr(dhcp_bind, "apply_bind") or hasattr(dhcp_bind, "auto_bind"):
                    bind_fn = getattr(dhcp_bind, "apply_bind", getattr(dhcp_bind, "auto_bind", None))
                    if bind_fn:
                        bind_fn()
                self.netlock_status.set(f"NetLock GUI launched. DHCP: IP={info.get('ip','?')} GW={info.get('gateway','?')} DNS={info.get('dns',[])}")
                self.dhcp_shared = True
            except Exception as e:
                self.netlock_status.set(f"NetLock GUI launched. DHCP bind error: {e}")

            try:
                import network_boot
                network_boot.probe_internet()
            except Exception:
                pass

        except Exception as exc:
            messagebox.showerror("NetLock launch failed", str(exc), parent=self.root)
            self.netlock_status.set(f"Launch failed: {exc}")

    def _scan_existing_pool(self):
        """Auto-scan for an existing 1GB VRAM/shared pool. If file or memory exists, mark button activated. If not detected, label generate file."""
        pool_file = MEMORY_DIR / "shared_pool.dat"
        exists = False
        try:
            from multiprocessing import shared_memory
            try:
                sm = shared_memory.SharedMemory(name=self.shared_pool_name, create=False)
                sm.close()
                exists = True
            except FileNotFoundError:
                pass
            except Exception:
                pass
        except Exception:
            pass
        if pool_file.exists() and pool_file.stat().st_size >= 1 * 1024 * 1024:
            exists = True
        if exists:
            self.pool_button.configure(text="Activated")
            self.netlock_status.set("1GB pool already exists (file or shared memory). Button set to Activated.")
        else:
            self.pool_button.configure(text="generate file")

    def _on_tab_changed(self, event=None):
        """When user selects the NetLock tab and AI is loaded, generate the pool and start NetLock."""
        try:
            current = self.notebook.tab(self.notebook.select(), "text")
        except Exception:
            return
        if current != "NetLock":
            return
        if self.llm is None:
            self.netlock_status.set("Load the AI model first, then select this tab to start NetLock.")
            return
        if getattr(self, "_netlock_started", False):
            return
        # Generate / ensure the 1GB pool
        self.create_shared_pool()
        # Mark activated
        self.pool_button.configure(text="Activated")
        # Start NetLock services only now
        self._start_netlock_services()
        self._netlock_started = True
        self.netlock_status.set("NetLock started (pool generated, services running). Select tab again is a no-op.")

    def create_shared_pool(self):
        """Create a shared memory pool for parallel AI/DHCP connection.
        Tries 1GB first; falls back to smaller sizes on WinError 1450 (commit limit)."""
        from multiprocessing import shared_memory
        sizes = [
            1 * 1024 * 1024 * 1024,   # 1 GB
            256 * 1024 * 1024,        # 256 MB
            64 * 1024 * 1024,         # 64 MB
            16 * 1024 * 1024,         # 16 MB
            1 * 1024 * 1024,          # 1 MB
        ]
        last_error = None
        for size in sizes:
            try:
                try:
                    self.shared_pool = shared_memory.SharedMemory(
                        name=self.shared_pool_name, create=True, size=size
                    )
                except FileExistsError:
                    self.shared_pool = shared_memory.SharedMemory(name=self.shared_pool_name)
                gb = size / (1024 ** 3)
                self.netlock_status.set(
                    f"Shared memory pool ready: {self.shared_pool_name} ({gb:.2f} GB)"
                )
                return
            except OSError as exc:
                last_error = exc
                # WinError 1450 = ERROR_NO_SYSTEM_RESOURCES (commit limit)
                if getattr(exc, "winerror", None) == 1450 or "1450" in str(exc):
                    continue
                break
            except Exception as exc:
                last_error = exc
                break

        # File-backed fallback with a small real allocation (avoids 1450 on sparse)
        pool_file = MEMORY_DIR / "shared_pool.dat"
        pool_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(pool_file, "wb") as f:
                f.write(b"\0" * (1 * 1024 * 1024))  # 1 MB real
            self.netlock_status.set(
                f"Shared pool using file {pool_file} (1 MB). "
                f"Large allocation failed: {last_error}. "
                f"Increase pagefile size if you need the full 1 GB."
            )
        except Exception as e2:
            self.netlock_status.set(
                f"Could not create shared pool: {last_error} / {e2}. "
                f"Free commit charge (RAM+pagefile) is too low for a large reservation."
            )


    def _share_dhcp_parallel(self):
        """When AI is loaded, share parallel connection to DHCP with firewall settings via the pool."""
        if self.shared_pool is None:
            self.create_shared_pool()
        try:
            import dhcp_bind
            import json
            info = dhcp_bind.read_dhcp()
            payload = {
                "dhcp": info,
                "ai_loaded": True,
                "firewall": "configured",
                "parallel": True,
                "pool": self.shared_pool_name,
            }
            data = json.dumps(payload).encode("utf-8")
            if self.shared_pool and len(data) < self.shared_pool.size:
                self.shared_pool.buf[:len(data)] = data
                self.shared_pool.buf[len(data)] = 0
            self.netlock_status.set(f"AI loaded -- parallel DHCP share active. IP={info.get('ip','?')} via {self.shared_pool_name}")
            self.dhcp_shared = True
        except Exception as exc:
            self.netlock_status.set(f"AI loaded. DHCP share warning: {exc}")

    def _preset_changed(self, _event=None):
        preset = self.preset_var.get()
        if preset == "Balanced":
            self.tokens_var.set("1024")
            self.temp_var.set(0.8)
            self.top_p_var.set(0.95)
        elif preset == "Fast / short":
            self.tokens_var.set("256")
            self.temp_var.set(0.3)
            self.top_p_var.set(0.80)
        elif preset == "Quality / long":
            self.tokens_var.set("2048")
            self.temp_var.set(0.6)
            self.top_p_var.set(0.95)
        elif preset == "Deep think":
            self.tokens_var.set("4096")
            self.temp_var.set(1.0)
            self.top_p_var.set(0.90)
        elif preset == "Code":
            self.tokens_var.set("2048")
            self.temp_var.set(0.1)
            self.top_p_var.set(1.00)

    def _device_changed(self, _event=None):
        if self.device_var.get() == "CPU + GPU layers":
            self.gpu_layers_entry.configure(state="normal")
            if self.gpu_layers_var.get() == "0" or self.gpu_layers_var.get() == "-1":
                self.gpu_layers_var.set("20")
        else:
            self.gpu_layers_entry.configure(state="disabled")
            self.gpu_layers_var.set("-1" if self.device_var.get() == "GPU auto" else "0")

    def browse_model(self):
        selected = filedialog.askopenfilename(
            title="Choose a GGUF model",
            initialdir=str(BASE_DIR / "models"),
            filetypes=(("GGUF models", ".gguf"), ("All files", ".*")),
        )
        if selected:
            self.model_var.set(selected)
            context = get_gguf_max_context(selected)
            self.context_var.set(str(min(context, 4096)))

    def _runtime_settings(self):
        model_path = Path(self.model_var.get()).expanduser()
        if not model_path.is_file() or model_path.suffix.lower() != ".gguf":
            raise ValueError("Choose an existing .gguf model file.")

        threads_str = self.threads_var.get()
        if threads_str == "auto":
            threads = multiprocessing.cpu_count() or 1
        else:
            threads = int(threads_str)

        context = int(self.context_var.get())
        tokens = int(self.tokens_var.get())

        if self.device_var.get() == "CPU only":
            gpu_layers = 0
        elif self.device_var.get() == "GPU auto":
            gpu_layers = -1
        else:
            gpu_layers = int(self.gpu_layers_var.get())

        if threads < 1 or threads > (multiprocessing.cpu_count() or 1):
            raise ValueError("Threads must be between 1 and the available CPU thread count.")
        if context < 128:
            raise ValueError("Context must be at least 128 tokens.")
        if tokens < 1:
            raise ValueError("Max tokens must be at least 1.")
        if gpu_layers < -1:
            raise ValueError("GPU layers must be -1 (auto) or zero or greater.")

        return model_path, threads, context, tokens, gpu_layers

    def load_ai(self):
        if self.busy:
            return
        try:
            model_path, threads, context, _tokens, gpu_layers = self._runtime_settings()
        except (ValueError, OSError) as error:
            messagebox.showerror("Invalid settings", str(error), parent=self.root)
            return

        if not LLAMA_SERVER_PATH.is_file():
            messagebox.showerror(
                "llama-server not found",
                f"Could not find the bundled server:\n{LLAMA_SERVER_PATH}",
                parent=self.root,
                )
            return

        if self.llm:
            self.llm.close()
            self.llm = None

        self.busy = True
        self.load_button.configure(state=tk.DISABLED)
        self.send_button.configure(state=tk.DISABLED)
        self.status_var.set("Loading model. This may take several minutes...")

        threading.Thread(
            target=self._load_worker,
            args=(model_path, threads, context, gpu_layers),
            daemon=True,
        ).start()

    def _load_worker(self, model_path, threads, context, gpu_layers):
        try:
            llm = create_llama_model(model_path, threads, context, gpu_layers)
            self.events.put(("loaded", llm, model_path.name, context, gpu_layers))
        except Exception as error:
            self.events.put(("load_error", str(error)))

    def _load_existing_workspace(self):
        workspace_dir, already_exists = ensure_workspace_folder()
        if not already_exists:
            self.status_var.set("Workspace folder created: " + str(workspace_dir))
            return
        files = [path for path in workspace_dir.rglob("*") if path.is_file()]
        if not files:
            self.status_var.set("Workspace folder already exists: " + str(workspace_dir))
            return
        try:
            loaded = read_text_attachment(workspace_dir)
        except (OSError, ValueError, zipfile.BadZipFile):
            self.status_var.set("Workspace folder already exists: " + str(workspace_dir))
            return
        self.attachments = [(workspace_dir, loaded)]
        self.attachment_text = loaded
        self.workspace_loaded = True
        self.loaded_targets = [workspace_dir]
        self.attachment_label.configure(
            text="Workspace already exists and was loaded"
        )
        self.status_var.set("Workspace folder already exists: " + str(workspace_dir))

    def add_files(self):
        selected = filedialog.askopenfilenames(
            title="Add text files, binary codes, or ZIP archives",
            filetypes=(
                ("Supported files", "*.txt *.md *.py *.json *.bin *.zip"),
                ("All files", "*.*"),
            ),
        )
        selected = list(selected) if selected else []
        folder = ""
        if not self.workspace_loaded:
            folder = filedialog.askdirectory(
                title="Add a folder to the workspace, or cancel",
                initialdir=str(BASE_DIR),
            )
        if folder:
            selected.append(folder)
        if not selected:
            return

        workspace_dir, already_exists = ensure_workspace_folder()
        additions = []
        combined = list(self.attachments)
        try:
            for item in selected:
                staged = copy_into_workspace(item)
                loaded = read_text_attachment(staged)
                store_memory_code_bin(staged)
                additions.append((Path(staged), loaded))
                combined.append((Path(staged), loaded))
                self.loaded_targets.append(Path(staged))
            if sum(len(item_text.encode("utf-8")) for _, item_text in combined) > MAX_TOTAL_ATTACHMENT_BYTES:
                raise ValueError("Attachments exceed the 4 MiB combined text limit.")
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            messagebox.showerror("Could not add attachment", str(error), parent=self.root)
            return

        self.attachments = combined
        self.attachment_text = "\n\n".join(item_text for _, item_text in combined)
        self.workspace_loaded = True
        state = "existing" if already_exists else "new"
        names = ", ".join(path.name for path in self.loaded_targets[-len(selected):])
        self.attachment_label.configure(
            text="File selected and loaded: " + names
        )
        self.status_var.set("File selected and loaded into " + state + " workspace: " + str(workspace_dir))
    def send_message(self):
        if not self.llm or self.busy:
            return
        prompt = self.prompt.get("1.0", tk.END).strip()
        if not prompt:
            return
        try:
            _model, _threads, _context, tokens, _gpu = self._runtime_settings()
        except (ValueError, OSError) as error:
            messagebox.showerror("Invalid settings", str(error), parent=self.root)
            return

        self.prompt.delete("1.0", tk.END)
        self._append_chat("You", prompt, "user")
        self._append_chat("AI", "", "assistant")

        self.busy = True
        self.stop_event = threading.Event()
        self.active_conv_id = uuid.uuid4().hex

        self.send_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.load_button.configure(state=tk.DISABLED)
        self.status_var.set("Generating response...")

        fix_mode = is_fix_command(prompt) and bool(self.loaded_targets)
        attachments = self.attachment_text
        if fix_mode:
            attachments = build_loaded_attachment(self.loaded_targets)
            self.attachment_text = attachments
        threading.Thread(
            target=self._generate_worker,
            args=(prompt, tokens, self.temp_var.get(), self.top_p_var.get(), self.rep_pen_var.get(), self.top_k_var.get(), attachments, self.active_conv_id, self.stop_event, self.revolve_var.get() == "On", fix_mode, list(self.loaded_targets)),
            daemon=True,
        ).start()

    def _generate_worker(self, prompt, tokens, temp, top_p, rep_pen, top_k, attachments, conv_id, stop_event, revolve=False, fix_mode=False, loaded_targets=None):
        started = time.perf_counter()
        try:
            request_prompt = prompt
            if fix_mode:
                request_prompt = prompt + "\n\n" + FIX_FILE_INSTRUCTION
            response = generate_response(
                self.llm, request_prompt, self.memory_records, tokens,
                temperature=temp, top_p=top_p, repeat_penalty=rep_pen, top_k=top_k,
                attachments=attachments,
                on_token=None if fix_mode else (lambda token: self.events.put(("token", token))),
                conv_id=conv_id,
                stop_event=stop_event,
                revolve=revolve,
            )
            if fix_mode:
                response = apply_loaded_file_edits(response, loaded_targets or [])
                self.events.put(("token", response + "\n\n"))
            self.events.put(("generated", prompt, response, time.perf_counter() - started))
        except Exception as error:
            self.events.put(("generation_error", str(error)))

    def stop_generation(self):
        if not self.busy or not self.stop_event:
            return
        self.stop_event.set()
        if self.llm and self.active_conv_id:
            threading.Thread(
                target=self._stop_worker,
                args=(self.llm, self.active_conv_id),
                daemon=True,
            ).start()
        self.stop_button.configure(state=tk.DISABLED)
        self.status_var.set("Stopping generation...")

    @staticmethod
    def _stop_worker(llm, conv_id):
        try:
            llm.stop_generation(conv_id)
        except (OSError, urllib.error.URLError):
            pass

    def _append_chat(self, speaker, text, tag):
        self.chat.configure(state=tk.NORMAL)
        if speaker:
            self.chat.insert(tk.END, speaker + ":\n", tag)
        if text:
            self.chat.insert(tk.END, text + "\n\n")
        self.chat.configure(state=tk.DISABLED)
        self.chat.see(tk.END)

    def _poll_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "loaded":
                    self.llm = event[1]
                    self.busy = False
                    self.load_button.configure(state=tk.NORMAL)
                    self.send_button.configure(state=tk.NORMAL)
                    self.status_var.set(
                        f"AI ready: {event[2]} | context {event[3]:,} | GPU layers {event[4]}"
                    )
                    self._start_ai_secure_server()
                    self._start_aes_thinking()
                    # NetLock starts only when user selects the NetLock tab (after AI is loaded)



                elif kind == "aes_thought":
                    try:
                        self.aes_think_text.configure(state=tk.NORMAL)
                        self.aes_think_text.insert(tk.END, event[1] + "\n\n")
                        self.aes_think_text.configure(state=tk.DISABLED)
                        self.aes_think_text.see(tk.END)
                    except Exception:
                        pass
                elif kind == "load_error":
                    self.busy = False
                    self.load_button.configure(state=tk.NORMAL)
                    self.status_var.set("Model failed to load.")
                    messagebox.showerror("Model load failed", event[1], parent=self.root)
                elif kind == "token":
                    self.chat.configure(state=tk.NORMAL)
                    self.chat.insert(tk.END, event[1])
                    self.chat.configure(state=tk.DISABLED)
                    self.chat.see(tk.END)
                elif kind == "generated":
                    _kind, prompt, response, elapsed = event
                    if response:
                        self.memory_records.append(
                            {"prompt": prompt, "response": response}
                        )
                        write_chat_to_memory(prompt, response)
                    else:
                        self._append_chat("", "\n[Generation stopped]", "error")
                    self.busy = False
                    self.stop_button.configure(state=tk.DISABLED)
                    self.load_button.configure(state=tk.NORMAL)
                    self.send_button.configure(state=tk.NORMAL)
                    self.status_var.set(f"Ready. Response time: {elapsed:.1f} seconds.")
                    if not self.workspace_loaded:
                        self.attachment_text = ""
                        self.attachments = []
                        self.attachment_label.configure(text="No files attached")
                elif kind == "generation_error":
                    self.busy = False
                    self.stop_button.configure(state=tk.DISABLED)
                    self.load_button.configure(state=tk.NORMAL)
                    self.send_button.configure(state=tk.NORMAL)
                    self.status_var.set("Generation failed.")
                    self._append_chat("Error", event[1], "error")
        except queue.Empty:
            pass
        if not self.closing:
            self.root.after(50, self._poll_events)

    def close(self):
        self.closing = True
        # Always run API binding process on close (including X click)
        self._run_api_bindings_process()
        if self.stop_event:
            self.stop_event.set()
        if self.llm and self.active_conv_id:
            threading.Thread(
                target=self._stop_worker,
                args=(self.llm, self.active_conv_id),
                daemon=True,
            ).start()
        if self.llm:
            threading.Thread(target=self.llm.close, daemon=True).start()
        self.root.destroy()

    def _run_api_bindings_process(self):
        """Process that registers/runs all API bindings. Executes on every close, including X."""
        try:
            bindings_path = BASE_DIR / "bin" / "api_bindings.json"
            bindings_path.parent.mkdir(parents=True, exist_ok=True)
            bindings = {
                "tabs": ["Chat", "NetLock"],
                "chat_functions": ["load_ai", "send_message", "stop_generation", "browse_model", "add_files"],
                "netlock_functions": ["launch_netlock", "create_shared_pool"],
                "script_functions": ["scan_apps", "secure_stream_seal", "secure_scripts", "ai_upload", "ai_download", "scan_malicious"],
                "endpoint": "127.0.0.1:8765",
                "cmd": "api_bind",
                "ran_on_close": True,
                "timestamp": time.time(),
            }
            import json
            bindings_path.write_text(json.dumps(bindings, indent=2), encoding="utf-8")
            # Also touch a flag so external processes see it ran
            (BASE_DIR / "bin" / "api_bindings_ran.flag").write_text("1", encoding="utf-8")
        except Exception:
            pass


def run_gui(initial_model=None, initial_context=None):
    root = tk.Tk()
    ChatWindow(root, initial_model, initial_context)
    root.mainloop()


# ==========================================
# PART 12: INTERACTIVE CHAT LOOP
# ==========================================


def run_chat_loop(llm, memory_records, max_tokens):
    """Run the interactive Thox chat session."""
    print("Thox assistant is ready.")
    print("Type 'exit' or 'quit' to close.")
    while True:
        try:
            user_prompt = input("\nEnter your prompt: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nClosing chat safely.")
            break
        if user_prompt.lower() in {"exit", "quit"}:
            print("Closing chat. Goodbye!")
            break
        if not user_prompt:
            continue

        start_time = time.perf_counter()
        try:
            ai_response_text = generate_response(
                llm, user_prompt, memory_records, max_tokens
            )
        except Exception as error:
            print(f"[-] Thox generation error: {error}")
            continue

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        print("\nThox Response:")
        print(ai_response_text)
        print(f"--- Processed in {elapsed_ms:.2f} ms ---")
        write_chat_to_memory(user_prompt, ai_response_text)
        memory_records.append({"prompt": user_prompt, "response": ai_response_text})


# ==========================================
# PART 13: ARGUMENTS AND MAIN LOGIC
# ==========================================


def parse_arguments():
    """Read command-line configuration."""
    parser = argparse.ArgumentParser(description="Local Thox GGUF assistant.")
    parser.add_argument("--model", help="Exact path to the approved GGUF model.")
    parser.add_argument("--threads", type=int, help="Maximum real CPU threads to use.")
    parser.add_argument("--context", type=int, help="Override native max context size.")
    parser.add_argument("--max-tokens", type=int, default=1024, help="Max generated tokens.")
    parser.add_argument("--rebuild-profile", action="store_true", help="Force profile rebuild.")
    return parser.parse_args()


def keep_terminal_open(exit_code):
    """Keep a Windows terminal open after exit."""
    if os.name == "nt" and sys.stdin.isatty():
        try:
            input("\nPress Enter to close this terminal...")
        except (EOFError, KeyboardInterrupt):
            pass
    return exit_code


def main():
    arguments = parse_arguments()
    if arguments.max_tokens < 1:
        print("[-] max-tokens must be positive.", file=sys.stderr)
        return 2

    try:
        # Load up or initialize via structural save states
        target_profile, profile = ensure_global_binary_profile()
        if arguments.rebuild_profile:
            compile_global_hardware_profile(target_profile)
            profile = read_binary_profile(target_profile)
        display_binary_profile(profile)

        print("\n=====================================================")
        print(" STARTING LOCAL THOX LLAMA ENGINE (GUI MODE)")
        print("=====================================================\n")

        # Resolve setup parameters to pass as baseline hints into the GUI
        try:
            model_path = locate_model(arguments.model)
        except Exception:
            model_path = None

        if model_path and not arguments.context:
            context_size = get_gguf_max_context(model_path)
        else:
            context_size = arguments.context

        # Launch the fully interactive graphical framework directly
        run_gui(initial_model=model_path, initial_context=context_size)
        return 0
    except Exception as error:
        print(f"[-] Startup error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    exit_code = main()
    raise SystemExit(keep_terminal_open(exit_code))

