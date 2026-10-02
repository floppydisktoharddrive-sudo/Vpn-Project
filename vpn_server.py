#!/usr/bin/env python3
"""
Host-only AES-256-GCM tunnel server. No WireGuard.

- Generates a real 256-bit key on disk (not placeholders)
- Listens for encrypted inbound connections
- Exposes a local SOCKS5 port so this computer can send traffic
  through the AES path
- Start / stop from the GUI or CLI
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

PARALLEL = 16

BASE = Path(__file__).resolve().parent
DATA = BASE / "vpn_data"
STATE_FILE = BASE / "vpn_server_state.json"

DEFAULT_PORT = 51821
DEFAULT_PUBLIC_PORT = 51822
DEFAULT_SOCKS = 1080
DEFAULT_PUBLIC_SOCKS = 1081
DEFAULT_DNS = ["1.1.1.1", "1.0.0.1"]
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
MAX_FRAME = 1024 * 1024 * 4
STREAM_CHUNK = 1024 * 1024 * 2
SOCK_BUF = 100 * 1024 * 1024
PKT_DATA = 1
PKT_ACK = 2
PKT_CLOSE = 3
ACK_EVERY = 8


def _ensure_crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401

        return
    except ImportError:
        pass
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "cryptography"])


def aesgcm_class():
    _ensure_crypto()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM


def _local_key_path() -> Path:
    return DATA / "aes256.key"


def _session_key_path() -> Path:
    return DATA / "session.key"


def _session_public_key_path() -> Path:
    return DATA / "session_public.key"


def _local_info_path() -> Path:
    return DATA / "server.txt"


def lan_bind_ip() -> str:
    """Use the 192.x LAN address, never a NIC name or 10.x bridge."""
    try:
        import network_boot
        import persist

        rec = persist.load_applied()
        for candidate in (
            rec.get("bind"),
            rec.get("local_ip"),
            rec.get("gateway"),
        ):
            ip = str(candidate or "").strip()
            if network_boot._is_192(ip):
                return ip
        info = network_boot.local_and_gateway()
        ip = str(info.get("local_ip") or "").strip()
        if network_boot._is_192(ip):
            return ip
        gw = str(info.get("gateway") or "").strip()
        if network_boot._is_192(gw):
            parts = gw.split(".")
            if len(parts) == 4:
                last = "2" if parts[3] != "2" else "3"
                return ".".join(parts[:3] + [last])
    except Exception:
        pass
    return "127.0.0.1"


def _usable_path(raw) -> Path | None:
    if not raw:
        return None
    p = Path(str(raw))
    try:
        # Always keep data next to these scripts, never a foreign machine path.
        resolved = p if p.is_absolute() else (BASE / p)
        resolved.relative_to(BASE)
        return resolved
    except ValueError:
        return None


def load_state() -> dict:
    state = {
        "port": DEFAULT_PORT,
        "public_port": DEFAULT_PUBLIC_PORT,
        "socks_port": DEFAULT_SOCKS,
        "public_socks_port": DEFAULT_PUBLIC_SOCKS,
        "dns": DEFAULT_DNS,
        "bind": "192.168.49.1",
        "bind": "127.0.0.1",
        "public_bind": "1.1.1.1",
        "public_bind": "1.0.0.1",
        "private_bind": "0.0.0.0",
        "running": False,
        "public_running": False,
        "key_file": "vpn_data/aes256.key",
        "server_conf": "vpn_data/server.txt",
        "client_conf": "vpn_data/server.txt",
    }
    if STATE_FILE.exists():
        try:
            saved = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                for k in (
                    "port",
                    "public_port",
                    "socks_port",
                    "public_socks_port",
                    "dns",
                    "bind",
                    "public_bind",
                    "private_bind",
                    "running",
                    "public_running",
                ):
                    if k in saved:
                        state[k] = saved[k]
        except json.JSONDecodeError:
            pass
    # Always prefer a 192.x LAN bind over a stored NIC/loopback value.
    lan = lan_bind_ip()
    if lan.startswith("192."):
        state["bind"] = lan
    state["key_file"] = "vpn_data/aes256.key"
    state["server_conf"] = "vpn_data/server.txt"
    state["client_conf"] = "vpn_data/server.txt"
    return state


def save_state(state: dict) -> None:
    out = dict(state)
    out["key_file"] = "vpn_data/aes256.key"
    out["server_conf"] = "vpn_data/server.txt"
    out["client_conf"] = "vpn_data/server.txt"
    STATE_FILE.write_text(json.dumps(out, indent=2), encoding="utf-8")


def generate_key(force: bool = False) -> Path:
    """Long-term key. Created once, then only loaded."""
    DATA.mkdir(parents=True, exist_ok=True)
    path = _local_key_path()
    if path.exists() and path.stat().st_size == KEY_LEN and not force:
        return path
    path.write_bytes(secrets.token_bytes(KEY_LEN))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def generate_session_key() -> Path:
    """New 256-bit key on every malicious hit / new session. Also writes aes-*.key."""
    from datetime import datetime

    DATA.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(KEY_LEN)
    path = _session_key_path()
    path.write_bytes(key)
    archive = DATA / "aes"
    archive.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    named = archive / f"aes-{stamp}.key"
    named.write_bytes(key)
    for p in (path, named):
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    _publish_session_key(key, named)
    return path


_live_links: list = []
_link_lock = threading.Lock()
_prev_key: bytes | None = None
_bound_keys: list[bytes] = []
_ping_stop = threading.Event()
_ping_thread: threading.Thread | None = None
_last_tab_signature: tuple = ()
_BROWSER_MARKS = ("chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "browser")


def _safe_tab_name(value: str) -> str:
    out = []
    for ch in str(value or "tab"):
        if ch.isascii() and (ch.isalnum() or ch in ".-"):
            out.append(ch)
        else:
            out.append("-")
    text = "".join(out).strip("-") or "tab"
    return text[:48]


def _browser_tab_rows() -> list[dict]:
    try:
        import connections
        rows = connections.list_connections()
    except Exception:
        return []
    found = []
    seen = set()
    for row in rows:
        app = (row.get("app") or "").lower()
        state = (row.get("state") or "").upper()
        if state not in {"ESTABLISHED", "ESTAB", "CLOSE_WAIT"}:
            continue
        if not any(mark in app for mark in _BROWSER_MARKS):
            continue
        remote = str(row.get("remote") or "")
        local = str(row.get("local") or "")
        token = (app, local, remote)
        if token in seen:
            continue
        seen.add(token)
        found.append(row)
    return found


def _tab_signature() -> tuple:
    return tuple(
        (
            str(row.get("app") or ""),
            str(row.get("local") or ""),
            str(row.get("remote") or ""),
        )
        for row in _browser_tab_rows()
    )


def register_live_link(link) -> None:
    with _link_lock:
        if link not in _live_links:
            _live_links.append(link)


def unregister_live_link(link) -> None:
    with _link_lock:
        if link in _live_links:
            _live_links.remove(link)


def _bound_key_list() -> list[bytes]:
    with _link_lock:
        keys = list(_bound_keys)
        if _prev_key and _prev_key not in keys:
            keys.append(_prev_key)
        return keys


def rebind_live_keys(key: bytes) -> None:
    """Point the running tunnel and open sockets at the new key. Sockets stay open."""
    global _prev_key
    if _runtime is not None and getattr(_runtime, "key", None):
        _prev_key = bytes(_runtime.key)
        _runtime.key = key
    else:
        _prev_key = None
    with _link_lock:
        _bound_keys.clear()
        _bound_keys.append(key)
        for link in list(_live_links):
            try:
                link.key = key
            except Exception:
                pass
    _aes_cache.clear()


def purge_old_aes_keys(keep: set[str]) -> None:
    """Permanently delete every aes key file that is not in the new set."""
    archive = DATA / "aes"
    if not archive.is_dir():
        return
    for path in list(archive.glob("*.key")):
        if path.name in keep:
            continue
        try:
            path.unlink()
        except OSError:
            pass


def _publish_session_key(key: bytes, named: Path) -> None:
    """Bind the new key, write one file per open browser tab, delete the old files."""
    from datetime import datetime

    archive = DATA / "aes"
    archive.mkdir(parents=True, exist_ok=True)
    tabs = _browser_tab_rows()
    keep: set[str] = set()
    if tabs:
        for index, row in enumerate(tabs, start=1):
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
            remote = _safe_tab_name(row.get("remote") or "tab")
            tab_path = archive / f"aes-{stamp}-tab{index}-{remote}.key"
            tab_path.write_bytes(key)
            try:
                os.chmod(tab_path, 0o600)
            except OSError:
                pass
            keep.add(tab_path.name)
    else:
        keep.add(named.name)
    purge_old_aes_keys(keep)
    rebind_live_keys(key)
    global _last_tab_signature
    _last_tab_signature = _tab_signature()


def _send_link_ping(link) -> None:
    sock = getattr(link, "sock", None)
    key = getattr(link, "key", None)
    lock = getattr(link, "_io", None)
    if sock is None or not key:
        return
    if lock is None:
        send_frame(sock, key, b"PING")
        return
    with lock:
        send_frame(sock, key, b"PING")


def _ping_loop() -> None:
    global _last_tab_signature
    while not _ping_stop.is_set():
        if _ping_stop.wait(1.0):
            break
        if _runtime is None:
            continue
        signature = _tab_signature()
        if signature != _last_tab_signature:
            try:
                generate_session_key()
            except Exception:
                pass
            _last_tab_signature = signature
        with _link_lock:
            links = list(_live_links)
        for link in links:
            try:
                _send_link_ping(link)
            except Exception:
                unregister_live_link(link)


def start_key_ping() -> None:
    global _ping_thread
    if _ping_thread is not None and _ping_thread.is_alive():
        return
    _ping_stop.clear()
    _ping_thread = threading.Thread(target=_ping_loop, name="aes-tab-ping", daemon=True)
    _ping_thread.start()


def stop_key_ping() -> None:
    _ping_stop.set()


def generate_public_session_key() -> Path:
    """Separate 256-bit key for the public tunnel."""
    DATA.mkdir(parents=True, exist_ok=True)
    path = _session_public_key_path()
    path.write_bytes(secrets.token_bytes(KEY_LEN))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def load_key() -> bytes:
    if _runtime is not None and getattr(_runtime, "key", None):
        key = _runtime.key
        if isinstance(key, (bytes, bytearray)) and len(key) == KEY_LEN:
            return bytes(key)
    session = _session_key_path()
    if session.exists() and session.stat().st_size == KEY_LEN:
        return session.read_bytes()
    path = generate_key()
    key = path.read_bytes()
    if len(key) != KEY_LEN:
        raise ValueError("AES key file is the wrong size")
    return key


_aes_cache: dict[bytes, object] = {}


def _aes(key: bytes):
    obj = _aes_cache.get(key)
    if obj is None:
        obj = aesgcm_class()(key)
        _aes_cache[key] = obj
    return obj


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = _aes(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise ValueError("short frame")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return _aes(key).decrypt(nonce, ct, aad)


def tune_socket(sock: socket.socket) -> None:
    for size in (SOCK_BUF, 16 * 1024 * 1024, 4 * 1024 * 1024, 1024 * 1024):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, size)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, size)
            break
        except OSError:
            continue
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
    except OSError:
        pass
    if os.name == "nt":
        try:
            # Windows keepalive idle/interval (ms) via SIO_KEEPALIVE_VALS
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 15000, 5000))
        except Exception:
            pass


def pack_data(seq: int, payload: bytes) -> bytes:
    return struct.pack("!BI", PKT_DATA, seq) + payload


def pack_ack(seq: int) -> bytes:
    return struct.pack("!BI", PKT_ACK, seq)


def pack_close() -> bytes:
    return struct.pack("!BI", PKT_CLOSE, 0)


def unpack_packet(frame: bytes) -> tuple[int, int, bytes]:
    if frame in (b"CLOSE", b"PING", b"PONG") or frame.startswith(b"OPEN") or frame.startswith(b"D"):
        if frame.startswith(b"D"):
            return PKT_DATA, 0, frame[1:]
        if frame == b"CLOSE":
            return PKT_CLOSE, 0, b""
        return PKT_DATA, 0, frame
    if len(frame) < 5:
        return PKT_DATA, 0, frame
    ptype, seq = struct.unpack("!BI", frame[:5])
    return ptype, seq, frame[5:]


def send_frame(sock: socket.socket, key: bytes, payload: bytes) -> None:
    blob = encrypt(key, payload)
    sock.sendall(struct.pack("!I", len(blob)) + blob)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    parts = bytearray()
    while len(parts) < n:
        chunk = sock.recv(n - len(parts))
        if not chunk:
            raise ConnectionError("closed")
        parts.extend(chunk)
    return bytes(parts)


def recv_frame(sock: socket.socket, key: bytes) -> bytes:
    raw_len = recv_exact(sock, 4)
    (n,) = struct.unpack("!I", raw_len)
    if n == 0 or n > MAX_FRAME:
        raise ValueError("bad frame length")
    blob = recv_exact(sock, n)
    try:
        return decrypt(key, blob)
    except Exception:
        for alt in _bound_key_list():
            if alt == key:
                continue
            try:
                return decrypt(alt, blob)
            except Exception:
                continue
        raise


class TunnelServer:
    def __init__(self, bind: str, port: int, socks_port: int, key: bytes):
        self.bind = bind
        self.port = port
        self.socks_port = socks_port
        self.key = key
        self._stop = threading.Event()
        self._sockets: list[socket.socket] = []
        self._pool = ThreadPoolExecutor(max_workers=PARALLEL, thread_name_prefix="aes-par")

    def _listen(self, host: str, port: int) -> socket.socket:
        sock = self._track(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(PARALLEL * 2)
        sock.settimeout(1.0)
        return sock

    def start(self) -> None:
        self._stop.clear()
        # Bind the encrypted port on the 192.x LAN address, not a NIC name.
        # Keep 127.0.0.1 as well so this PC can still open AesClient locally.
        binds = []
        hosts = (self.bind, "127.0.0.1")
        if (self.bind or "").strip() in {"1.1.1.1", "1.0.0.1", "::"}:
            hosts = (self.bind,)
        for host in hosts:
            host = (host or "").strip()
            if not host or host in binds:
                continue
            binds.append(host)
        last_err = None
        tun_socks = []
        for host in binds:
            try:
                tun_socks.append(self._listen(host, self.port))
            except OSError as exc:
                last_err = exc
        if not tun_socks:
            raise last_err or OSError("could not bind 192.x tunnel port")
        self._tun_sock = tun_socks[0]
        self._tun_socks = tun_socks
        sox = self._listen("127.0.0.1", self.socks_port)
        self._socks_sock = sox
        for i, sock in enumerate(tun_socks):
            threading.Thread(
                target=self._serve_tunnel_sock,
                args=(sock,),
                name=f"aes-tunnel-{i}",
                daemon=True,
            ).start()
        threading.Thread(target=self._serve_socks, name="aes-socks", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        for s in list(self._sockets):
            try:
                s.close()
            except OSError:
                pass
        self._sockets.clear()
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _track(self, sock: socket.socket) -> socket.socket:
        self._sockets.append(sock)
        return sock

    def _serve_tunnel(self) -> None:
        srv = getattr(self, "_tun_sock", None)
        if srv is None:
            srv = self._listen(self.bind, self.port)
        self._serve_tunnel_sock(srv)

    def _serve_tunnel_sock(self, srv: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._pool.submit(self._handle_peer, conn, addr)

    def _handle_peer(self, conn: socket.socket, addr) -> None:
        conn.settimeout(60)
        remote = None
        try:
            hello = recv_exact(conn, 16)
            send_frame(conn, self.key, b"NETLOCK-OK" + hello)
            ack = recv_frame(conn, self.key)
            if not ack.startswith(b"NETLOCK-READY"):
                return
            while not self._stop.is_set():
                frame = recv_frame(conn, self.key)
                if frame == b"PING":
                    send_frame(conn, self.key, b"PONG")
                    continue
                if frame.startswith(b"DNS?"):
                    state = load_state()
                    send_frame(conn, self.key, ("DNS=" + ",".join(state.get("dns") or [])).encode())
                    continue
                if frame.startswith(b"OPEN\n"):
                    parts = frame.split(b"\n")
                    if len(parts) < 3:
                        send_frame(conn, self.key, b"ERR")
                        continue
                    host = parts[1].decode("ascii", errors="replace")
                    port = int(parts[2])
                    try:
                        remote = socket.create_connection((host, port), timeout=15)
                        tune_socket(remote)
                        tune_socket(conn)
                    except OSError as exc:
                        send_frame(conn, self.key, b"OPENFAIL " + str(exc).encode())
                        continue
                    send_frame(conn, self.key, b"OPENED")
                    conn.settimeout(None)
                    remote.settimeout(None)
                    self._bridge(conn, remote)
                    return
                send_frame(conn, self.key, b"ERR")
        except Exception:
            pass
        finally:
            for s in (conn, remote):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    def _bridge(self, enc: socket.socket, remote: socket.socket) -> None:
        def to_remote():
            last_ack = 0
            try:
                while not self._stop.is_set():
                    frame = recv_frame(enc, self.key)
                    ptype, seq, payload = unpack_packet(frame)
                    if frame in (b"PING", b"PONG"):
                        if frame == b"PING":
                            send_frame(enc, self.key, b"PONG")
                        continue
                    if ptype == PKT_CLOSE:
                        break
                    if ptype == PKT_ACK:
                        continue
                    if payload:
                        remote.sendall(payload)
                    if seq and seq - last_ack >= ACK_EVERY:
                        send_frame(enc, self.key, pack_ack(seq))
                        last_ack = seq
            except Exception:
                pass
            try:
                remote.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        def to_client():
            seq = 0
            try:
                while not self._stop.is_set():
                    data = remote.recv(STREAM_CHUNK)
                    if not data:
                        break
                    seq += 1
                    send_frame(enc, self.key, pack_data(seq, data))
            except Exception:
                pass
            try:
                send_frame(enc, self.key, pack_close())
            except Exception:
                pass

        t = threading.Thread(target=to_client, daemon=True)
        t.start()
        to_remote()
        t.join(timeout=2)

    def _serve_socks(self) -> None:
        srv = getattr(self, "_socks_sock", None)
        if srv is None:
            srv = self._track(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", self.socks_port))
            srv.listen(PARALLEL * 2)
            srv.settimeout(1.0)
        while not self._stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._pool.submit(self._socks_client, conn)

    def _socks_client(self, client: socket.socket) -> None:
        remote = None
        try:
            client.settimeout(30)
            header = recv_exact(client, 2)
            nmethods = header[1]
            recv_exact(client, nmethods)
            client.sendall(b"\x05\x00")
            req = recv_exact(client, 4)
            if req[0] != 5 or req[1] != 1:
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            atyp = req[3]
            if atyp == 1:
                addr = socket.inet_ntoa(recv_exact(client, 4))
            elif atyp == 3:
                ln = recv_exact(client, 1)[0]
                addr = recv_exact(client, ln).decode("idna", errors="replace")
            elif atyp == 4:
                addr = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
            else:
                client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            port = struct.unpack("!H", recv_exact(client, 2))[0]
            remote = socket.create_connection((addr, port), timeout=20)
            bind = remote.getsockname()
            client.sendall(
                b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", bind[1])
            )
            _pipe(client, remote)
        except Exception:
            try:
                client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
        finally:
            for s in (client, remote):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass


def _pipe(a: socket.socket, b: socket.socket) -> None:
    def one_way(src, dst):
        try:
            while True:
                data = src.recv(STREAM_CHUNK)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    t = threading.Thread(target=one_way, args=(b, a), daemon=True)
    t.start()
    one_way(a, b)
    t.join(timeout=1)


_runtime: TunnelServer | None = None
_runtime_public: TunnelServer | None = None
_lock = threading.Lock()


def write_server_files(port: int | None = None, dns: list[str] | None = None) -> dict:
    state = load_state()
    if port:
        state["port"] = int(port)
    if dns:
        state["dns"] = dns
    DATA.mkdir(parents=True, exist_ok=True)
    key_path = generate_key(force=False)
    print(f"AES-256 key file: {key_path}")
    dll = None
    for name in ("libnetlock_net.dll", "netlock_net.dll", "libnetlock_net.so", "netlock_net.so"):
        candidate = BASE / name
        if candidate.exists():
            dll = candidate
            break
    if dll is not None:
        print(f"C helper: {dll}")
        state["c_helper_dll"] = dll.name
    else:
        print("C helper missing: libnetlock_net.dll / netlock_net.dll (place it next to these scripts)")
    info = _local_info_path()
    info.write_text(
        "\n".join(
            [
                "NetLock AES-256-GCM host-only tunnel",
                f"Private bind (127.x LAN): {state.get('bind', '127.0.0.1')}",
                f"Private bind (127.x LAN): {state.get('bind', '0.0.0.0')}",
                f"Private TCP port: {state['port']}",
                f"Public bind: {state.get('public_bind', '192.168.49.1')}",
                f"Public bind: {state.get('public_bind', '1.1.1.1')}",
                f"Public bind: {state.get('public_bind', '1.0.0.1')}",
                f"Public TCP port: {state.get('public_port', DEFAULT_PUBLIC_PORT)}",
                f"Private SOCKS5: 127.0.0.1:{state.get('socks_port', DEFAULT_SOCKS)}",
                f"Public SOCKS5: 127.0.0.1:{state.get('public_socks_port', DEFAULT_PUBLIC_SOCKS)}",
                f"DNS list: {', '.join(state.get('dns') or [])}",
                f"Key file: {key_path}",
                "Cipher: AES-256-GCM",
                "No WireGuard. Key is 32 random bytes generated on this PC.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    lan = lan_bind_ip()
    if lan.startswith("192."):
        state["bind"] = lan
    state["server_conf"] = "vpn_data/server.txt"
    state["client_conf"] = "vpn_data/server.txt"
    state["key_file"] = "vpn_data/aes256.key"
    save_state(state)
    return state


def start_server() -> tuple[bool, str]:
    """Start the private 192.x / loopback tunnel only."""
    global _runtime
    with _lock:
        if _runtime is not None:
            return True, "Private AES tunnel already running."
        state = write_server_files()
        lan = lan_bind_ip()
        if lan.startswith("192."):
            state["bind"] = lan
            save_state(state)
        try:
            long_term = generate_key(force=False)
            session_path = generate_session_key()
            key = session_path.read_bytes()
            _ensure_crypto()
        except Exception as exc:
            return False, f"Could not start private AES engine: {exc}"
        srv = TunnelServer(
            bind=state.get("bind") or lan or "127.0.0.1",
            port=int(state["port"]),
            socks_port=int(state.get("socks_port") or DEFAULT_SOCKS),
            key=key,
        )
        try:
            srv.start()
        except OSError as exc:
            return False, f"Could not bind private tunnel port: {exc}"
        _runtime = srv
        state["running"] = True
        save_state(state)
        start_key_ping()
        return (
            True,
            "Private AES-256-GCM tunnel is up (192.x LAN + loopback only).\n"
            f"Private listen: {state.get('bind')}:{state['port']}\n"
            f"Private SOCKS5: 127.0.0.1:{state.get('socks_port', DEFAULT_SOCKS)}\n"
            f"Saved long-term key: {long_term} (loaded, not rotated)\n"
            f"Private session key: {session_path}"
        )


def start_public_server() -> tuple[bool, str]:
    """Start the public Internet-facing tunnel on a separate port and key."""
    global _runtime_public
    with _lock:
        if _runtime_public is not None:
            return True, "Public AES tunnel already running."
        state = write_server_files()
        state["public_bind"] = state.get("public_bind") or "0.0.0.0"
        try:
            long_term = generate_key(force=False)
            session_path = generate_public_session_key()
            key = session_path.read_bytes()
            _ensure_crypto()
        except Exception as exc:
            return False, f"Could not start public AES engine: {exc}"
        srv = TunnelServer(
            bind=state.get("public_bind") or "0.0.0.0",
            port=int(state.get("public_port") or DEFAULT_PUBLIC_PORT),
            socks_port=int(state.get("public_socks_port") or DEFAULT_PUBLIC_SOCKS),
            key=key,
        )
        try:
            srv.start()
        except OSError as exc:
            return False, f"Could not bind public tunnel port: {exc}"
        _runtime_public = srv
        state["public_running"] = True
        save_state(state)
        return (
            True,
            "Public AES-256-GCM tunnel is up (192.168.49.1, 1.1.1.1, 1.0.0.1, separate from private LAN).\n"
            f"Public listen: {state.get('public_bind')}:{state.get('public_port')}\n"
            f"Public SOCKS5: 127.0.0.1:{state.get('public_socks_port', DEFAULT_PUBLIC_SOCKS)}\n"
            f"Saved long-term key: {long_term}\n"
            f"Public session key: {session_path}"
        )


def is_tunnel_live() -> bool:
    return _runtime is not None and not _runtime._stop.is_set()


def is_public_tunnel_live() -> bool:
    return _runtime_public is not None and not _runtime_public._stop.is_set()


def probe_outside(timeout: float = 3.0) -> bool:
    targets = [("1.1.1.1", 443), ("9.9.9.9", 53), ("8.8.8.8", 443)]
    for host, port in targets:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return True
        except OSError:
            continue
    return False


def link_status() -> dict:
    live = is_tunnel_live()
    outside = probe_outside() if live else False
    if live and outside:
        label = "LIVE"
    elif live and not outside:
        label = "TUNNEL UP / OUTSIDE DEAD"
    else:
        label = "DEAD"
    return {
        "tunnel_live": live,
        "outside_live": outside,
        "label": label,
    }


class AesClient:
    """Open a remote TCP host through the local AES tunnel."""

    def __init__(self, port: int | None = None):
        state = load_state()
        self.port = int(port or state.get("port") or DEFAULT_PORT)
        # Local apps always hit the private listener on loopback.
        self.bind = "127.0.0.1"
        self.key = load_key()
        self.sock: socket.socket | None = None
        self._seq = 0
        self._io = threading.Lock()

    def connect(self, host: str, port: int) -> None:
        self.key = load_key()
        sock = socket.create_connection((self.bind, self.port), timeout=10)
        tune_socket(sock)
        self.sock = sock
        register_live_link(self)
        hello = secrets.token_bytes(16)
        sock.sendall(hello)
        ok = recv_frame(sock, self.key)
        if not ok.startswith(b"NETLOCK-OK"):
            raise ConnectionError("AES handshake failed")
        send_frame(sock, self.key, b"NETLOCK-READY")
        send_frame(sock, self.key, f"OPEN\n{host}\n{port}".encode())
        reply = recv_frame(sock, self.key)
        if reply != b"OPENED":
            raise ConnectionError(reply.decode("utf-8", errors="replace"))

    def send(self, data: bytes) -> None:
        if not self.sock:
            raise ConnectionError("closed")
        self._seq += 1
        with self._io:
            send_frame(self.sock, self.key, pack_data(self._seq, data))

    def recv(self, nbytes: int = 16384) -> bytes:
        if not self.sock:
            return b""
        while True:
            with self._io:
                frame = recv_frame(self.sock, self.key)
            if frame in (b"PING", b"PONG"):
                continue
            ptype, seq, payload = unpack_packet(frame)
            if ptype == PKT_CLOSE:
                return b""
            if ptype == PKT_ACK:
                continue
            return payload

    def close(self) -> None:
        unregister_live_link(self)
        if not self.sock:
            return
        try:
            with self._io:
                send_frame(self.sock, self.key, pack_close())
        except Exception:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        self.sock = None


def stop_server() -> tuple[bool, str]:
    global _runtime, _runtime_public
    with _lock:
        notes = []
        if _runtime is not None:
            stop_key_ping()
            _runtime.stop()
            _runtime = None
            notes.append("Private AES tunnel stopped.")
        else:
            notes.append("Private AES tunnel was not running.")
        if _runtime_public is not None:
            _runtime_public.stop()
            _runtime_public = None
            notes.append("Public AES tunnel stopped.")
        else:
            notes.append("Public AES tunnel was not running.")
        state = load_state()
        state["running"] = False
        state["public_running"] = False
        save_state(state)
        return True, " ".join(notes)


def stop_private_server() -> tuple[bool, str]:
    global _runtime
    with _lock:
        if _runtime is None:
            state = load_state()
            state["running"] = False
            save_state(state)
            return True, "Private AES tunnel was not running."
        _runtime.stop()
        _runtime = None
        state = load_state()
        state["running"] = False
        save_state(state)
        return True, "Private AES tunnel stopped."


def stop_public_server() -> tuple[bool, str]:
    global _runtime_public
    with _lock:
        if _runtime_public is None:
            state = load_state()
            state["public_running"] = False
            save_state(state)
            return True, "Public AES tunnel was not running."
        _runtime_public.stop()
        _runtime_public = None
        state = load_state()
        state["public_running"] = False
        save_state(state)
        return True, "Public AES tunnel stopped."


def status_text() -> str:
    state = load_state()
    key_path = _local_key_path()
    key_ok = key_path.exists() and key_path.stat().st_size == KEY_LEN
    live = _runtime is not None and not _runtime._stop.is_set()
    public_live = _runtime_public is not None and not _runtime_public._stop.is_set()
    link = link_status()
    return "\n".join(
        [
            "Engine: built-in AES-256-GCM — private and public tunnels are separate",
            f"Outside link: {link['label']}",
            f"Private live: {live}  (192.x + 127.0.0.1:{state.get('port')})",
            f"Public live: {public_live}  (192.168.49.1:{state.get('public_port', DEFAULT_PUBLIC_PORT)})",
            f"Public live: {public_live}  (1.1.1.1:{state.get('public_port', DEFAULT_PUBLIC_PORT)})",
            f"Public live: {public_live}  (1.0.0.1:{state.get('public_port', DEFAULT_PUBLIC_PORT)})",
            f"State private running: {state.get('running')}  public running: {state.get('public_running')}",
            f"Private TCP: {state.get('bind', '127.0.0.1')}:{state.get('port')}",
            f"Private TCP: {state.get('bind', '0.0.0.0')}:{state.get('port')}",
            f"Public TCP: {state.get('public_bind', '192.168.49.1')}:{state.get('public_port', DEFAULT_PUBLIC_PORT)}",
            f"Public TCP: {state.get('public_bind', '1.1.1.1')}:{state.get('public_port', DEFAULT_PUBLIC_PORT)}",
            f"Public TCP: {state.get('public_bind', '1.0.0.1')}:{state.get('public_port', DEFAULT_PUBLIC_PORT)}",
            f"Private SOCKS5: 127.0.0.1:{state.get('socks_port', DEFAULT_SOCKS)}",
            f"Public SOCKS5: 127.0.0.1:{state.get('public_socks_port', DEFAULT_PUBLIC_SOCKS)}",
            f"DNS list: {', '.join(state.get('dns') or [])}",
            f"Key file: {key_path} ({'present' if key_ok else 'missing — press Generate or Start'})",
        ]
    )


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="AES-256-GCM host-only tunnel")
    p.add_argument(
        "command",
        choices=["generate", "start", "start-private", "start-public", "stop", "stop-public", "status"],
    )
    p.add_argument("--port", type=int)
    p.add_argument("--dns")
    args = p.parse_args()
    if args.command == "generate":
        dns = [x.strip() for x in args.dns.split(",")] if args.dns else None
        print(json.dumps(write_server_files(port=args.port, dns=dns), indent=2))
    elif args.command in {"start", "start-private"}:
        ok, msg = start_server()
        print(msg)
        if ok:
            try:
                threading.Event().wait()
            except KeyboardInterrupt:
                stop_server()
        raise SystemExit(0 if ok else 1)
    elif args.command == "start-public":
        ok, msg = start_public_server()
        print(msg)
        if ok:
            try:
                threading.Event().wait()
            except KeyboardInterrupt:
                stop_public_server()
        raise SystemExit(0 if ok else 1)
    elif args.command == "stop":
        ok, msg = stop_server()
        print(msg)
        raise SystemExit(0 if ok else 1)
    elif args.command == "stop-public":
        ok, msg = stop_public_server()
        print(msg)
        raise SystemExit(0 if ok else 1)
    else:
        print(status_text())
