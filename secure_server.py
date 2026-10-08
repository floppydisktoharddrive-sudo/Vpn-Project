#!/usr/bin/env python3
"""Encrypted 0.0.0.0 listener. Accepts every interface, in and out.

The bind address on the socket is the real wildcard. The address, port, and
connection are sealed with the revolving key in secure_stream.py. Parallel
process binds are owned by parallel_processor.py.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import threading
import time
from pathlib import Path

import data_stream
import parallel_processor
import secure_stream

BASE = Path(__file__).resolve().parent
DATA = BASE / "vpn_data"
LOCK = DATA / "secure_server.pid"
STATE = DATA / "secure_server.json"
WILDCARD = "0.0.0.0"
CONTROL_PORT = 51823
UDP_PORT = 51824

_stop = threading.Event()
_threads: list[threading.Thread] = []
_sockets: list[socket.socket] = []


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    except SystemError:
        return False
    return True


def already_running() -> int:
    try:
        pid = int(LOCK.read_text(encoding="utf-8").strip() or "0")
    except (OSError, ValueError):
        return 0
    return pid if _pid_alive(pid) else 0


def _write_state(**extra) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    rec = {
        "wildcard": WILDCARD,
        "token": secure_stream.seal_wildcard(CONTROL_PORT, os.getpid(), "control"),
        "control_port": CONTROL_PORT,
        "udp_port": UDP_PORT,
        "pid": os.getpid(),
        "generation": secure_stream.ring().generation,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    rec.update(extra)
    STATE.write_text(json.dumps(rec, indent=2), encoding="utf-8")


def _tcp_loop(sock: socket.socket) -> None:
    sock.settimeout(1.0)
    while not _stop.is_set():
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        peer = f"{addr[0]}:{addr[1]}"
        secure_stream.rotate_now("tcp-in")
        token = secure_stream.seal_wildcard(CONTROL_PORT, os.getpid(), peer)
        try:
            blob = conn.recv(65536)
            data_stream.traffic("in", len(blob), peer, CONTROL_PORT, os.getpid())
            sealed, plain = secure_stream.end_to_end(blob or token.encode("ascii"))
            conn.sendall(plain)
            data_stream.traffic("out", len(sealed), peer, CONTROL_PORT, os.getpid())
            data_stream.event("tcp", f"{WILDCARD}:{CONTROL_PORT} {peer} token={token[:18]}")
        except OSError as exc:
            data_stream.event("tcp-fail", f"{peer} {exc}")
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _udp_loop(sock: socket.socket) -> None:
    sock.settimeout(1.0)
    while not _stop.is_set():
        try:
            blob, addr = sock.recvfrom(65536)
        except socket.timeout:
            continue
        except OSError:
            break
        peer = f"{addr[0]}:{addr[1]}"
        secure_stream.rotate_now("udp-in")
        data_stream.traffic("in", len(blob), peer, UDP_PORT, os.getpid())
        sealed, plain = secure_stream.end_to_end(blob)
        try:
            sock.sendto(plain, addr)
            data_stream.traffic("out", len(sealed), peer, UDP_PORT, os.getpid())
        except OSError as exc:
            data_stream.event("udp-fail", f"{peer} {exc}")


def _rotate_loop() -> None:
    while not _stop.is_set():
        secure_stream.ring().maybe_rotate()
        _write_state(binds=parallel_processor.list_binds())
        _stop.wait(5)


def start_background() -> dict:
    """Start unless another secure_server already holds the lock."""
    running = already_running()
    if running:
        return {"ok": True, "already": True, "pid": running, "wildcard": WILDCARD}
    DATA.mkdir(parents=True, exist_ok=True)
    LOCK.write_text(str(os.getpid()), encoding="utf-8")
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((WILDCARD, CONTROL_PORT))
    tcp.listen(128)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((WILDCARD, UDP_PORT))
    _sockets[:] = [tcp, udp]
    token = secure_stream.seal_wildcard(CONTROL_PORT, os.getpid(), "listen")
    vpn_key = DATA / "aes256.key"
    guard_token = secure_stream.seal_wildcard(CONTROL_PORT, os.getpid(), "vpn-guard" if vpn_key.exists() else "vpn-guard-pending")
    data_stream.note_bind(os.getpid(), CONTROL_PORT, token, "secure_server")
    data_stream.event("listen", f"{WILDCARD}:{CONTROL_PORT} tcp and {WILDCARD}:{UDP_PORT} udp")
    data_stream.event("vpn-guard", f"{WILDCARD} sealed generation={secure_stream.ring().generation} token={guard_token[:18]}")
    parallel_processor.start()
    _stop.clear()
    for target, args in ((_tcp_loop, (tcp,)), (_udp_loop, (udp,)), (_rotate_loop, ())):
        thread = threading.Thread(target=target, args=args, daemon=True, name=target.__name__)
        thread.start()
        _threads.append(thread)
    _write_state()
    try:
        import persist
        persist.write_applied_and_save({
            "wildcard": WILDCARD,
            "wildcard_port": CONTROL_PORT,
            "wildcard_token": token,
            "vpn_guard": True,
        })
    except Exception:
        pass
    return {"ok": True, "already": False, "pid": os.getpid(), "wildcard": WILDCARD, "port": CONTROL_PORT, "token": token}


def stop() -> dict:
    """Close the 0.0.0.0 listener. Does not touch DHCP."""
    _stop.set()
    for sock in list(_sockets):
        try:
            sock.close()
        except OSError:
            pass
    _sockets.clear()
    try:
        LOCK.unlink()
    except OSError:
        pass
    try:
        import persist
        persist.write_applied_and_save({"wildcard": False, "vpn_guard": False})
    except Exception:
        pass
    return {"ok": True, "wildcard": False}


def serve_forever() -> None:
    rec = start_background()
    print(f"Wildcard {WILDCARD} secure server pid={rec.get('pid')} already={rec.get('already')}")
    if rec.get("already"):
        return
    try:
        while not _stop.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        _stop.set()


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted 0.0.0.0 wildcard listener")
    parser.add_argument("--boot", action="store_true", help="Stay up for start.bat")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()
    if args.status:
        print(STATE.read_text(encoding="utf-8") if STATE.exists() else "not running")
        return
    if args.boot:
        serve_forever()
        return
    print(json.dumps(start_background()))


if __name__ == "__main__":
    main()
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
