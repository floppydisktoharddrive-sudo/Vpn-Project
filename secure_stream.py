#!/usr/bin/env python3
"""Revolving-key seal for the 0.0.0.0 wildcard, ports, and connections.

The kernel still binds the literal address 0.0.0.0. What is stored and sent
on the wire is the sealed form, rotated the same way vpn_server rotates the
session key: current key encrypts, previous key still opens in-flight frames.
"""

from __future__ import annotations

import base64
import os
import secrets
import struct
import threading
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA = BASE / "vpn_data"
KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
WILDCARD = "0.0.0.0"
ROTATE_SECONDS = 30.0

def _aesgcm():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM


class RevolvingKey:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (DATA / "wildcard.key")
        self.prev_path = DATA / "wildcard.prev.key"
        self._lock = threading.Lock()
        self.key = self._load_or_create()
        self.prev: bytes | None = self._read(self.prev_path)
        self.generation = 0
        self.rotated_at = time.time()

    def _read(self, path: Path) -> bytes | None:
        try:
            blob = path.read_bytes()
        except OSError:
            return None
        return blob if len(blob) == KEY_LEN else None

    def _load_or_create(self) -> bytes:
        DATA.mkdir(parents=True, exist_ok=True)
        existing = self._read(self.path)
        if existing:
            return existing
        key = secrets.token_bytes(KEY_LEN)
        self.path.write_bytes(key)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return key

    def rotate(self, reason: str = "interval") -> bytes:
        with self._lock:
            self.prev = self.key
            self.key = secrets.token_bytes(KEY_LEN)
            self.generation += 1
            self.rotated_at = time.time()
            try:
                self.prev_path.write_bytes(self.prev)
                self.path.write_bytes(self.key)
            except OSError:
                pass
        return self.key

    def maybe_rotate(self) -> None:
        if time.time() - self.rotated_at >= ROTATE_SECONDS:
            self.rotate("interval")

    def keys(self) -> list[bytes]:
        with self._lock:
            out = [self.key]
            if self.prev and self.prev not in out:
                out.append(self.prev)
            return out

    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        self.maybe_rotate()
        AESGCM = _aesgcm()
        nonce = secrets.token_bytes(NONCE_LEN)
        with self._lock:
            key = self.key
            gen = self.generation
        blob = AESGCM(key).encrypt(nonce, plaintext, aad)
        return struct.pack("!I", gen) + nonce + blob

    def open(self, blob: bytes, aad: bytes = b"") -> bytes:
        if len(blob) < 4 + NONCE_LEN + TAG_LEN:
            raise ValueError("short sealed blob")
        nonce = blob[4:4 + NONCE_LEN]
        body = blob[4 + NONCE_LEN:]
        AESGCM = _aesgcm()
        last = None
        for key in self.keys():
            try:
                return AESGCM(key).decrypt(nonce, body, aad)
            except Exception as exc:
                last = exc
        raise ValueError(f"revolving key open failed: {last}")


_ring: RevolvingKey | None = None
_ring_lock = threading.Lock()


def ring() -> RevolvingKey:
    global _ring
    with _ring_lock:
        if _ring is None:
            _ring = RevolvingKey()
        return _ring


def seal_wildcard(port: int, pid: int = 0, peer: str = "") -> str:
    """Seal 0.0.0.0 plus the port and connection, same key as live frames."""
    raw = f"{WILDCARD}|{int(port)}|{int(pid)}|{peer}".encode("utf-8", errors="replace")
    token = ring().seal(raw, aad=b"wildcard")
    return base64.b64encode(token).decode("ascii")


def open_wildcard(token: str) -> dict:
    blob = base64.b64decode(token.encode("ascii"))
    raw = ring().open(blob, aad=b"wildcard")
    host, port, pid, peer = raw.decode("utf-8", errors="replace").split("|", 3)
    return {"wildcard": host, "port": int(port), "pid": int(pid), "peer": peer}


def seal_frame(payload: bytes) -> bytes:
    return ring().seal(payload, aad=b"frame")


def open_frame(blob: bytes) -> bytes:
    return ring().open(blob, aad=b"frame")


def end_to_end(payload: bytes) -> tuple[bytes, bytes]:
    """Seal onto the revolving AES stream. Caller decrypts only at an endpoint."""
    sealed = seal_frame(payload)
    return sealed, sealed


def open_endpoint(blob: bytes) -> bytes:
    """Decrypt only at a stream endpoint. Middle hops keep the sealed frame."""
    try:
        return open_frame(blob)
    except Exception:
        return blob


def rotate_now(reason: str = "connection") -> int:
    ring().rotate(reason)
    return ring().generation
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
