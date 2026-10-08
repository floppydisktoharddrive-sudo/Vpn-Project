#!/usr/bin/env python3
"""Local CA for this PC only. Used to inspect HTTPS on the local proxy."""

from __future__ import annotations

import os
import socket
import ssl
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
CA_DIR = BASE / "vpn_data" / "ca"
CA_KEY = CA_DIR / "ca.key"
CA_CERT = CA_DIR / "ca.crt"
HOST_DIR = CA_DIR / "hosts"


def _ensure_crypto():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    return rsa, hashes, serialization, x509, NameOID


def generate_ca() -> Path:
    rsa, hashes, serialization, x509, NameOID = _ensure_crypto()
    CA_DIR.mkdir(parents=True, exist_ok=True)
    if CA_KEY.exists() and CA_CERT.exists():
        return CA_CERT
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NetLock Local CA")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    CA_KEY.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    CA_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return CA_CERT


def install_windows_trust() -> str:
    generate_ca()
    if os.name != "nt":
        return f"CA written to {CA_CERT} (install into the OS trust store manually)"
    res = subprocess.run(
        ["certutil", "-user", "-addstore", "Root", str(CA_CERT)],
        capture_output=True,
        text=True,
    )
    extra = subprocess.run(
        ["certutil", "-addstore", "Root", str(CA_CERT)],
        capture_output=True,
        text=True,
    )
    if res.returncode == 0 or extra.returncode == 0:
        return f"NetLock CA trusted in Windows Root. File: {CA_CERT}"
    return f"CA file ready at {CA_CERT}. Trust install: {(res.stderr or res.stdout or extra.stderr)[:200]}"


def host_material(hostname: str) -> tuple[Path, Path]:
    rsa, hashes, serialization, x509, NameOID = _ensure_crypto()
    generate_ca()
    HOST_DIR.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in ".-" else "_" for c in hostname)[:80]
    key_path = HOST_DIR / f"{safe}.key"
    crt_path = HOST_DIR / f"{safe}.crt"
    if key_path.exists() and crt_path.exists():
        return key_path, crt_path
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.x509 import load_pem_x509_certificate

    ca_key = load_pem_private_key(CA_KEY.read_bytes(), password=None)
    ca_cert = load_pem_x509_certificate(CA_CERT.read_bytes())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])])
    now = datetime.now(timezone.utc)
    try:
        import ipaddress

        san = x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        san = x509.DNSName(hostname)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName([san]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, crt_path


def server_ssl_context(hostname: str) -> ssl.SSLContext:
    key_path, crt_path = host_material(hostname)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt_path), str(key_path))
    return ctx


def client_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
