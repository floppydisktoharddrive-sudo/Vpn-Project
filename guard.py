#!/usr/bin/env python3
"""
Parallel HTTP/HTTPS filter + connection guard.

- HTTP proxy on 127.0.0.1:8080 (CONNECT for HTTPS, plain HTTP otherwise)
- Denies blocked hostnames before a payload is forwarded
- Polls OS sockets and can terminate rows that match block rules
  (blocked sites, inbound SQL, inbound foreign VPN ports)

This does not decrypt TLS. HTTPS is intercepted at CONNECT / socket level.
"""

from __future__ import annotations

import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import apps
import blocker
import connections
import dns_force
import engine
import network_boot
import persist
import vpn_server
import wintun_tun

PARALLEL = 16
_http_pool = ThreadPoolExecutor(max_workers=PARALLEL, thread_name_prefix="http-par")

HTTP_PORT = 8080
HTTP_BIND = "127.0.0.1"
# HTTP/HTTPS stay on the local proxy. VPN only monitors in parallel.
HTTP_THROUGH_VPN = False
SQL_PORTS = {"1433", "1434", "3306", "5432", "1521", "14330"}
VPN_PORTS = {"1194", "500", "4500", "1701", "1723", "51820"}
SAFE_LOCAL = {"127.0.0.1", "0.0.0.0", "::", "::1", "*"}
OWN_PORTS = {"8080", "1080", "1081", "51821", "51822", "53", "5353"}
SAFE_APPS = (
    "lm studio",
    "lmstudio",
    "llm studio",
    "llmstudio",
    "ollama",
    "llama",
    "huggingface",
    "chrome",
    "msedge",
    "firefox",
    "python",
)

SYSTEM_APPS = (
    "system",
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "wininit.exe",
    "csrss.exe",
    "smss.exe",
    "winlogon.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "spoolsv.exe",
    "searchindexer.exe",
    "conhost.exe",
    "runtimebroker.exe",
)
PASSTHROUGH_SUFFIXES = (
    "lmstudio.ai",
    "lmstudio.dev",
    "huggingface.co",
    "hf.co",
    "githubusercontent.com",
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "ytimg.com",
    "yt3.ggpht.com",
    "ggpht.com",
    "googlevideo.com",
    "gvt1.com",
    "gvt2.com",
    "widevine.com",
    "yt3.googleusercontent.com",
    "googleusercontent.com",
    "googleapis.com",
    "gstatic.com",
    "yt.be",
)


def _passthrough_host(host: str) -> bool:
    h = (host or "").split(":")[0].lower()
    return any(h == s or h.endswith("." + s) for s in PASSTHROUGH_SUFFIXES)

_stop = threading.Event()
_threads: list[threading.Thread] = []
_sockets: list[socket.socket] = []
_blocked_names: set[str] = set()
_own_pids: set[str] = set()
_lock = threading.Lock()


def _port_of(endpoint: str) -> str:
    if not endpoint:
        return ""
    if "]" in endpoint:
        return endpoint.rsplit("]", 1)[-1].lstrip(":").split(" ")[0]
    if endpoint.count(":") == 1:
        return endpoint.split(":")[-1]
    return endpoint.rsplit(":", 1)[-1]


def _host_of(endpoint: str) -> str:
    if not endpoint:
        return ""
    if endpoint.startswith("["):
        return endpoint.split("]")[0].lstrip("[")
    if endpoint.count(":") == 1:
        return endpoint.split(":")[0]
    return endpoint.rsplit(":", 1)[0]


_blocked_ips: set[str] = set()


def refresh_blocklist() -> set[str]:
    names = {s.lower().strip() for s in blocker.blocked_hosts()}
    _blocked_names.clear()
    _blocked_names.update(names)
    _blocked_ips.clear()
    _blocked_ips.update(blocker.blocked_ips())
    return names


def _is_our_port(port: str, tunnel_port: int) -> bool:
    if port in OWN_PORTS or port == str(tunnel_port):
        return True
    if port.isdigit() and 18100 <= int(port) <= 18600:
        return True
    return False


def _protected_site_names() -> set[str]:
    try:
        return {h.lower() for h in blocker.protected_hosts()}
    except Exception:
        return set()


def _peer_is_protected_site(host: str) -> bool:
    host = (host or "").lower().strip()
    if not host:
        return False
    for name in _protected_site_names():
        if host == name or host.endswith("." + name) or name.endswith("." + host):
            return True
    return False


def _app_allowed(row: dict) -> bool:
    app = (row.get("app") or "").lower()
    if not app:
        return False
    if any(s in app for s in SAFE_APPS) or any(app.endswith(s) or app == s for s in SYSTEM_APPS):
        return True
    return apps.is_protected_app(app)


def _is_inbound(row: dict, lport: str, rport: str, state: str) -> bool:
    """Only unsolicited inbound. User-opened outbound sockets are never inbound."""
    if state in {"LISTEN", "SYN_RECV", "SYN_RCVD"}:
        return True
    if state != "ESTABLISHED":
        return False
    if _app_allowed(row):
        return False
    if lport.isdigit() and rport.isdigit():
        lp, rp = int(lport), int(rport)
        # Client sockets use an ephemeral local port toward a well-known remote port.
        if rp < 49152 and lp >= 49152:
            return False
        if lp < 49152 and rp >= 49152:
            return True
    if lport in SQL_PORTS or lport in VPN_PORTS or lport in {"3389", "22", "21", "25", "445", "139", "5357"}:
        return True
    return False


def classify(row: dict, tunnel_port: int = 51821) -> str:
    remote = (row.get("remote") or "").lower()
    local = (row.get("local") or "").lower()
    rhost, rport = _host_of(remote), _port_of(remote)
    lhost, lport = _host_of(local), _port_of(local)
    state = (row.get("state") or "").upper()

    if _is_our_port(lport, tunnel_port) or _is_our_port(rport, tunnel_port):
        return "ok"
    try:
        protected_dns = {d.lower() for d in blocker.protected_dns()}
        rec = persist.load_applied()
        for extra in rec.get("protected_dns") or rec.get("dhcp_dns") or []:
            if extra:
                protected_dns.add(str(extra).lower())
        if rhost in protected_dns or lhost in protected_dns or rport in {"53", "5353"}:
            return "ok"
    except Exception:
        pass
    lan = network_boot.lan_safe_ips()
    if blocker._is_local_or_lan_ip(rhost) or blocker._is_local_or_lan_ip(lhost) or rhost in lan or lhost in lan:
        if rport in {"80", "443"} or lport in {"80", "443", "8080", "1080"}:
            return "http-lan-ok"
        return "ok"
    if _peer_is_protected_site(rhost) or _peer_is_protected_site(lhost):
        return "ok"
    if _is_inbound(row, lport, rport, state):
        if _app_allowed(row):
            return "ok"
        if state == "LISTEN" and lhost in SAFE_LOCAL and _is_our_port(lport, tunnel_port):
            return "ok"
        return "third-party-in"
    # Outbound from a user app is allowed unless the remote IP is already blacklisted.
    if rhost in _blocked_ips or any(rhost.startswith(ip) for ip in _blocked_ips if ip):
        if blocker._is_local_or_lan_ip(rhost):
            return "ok"
        return "blocked-ip"
    if any(name in remote or rhost.endswith(name) or name.startswith(rhost) for name in _blocked_names):
        return "blocked-host"
    if lport in SQL_PORTS and state in {"LISTEN", "ESTABLISHED", "SYN_RECV"}:
        if lhost not in SAFE_LOCAL or state != "LISTEN":
            return "sql-inbound"
        if state == "LISTEN":
            return "sql-listen"
    if lport in VPN_PORTS and lport != str(tunnel_port):
        return "vpn-inbound"
    if rport in SQL_PORTS and state == "ESTABLISHED":
        return "sql-outbound"
    if rport in {"80", "443", "8080", "1080"} and state in {
        "ESTABLISHED",
        "SYN_SENT",
        "SYN_RCVD",
        "TIME_WAIT",
    }:
        return "http-out"
    return "ok"


def terminate_pid(pid: str) -> tuple[bool, str]:
    if not pid or not str(pid).isdigit():
        return False, "no pid"
    if str(pid) in _own_pids or str(pid) == str(os.getpid()):
        return False, "refusing to kill this program"
    app = (connections.process_map().get(str(pid)) or "").lower()
    if any(s in app for s in SAFE_APPS) or apps.is_protected_app(app):
        return False, f"protected app {app}"
    if os.name == "nt":
        import subprocess

        res = subprocess.run(
            ["taskkill", "/PID", str(pid), "/F"],
            capture_output=True,
            text=True,
        )
        ok = res.returncode == 0
        return ok, (res.stdout or res.stderr or "").strip()
    try:
        os.kill(int(pid), 15)
        return True, f"signaled {pid}"
    except OSError as exc:
        return False, str(exc)


def scan_and_act(kill: bool = False, tunnel_port: int = 51821) -> list[dict]:
    refresh_blocklist()
    rows = connections.list_connections()
    flagged = []
    for row in rows:
        tag = classify(row, tunnel_port=tunnel_port)
        row["tag"] = tag
        if tag != "ok":
            flagged.append(row)
            if tag in {"sql-inbound", "vpn-inbound", "sql-outbound", "third-party-in", "piggyback"}:
                engine.note_hit(tag, f"{row.get('remote')} pid={row.get('pid')}")
                row["action"] = "observe-only; port lock removed"
                continue
            if kill and tag in {"blocked-host", "blocked-ip"}:
                engine.note_hit(tag, f"{row.get('remote')} pid={row.get('pid')}")
                ok, msg = terminate_pid(row.get("pid") or "")
                row["action"] = msg if ok else f"not killed: {msg}"
    return flagged


_http_leftover: dict[int, bytearray] = {}


def _recv_line(sock: socket.socket) -> bytes:
    """Read one HTTP line without dropping bytes that arrived in the same packet."""
    key = id(sock)
    buf = _http_leftover.setdefault(key, bytearray())
    while b"\n" not in buf and len(buf) < 16384:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf.extend(chunk)
    nl = buf.find(b"\n")
    if nl >= 0:
        line = bytes(buf[: nl + 1])
        del buf[: nl + 1]
        return line
    line = bytes(buf)
    buf.clear()
    _http_leftover.pop(key, None)
    return line


def _host_allowed(host: str) -> bool:
    host = (host or "").split(":")[0].lower().strip()
    if not host:
        return True
    for name in _blocked_names:
        if host == name or host.endswith("." + name):
            return False
    return True


def _split_host_port(host: str, default_port: int) -> tuple[str, int]:
    host = (host or "").strip()
    if host.startswith("[") and "]" in host:
        name, rest = host[1:].split("]", 1)
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else default_port
        return name, port
    if host.count(":") == 1:
        name, port_s = host.split(":")
        return name, int(port_s) if port_s.isdigit() else default_port
    return host, default_port


def _seal_http(data: bytes, kind: str) -> bytes:
    """Endpoint already has the bytes. Do not seal/open 4KB slices or log each chunk."""
    return data


def _pipe_aes(client: socket.socket, link) -> None:
    def to_net():
        import data_stream
        up_pending = bytearray()
        try:
            while True:
                data = client.recv(262144)
                if not data:
                    break
                hit = engine.inspect_payload(data)
                if hit:
                    engine.note_hit(hit, "https-up")
                    break
                data = _seal_http(data, "https-up")
                try:
                    import stream

                    stream.traffic("up", len(data), "aes")
                except Exception:
                    pass
                import data_stream
                data_stream.send_small(client, link, data, up_pending)
            rest = data_stream.drain_small(up_pending)
            if rest:
                link.send(rest)
        except OSError:
            pass
        try:
            link.close()
        except Exception:
            pass

    def to_app():
        import data_stream
        down_pending = bytearray()
        try:
            while True:
                data = link.recv()
                if not data:
                    break
                hit = engine.inspect_payload(data)
                if hit:
                    engine.note_hit(hit, "https-down")
                    break
                data = _seal_http(data, "https-down")
                try:
                    import stream

                    stream.traffic("down", len(data), "aes")
                except Exception:
                    pass
                import data_stream
                data_stream.send_small(link, client, data, down_pending)
            rest = data_stream.drain_small(down_pending)
            if rest:
                client.sendall(rest)
        except OSError:
            pass
        try:
            client.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    t = threading.Thread(target=to_app, daemon=True)
    t.start()
    to_net()
    t.join()


def _mitm_https(client: socket.socket, dest: str, port: int) -> None:
    import ca_store

    try:
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        ctx_srv = ca_store.server_ssl_context(dest)
        tls_client = ctx_srv.wrap_socket(client, server_side=True)
        raw = socket.create_connection((dest, port), timeout=20)
        vpn_server.tune_socket(raw)
        tls_remote = ca_store.client_ssl_context().wrap_socket(raw, server_hostname=dest)

        def inspect_and_send(src, dst):
            try:
                while True:
                    data = src.recv(1024 * 1024)
                    if not data:
                        break
                    hit = engine.inspect_payload(data)
                    if hit:
                        engine.note_hit(hit, dest)
                        break
                    dst.sendall(_seal_http(data, "https"))
            except OSError:
                pass

        t = threading.Thread(target=inspect_and_send, args=(tls_remote, tls_client), daemon=True)
        t.start()
        inspect_and_send(tls_client, tls_remote)
        t.join()
    except Exception:
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except OSError:
            pass


def _handle_http(client: socket.socket) -> None:
    client.settimeout(20)
    try:
        first = _recv_line(client)
        if not first:
            return
        parts = first.decode("iso-8859-1", errors="replace").split()
        if len(parts) < 2:
            return
        method, target = parts[0].upper(), parts[1]
        headers = [first]
        while True:
            line = _recv_line(client)
            headers.append(line)
            if line in (b"\r\n", b"\n", b""):
                break
        host = ""
        if method == "CONNECT":
            host = target.split("/")[0]
        else:
            for raw in headers:
                if raw.lower().startswith(b"host:"):
                    host = raw.split(b":", 1)[1].strip().decode("iso-8859-1", errors="replace")
            if not host:
                parsed = urlsplit(target)
                host = parsed.netloc or parsed.path
        refresh_blocklist()
        if not _host_allowed(host):
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nblocked host")
            persist.write_applied_and_save({"last_block": host})
            engine.note_hit("blocked-host", host)
            return
        raw_head = b"".join(headers)
        dest_guess = (host or "").split(":")[0]
        if _passthrough_host(dest_guess):
            inj = None
        else:
            inj = engine.inspect_payload(raw_head)
        if inj:
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\ninjection blocked")
            engine.note_hit(inj, host)
            return
        dest, port = _split_host_port(host, 443 if method == "CONNECT" else 80)
        if method != "CONNECT":
            parsed = urlsplit(target if target.startswith("http") else "http://" + (host or "localhost") + target)
            dest = parsed.hostname or dest
            port = parsed.port or 80
        # Video CDNs must go direct TCP. AES/MITM chunking causes YouTube buffering lag.
        if _passthrough_host(dest):
            try:
                remote = socket.create_connection((dest, int(port)), timeout=20)
                vpn_server.tune_socket(remote)
                vpn_server.tune_socket(client)
            except OSError:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return
            if method == "CONNECT":
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                remote.sendall(b"".join(headers))
            _pipe(client, remote, dest)
            return
        if HTTP_THROUGH_VPN and vpn_server.is_tunnel_live():
            link = vpn_server.AesClient()
            try:
                link.connect(dest, int(port))
            except Exception:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\nAES tunnel OPEN failed")
                return
            if method == "CONNECT":
                if _passthrough_host(dest):
                    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    _pipe_aes(client, link)
                else:
                    # AES OPEN already succeeded; keep that path so CONNECT
                    # is not dropped onto a second direct TCP socket.
                    try:
                        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        _pipe_aes(client, link)
                    except Exception:
                        try:
                            link.close()
                        except Exception:
                            pass
                        _mitm_https(client, dest, int(port))
                return
            link.send(b"".join(headers))
            _pipe_aes(client, link)
            return
        try:
            remote = socket.create_connection((dest, int(port)), timeout=15)
        except OSError:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        if method == "CONNECT":
            import data_stream
            if _passthrough_host(dest):
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                _pipe(client, remote, dest)
            elif data_stream.upload_host(dest):
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                _pipe(client, remote, dest)
            else:
                _mitm_https(client, dest, int(port))
            return
        remote.sendall(b"".join(headers))
        _pipe(client, remote, dest)
    except Exception:
        pass
    finally:
        _http_leftover.pop(id(client), None)
        try:
            client.close()
        except OSError:
            pass


def _pipe(a: socket.socket, b: socket.socket, host: str = "") -> None:
    upload = False
    try:
        import data_stream
        upload = data_stream.upload_host(host)
    except Exception:
        upload = False

    def one(src, dst):
        pending = bytearray()
        uploading = upload and src is a
        try:
            while True:
                data = src.recv(1024 * 1024)
                if not data:
                    break
                if uploading:
                    import data_stream
                    data_stream.send_upload_bytes(dst, data)
                    continue
                hit = engine.inspect_payload(data)
                if hit:
                    engine.note_hit(hit, "http")
                    break
                data = _seal_http(data, "http-down" if src is b else "http-up")
                try:
                    import stream

                    stream.traffic("down" if src is b else "up", len(data), "tcp")
                except Exception:
                    pass
                import data_stream
                data_stream.send_small(src, dst, data, pending)
            rest = data_stream.drain_small(pending)
            if rest:
                dst.sendall(rest)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    t = threading.Thread(target=one, args=(b, a), daemon=True)
    t.start()
    one(a, b)


def _http_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HTTP_BIND, HTTP_PORT))
    srv.listen(PARALLEL * 2)
    srv.settimeout(1.0)
    _sockets.append(srv)
    while not _stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        _http_pool.submit(_handle_http, conn)


def _guard_loop(tunnel_port: int) -> None:
    while not _stop.is_set():
        try:
            scan_and_act(kill=True, tunnel_port=tunnel_port)
            extra = engine.scan_hidden_and_mirror(kill=True)
            for row in extra:
                if row.get("tag") in {"hidden", "ip-mirror", "blocked-ip", "piggyback"}:
                    terminate_pid(row.get("pid") or "")
        except Exception:
            pass
        _stop.wait(15.0)


def set_system_proxy(enable: bool) -> str:
    if os.name != "nt":
        return "proxy skipped (not Windows)"
    import subprocess

    if enable:
        subprocess.run(["netsh", "winhttp", "set", "proxy", "127.0.0.1:8080"], capture_output=True, text=True)
        cmd = (
            "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
            "-Name ProxyEnable -Value 1; "
            "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
            "-Name ProxyServer -Value '127.0.0.1:8080'; "
            "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
            "-Name ProxyOverride -Value '*.lmstudio.ai;search.lmstudio.ai;*.huggingface.co;localhost;127.0.0.1;<local>'"
        )
        subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True)
        return "System proxy set to 127.0.0.1:8080 (HTTP/HTTPS filter; VPN monitors in parallel)"
    subprocess.run(["netsh", "winhttp", "reset", "proxy"], capture_output=True, text=True)
    cmd = (
        "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
        "-Name ProxyEnable -Value 0"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True)
    return "System proxy cleared"


def start_inbound_watch(tunnel_port: int = 51821) -> tuple[bool, str]:
    """Kill third-party inbound without starting the AES server."""
    global _threads
    with _lock:
        alive = [x for x in _threads if x.is_alive()]
        guard_alive = any(t.name == "conn-guard" for t in alive)
        http_alive = any(t.name == "http-https-filter" for t in alive)
        if guard_alive and http_alive:
            return True, "Inbound watch already running"
        _stop.clear()
        refresh_blocklist()
        _own_pids.add(str(os.getpid()))
        apps.sync_open_apps()
        extra = []
        # Boot sets the system proxy to :8080; the HTTP listener must exist
        # even when the AES server is still OFF, or browsers hang.
        if not http_alive:
            t_http = threading.Thread(target=_http_server, name="http-https-filter", daemon=True)
            extra.append(t_http)
            t_http.start()
        if not guard_alive:
            t = threading.Thread(target=_guard_loop, args=(tunnel_port,), name="conn-guard", daemon=True)
            extra.append(t)
            t.start()
        _threads = alive + extra
        persist.write_applied_and_save({"inbound_watch": True, "http_proxy": f"127.0.0.1:{HTTP_PORT}"})
        return True, "Inbound watch on: only protected apps and protected sites may accept inbound. Third-party data connections are terminated."


def start(tunnel_port: int = 51821) -> tuple[bool, str]:
    global _threads
    with _lock:
        alive = [t for t in _threads if t.is_alive()]
        http_alive = any(t.name == "http-https-filter" for t in alive)
        guard_alive = any(t.name == "conn-guard" for t in alive)
        if http_alive and guard_alive:
            return True, f"HTTP/HTTPS guard already running on 127.0.0.1:{HTTP_PORT}"
        _stop.clear()
        refresh_blocklist()
        _own_pids.add(str(os.getpid()))
        protected = apps.sync_open_apps()
        persist.write_applied_and_save({"protected_apps": protected})
        extra = []
        if not http_alive:
            t1 = threading.Thread(target=_http_server, name="http-https-filter", daemon=True)
            extra.append(t1)
            t1.start()
        if not guard_alive:
            t2 = threading.Thread(target=_guard_loop, args=(tunnel_port,), name="conn-guard", daemon=True)
            extra.append(t2)
            t2.start()
        _threads = alive + extra
        proxy_msg = set_system_proxy(True)
        dns_msg = dns_force.start()
        tun_ok, tun_msg = wintun_tun.start()
        try:
            import ca_store

            ca_msg = ca_store.install_windows_trust()
        except Exception as exc:
            ca_msg = f"CA install skipped: {exc}"
        persist.write_applied_and_save({"http_guard": True, "http_proxy": f"127.0.0.1:{HTTP_PORT}", "wintun": tun_msg})
        return (
            True,
            "HTTP/HTTPS filter + connection guard running in parallel with the AES tunnel.\n"
            f"Local HTTP proxy: 127.0.0.1:{HTTP_PORT}\n"
            f"{proxy_msg}\n"
            f"{dns_msg}\n"
            f"{tun_msg}\n"
            f"{ca_msg}\n"
            "Outbound HTTP/HTTPS started by this PC is allowed (browsers, downloaders).\n"
            "Those sessions are framed through AES when the tunnel is LIVE.\n"
            f"16 parallel workers. Desktop apps added to protection: {', '.join(protected[:12]) or '(none)'}\n"
            "Engine watches SQL-injection text, hidden sockets, mirrored IPs; rotates session key on hit.",
        )


def stop() -> tuple[bool, str]:
    _stop.set()
    for s in list(_sockets):
        try:
            s.close()
        except OSError:
            pass
    _sockets.clear()
    proxy_msg = set_system_proxy(False)
    dns_msg = dns_force.stop()
    tun_msg = wintun_tun.stop()
    persist.write_applied_and_save({"http_guard": False})
    return True, f"HTTP/HTTPS guard stopped. {proxy_msg} {dns_msg} {tun_msg}"


def running() -> bool:
    return any(t.is_alive() for t in _threads)
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
