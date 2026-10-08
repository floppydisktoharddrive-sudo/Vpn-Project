#!/usr/bin/env python3
"""Settings and start path for the Parallel processes tab.

Reads the configured firewall mode and VPN server bind, then starts
secure_server, secure_stream, and parallel_processor on the shared pools.
"""

from __future__ import annotations

import worker_pool

worker_pool.attach(__name__)


def load_settings() -> dict:
    import netlock
    import persist
    import vpn_server

    saved = persist.load_applied()
    firewall = netlock.load_state()
    vpn = vpn_server.load_state()
    dns = saved.get("tunnel_dns") or firewall.get("tunnel_dns") or vpn.get("dns") or []
    if isinstance(dns, str):
        dns = [part.strip() for part in dns.split(",") if part.strip()]
    return {
        "firewall_mode": saved.get("firewall_mode") or firewall.get("mode") or "off",
        "tunnel_port": int(saved.get("tunnel_port") or firewall.get("tunnel_port") or vpn.get("port") or 51821),
        "dns": ",".join(str(item) for item in dns),
        "bind": saved.get("bind") or vpn.get("bind") or "127.0.0.1",
        "socks_port": int(vpn.get("socks_port") or saved.get("socks_port") or 1080),
        "public_bind": saved.get("public_bind") or vpn.get("public_bind") or "0.0.0.0",
        "public_port": int(vpn.get("public_port") or saved.get("public_port") or 51822),
        "wildcard": bool(saved.get("wildcard")),
        "wildcard_online": bool(saved.get("wildcard_online")),
        "pool_16": worker_pool.POOL_16_SIZE,
        "pool_256": worker_pool.POOL_256_SIZE,
    }


def apply_settings(settings: dict) -> dict:
    """Write the tab fields back onto the firewall and VPN server records."""
    import netlock
    import persist
    import vpn_server

    port = int(settings.get("tunnel_port") or 51821)
    dns = [part.strip() for part in str(settings.get("dns") or "").split(",") if part.strip()]
    state = netlock.load_state()
    state["tunnel_port"] = port
    if dns:
        state["tunnel_dns"] = dns
    state["mode"] = settings.get("firewall_mode") or state.get("mode") or "off"
    netlock.save_state(state)
    vpn = vpn_server.load_state()
    vpn["port"] = port
    vpn["bind"] = settings.get("bind") or vpn.get("bind") or "127.0.0.1"
    vpn["public_bind"] = settings.get("public_bind") or vpn.get("public_bind") or "0.0.0.0"
    vpn["public_port"] = int(settings.get("public_port") or vpn.get("public_port") or 51822)
    vpn["socks_port"] = int(settings.get("socks_port") or 1080)
    if dns:
        vpn["dns"] = dns
    vpn_server.save_state(vpn)
    vpn_server.write_server_files(port=port, dns=dns or None)
    saved = persist.write_applied_and_save(
        {
            "firewall_mode": state["mode"],
            "tunnel_port": port,
            "tunnel_dns": dns,
            "bind": vpn["bind"],
            "socks_port": vpn["socks_port"],
            "public_bind": vpn["public_bind"],
            "public_port": vpn["public_port"],
        }
    )
    return saved


def start_processes(settings: dict | None = None) -> dict:
    """Start secure server, seal the stream, and open the parallel processor."""
    settings = dict(settings or load_settings())
    apply_settings(settings)

    def _secure():
        if not settings.get("wildcard"):
            return {"ok": False, "skipped": True, "wildcard": False}
        import secure_server
        return secure_server.start_background()

    def _stream():
        import secure_stream
        token = secure_stream.seal_wildcard(
            int(settings.get("tunnel_port") or 0),
            0,
            f"firewall={settings.get('firewall_mode')} bind={settings.get('bind')}",
        )
        return {"token": token, "generation": secure_stream.ring().generation}

    def _parallel():
        import parallel_processor
        return parallel_processor.start()

    # Never submit the starter onto the 256 pool. Those workers stay inside
    # accept loops (16 per running exe), so a queued start times out.
    parallel = _parallel()
    secure = worker_pool.submit(_secure).result(timeout=30)
    stream = worker_pool.submit(_stream).result(timeout=30)
    wildcard = bool(settings.get("wildcard"))
    import persist
    persist.write_applied_and_save(
        {
            "wildcard": wildcard,
            "wildcard_configured": bool(wildcard and secure.get("ok")),
            "wildcard_online": wildcard,
            "public_bind": settings.get("public_bind") or "0.0.0.0",
            "public_port": int(settings.get("public_port") or 51822),
            "wildcard_online": bool(settings.get("wildcard_online")),
        }
    )
    return {
        "wildcard": wildcard,
        "secure": secure,
        "stream": stream,
        "parallel": parallel,
        "settings": settings,
    }


def snapshot() -> dict:
    import parallel_processor
    settings = load_settings()
    return {"settings": settings, "binds": parallel_processor.list_binds()}
