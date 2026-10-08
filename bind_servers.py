#!/usr/bin/env python3
"""Bind and configure every server. Called by start.bat.

Wildcard is set true only after the servers are configured and the Internet
probe succeeded. Offline leaves wildcard false.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import worker_pool

worker_pool.attach(__name__)

BASE = Path(__file__).resolve().parent


def _online() -> bool:
    try:
        import persist
        rec = persist.load_applied()
    except Exception:
        return False
    return bool(rec.get("internet_ok"))


def configure_and_bind() -> dict:
    import persist

    online = _online()
    report = {"online": online, "wildcard": False, "servers": []}

    def _vpn():
        import vpn_server
        vpn_server.write_server_files()
        if not online:
            return False, "configured only — Internet offline, tunnel not started"
        return vpn_server.start_server()

    def _proxy():
        import app_proxy
        return app_proxy.start()

    jobs = (
        ("vpn_server", _vpn),
        ("app_proxy", _proxy),
    )
    futures = [(name, worker_pool.submit(fn)) for name, fn in jobs]
    configured = True
    for name, fut in futures:
        try:
            result = fut.result(timeout=60)
            report["servers"].append({"name": name, "ok": True, "result": str(result)[:240]})
        except Exception as exc:
            configured = False
            report["servers"].append({"name": name, "ok": False, "result": str(exc)})
    wildcard = False
    persist.write_applied_and_save({
        "wildcard": False,
        "wildcard_configured": False,
        "wildcard_online": False,
        "worker_pool_16": worker_pool.POOL_16_SIZE,
        "worker_pool_256": worker_pool.POOL_256_SIZE,
    })
    report["wildcard"] = wildcard
    report["configured"] = configured
    print(f"Wildcard   : {wildcard} (configured={configured} online={online})")
    for row in report["servers"]:
        print(f"  {row['name']}: {'ok' if row['ok'] else 'fail'} {row['result']}")
    (BASE / "vpn_data").mkdir(parents=True, exist_ok=True)
    (BASE / "vpn_data" / "bind_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> int:
    rec = configure_and_bind()
    return 0 if rec.get("configured") else 1


if __name__ == "__main__":
    raise SystemExit(main())
