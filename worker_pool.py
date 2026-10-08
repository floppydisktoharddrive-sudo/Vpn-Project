#!/usr/bin/env python3
"""Shared worker pools used by every NetLock module.

pool_16  — server bind and configure tasks
pool_256 — parallel process workers, 16 per running exe
"""

from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor

POOL_16_SIZE = 16
POOL_256_SIZE = 256
PER_PROCESS_WORKERS = 16

_lock = threading.Lock()
_pool_16: ThreadPoolExecutor | None = None
_pool_256: ThreadPoolExecutor | None = None
_attached: set[str] = set()
_assigned: dict[str, int] = {}


def pool_16() -> ThreadPoolExecutor:
    global _pool_16
    with _lock:
        if _pool_16 is None:
            _pool_16 = ThreadPoolExecutor(max_workers=POOL_16_SIZE, thread_name_prefix="bind16")
        return _pool_16


def pool_256() -> ThreadPoolExecutor:
    global _pool_256
    with _lock:
        if _pool_256 is None:
            _pool_256 = ThreadPoolExecutor(max_workers=POOL_256_SIZE, thread_name_prefix="work256")
        return _pool_256


def submit(fn, *args, heavy: bool = False, **kwargs) -> Future:
    pool = pool_256() if heavy else pool_16()
    return pool.submit(fn, *args, **kwargs)


def assign_process(key: str, workers: int | None = None) -> int:
    """Reserve workers from the 256 pool. Apps get 16; script files get 1."""
    name = str(key)
    want = PER_PROCESS_WORKERS if workers is None else max(0, int(workers))
    with _lock:
        pool_256()
        current = _assigned.get(name, 0)
        if current:
            return current
        free = POOL_256_SIZE - sum(_assigned.values())
        grant = min(want, max(0, free))
        _assigned[name] = grant
        return grant


def release_process(key: str) -> None:
    with _lock:
        _assigned.pop(str(key), None)


def release_all() -> None:
    with _lock:
        _assigned.clear()


def assigned(key: str) -> int:
    with _lock:
        return _assigned.get(str(key), 0)


def attach(module_name: str) -> str:
    """Register a module so it runs work on the shared pools."""
    with _lock:
        _attached.add(module_name)
    return module_name


def attached() -> list[str]:
    with _lock:
        return sorted(_attached)
try:
    import worker_pool
    worker_pool.attach(__name__)
except Exception:
    pass
