"""
Session token cache for short-lived processes (e.g. the CLI).

Each CLI invocation is a fresh process, so without persistence every command
would log in from scratch. Some firmware throttles rapid successive logins (a
simple anti-brute-force measure), so re-logging in for every command is both
slow and can trip that throttle. We cache the SID (and the detected model, to
skip re-detection) in a small JSON file per host. If a cached session turns
out to be stale, Switch transparently re-authenticates.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Optional


def _cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    d = os.path.join(base, "gs30xctl")
    os.makedirs(d, exist_ok=True)
    return d


def _cache_path(host: str) -> str:
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    return os.path.join(_cache_dir(), f"{safe_host}.json")


def load_session(host: str) -> dict:
    """Return {"sid": ..., "model": ...} for host, or {} if nothing is cached."""
    try:
        with open(_cache_path(host)) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_session(host: str, sid: str, model: Optional[str] = None):
    try:
        path = _cache_path(host)
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump({"sid": sid, "model": model, "saved_at": time.time()}, f)
    except OSError:
        pass


def clear_session(host: str):
    try:
        os.remove(_cache_path(host))
    except OSError:
        pass
