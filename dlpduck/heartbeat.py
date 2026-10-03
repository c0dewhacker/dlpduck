"""Watcher heartbeats: one file per instance, under work_dir/heartbeats/.

There used to be a single work_dir/watcher.json that every replica
overwrote. With several pods that made it describe whichever wrote last —
a standby pod's "Standby" hid the leader's "Processing" on Overview — and
the "Stopped" a terminating pod writes on its way out made every pod's
readiness probe fail at once, for up to a heartbeat interval, on every
rolling update.

Readiness now judges this instance's own heartbeat. A console running on
a host with no watcher of its own (a separate process, elsewhere) falls
back to "is some watcher alive", which is what the single file used to
answer. Overview shows the instance doing the work: the leader, when there
is one, rather than whichever pod is standing by.
"""

from __future__ import annotations

import json
import os
import re
import socket
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dlpduck.durability import write_atomically

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
_ACTIVE = ("Processing", "Claiming", "Watching")
# Pods in a Deployment get a fresh name on every restart; a heartbeat
# nobody has refreshed in this long belongs to a pod that no longer exists.
_FORGET_AFTER_SECONDS = 24 * 60 * 60


def instance_identity(configured: str | None = None) -> str:
    """This instance's name: cluster.identity, then $POD_NAME, then
    $HOSTNAME, then the host name. The watcher and console of one pod share
    it, which is what lets the console find its own watcher."""
    return (
        configured
        or os.environ.get("POD_NAME")
        or os.environ.get("HOSTNAME")
        or socket.gethostname()
    )


def _root(work_dir: Path) -> Path:
    return Path(work_dir) / "heartbeats"


def _path(work_dir: Path, identity: str) -> Path:
    return _root(work_dir) / f"{_UNSAFE.sub('_', identity)[:128] or 'unnamed'}.json"


def write(work_dir: Path, identity: str, record: dict[str, Any]) -> None:
    path = _path(work_dir, identity)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_atomically(
        path,
        json.dumps({**record, "identity": identity, "updated_at": datetime.now(UTC).isoformat()}),
    )


def _load(path: Path, stale_after: float) -> dict[str, Any] | None:
    try:
        record = json.loads(path.read_text())
        age = (datetime.now(UTC) - datetime.fromisoformat(record["updated_at"])).total_seconds()
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not isinstance(record, dict):
        return None
    record["stale"] = age > stale_after
    return record


def read_all(work_dir: Path, stale_after: float) -> list[dict[str, Any]]:
    """Every instance's heartbeat, freshest first. Heartbeats from pods
    long gone are removed on the way past."""
    root = _root(work_dir)
    if not root.is_dir():
        return []
    out = []
    now = time.time()
    for path in root.glob("*.json"):
        try:
            if now - path.stat().st_mtime > _FORGET_AFTER_SECONDS:
                path.unlink(missing_ok=True)
                continue
        except OSError:
            continue
        record = _load(path, stale_after)
        if record is not None:
            out.append(record)
    out.sort(key=lambda r: r.get("updated_at", ""), reverse=True)
    return out


_MISSING = {"stale": True, "state": "No worker heartbeat", "backlog": None}


def own(work_dir: Path, identity: str, stale_after: float) -> dict[str, Any]:
    """The heartbeat readiness should judge: this instance's own, or — for a
    console with no watcher of its own — any live one."""
    record = _load(_path(work_dir, identity), stale_after)
    if record is not None:
        return record
    for other in read_all(work_dir, stale_after):
        if not other["stale"] and other.get("state") != "Stopped":
            return other
    return dict(_MISSING)


def cluster(work_dir: Path, identity: str, stale_after: float) -> dict[str, Any]:
    """The heartbeat Overview should show: an instance actively watching
    (the leader), or failing that this instance's own."""
    for record in read_all(work_dir, stale_after):
        if not record["stale"] and record.get("state") in _ACTIVE:
            return record
    return own(work_dir, identity, stale_after)
