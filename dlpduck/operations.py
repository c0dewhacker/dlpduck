"""Operational state, kept separate from permanent Parquet evidence.

A reentrant process/thread lock serializes filesystem transitions. Receipts
and revocable sessions are plain files on the work volume, one per receipt
or session — the same content-addressed, single-owner-per-file approach as
the index and content stores, so there's no embedded database whose locking
semantics have to be trusted on whatever filesystem work_dir ends up on.
Neither changes the identity of historical jobs.
"""
from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from dlpduck.durability import FileAlreadyExists, atomic_write, write_atomically

logger = logging.getLogger("dlpduck.operations")

_LOCAL_LOCKS: dict[str, threading.RLock] = {}
_REGISTRY_LOCK = threading.Lock()
_HELD = threading.local()


class LockContended(Exception):
    """Raised by operation_lock(..., blocking=False) when another thread or
    process already holds the lock for that root."""


@contextmanager
def operation_lock(root: Path, *, blocking: bool = True):
    import fcntl

    root.mkdir(parents=True, exist_ok=True)
    key = str(root.resolve())
    with _REGISTRY_LOCK:
        mutex = _LOCAL_LOCKS.setdefault(key, threading.RLock())
    if not mutex.acquire(blocking=blocking):
        raise LockContended(key)
    try:
        held: set[str] = getattr(_HELD, "roots", set())
        if key in held:
            yield
            return
        with open(root / ".operations.lock", "a+b") as lock:
            os.chmod(lock.name, 0o600)
            if blocking:
                fcntl.flock(lock, fcntl.LOCK_EX)
            else:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    raise LockContended(key) from exc
            _HELD.roots = held | {key}
            try:
                yield
            finally:
                _HELD.roots = held
                fcntl.flock(lock, fcntl.LOCK_UN)
    finally:
        mutex.release()


def serialized(method):
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        pipeline = getattr(self, "pipeline", self)
        with operation_lock(pipeline.config.destination.work_dir):
            return method(self, *args, **kwargs)

    return wrapped


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


class OperationalStore:
    """Receipts and sessions, as one JSON file each.

    A receipt is created once (its receipt_id is a fresh uuid4, so a
    plain atomic-exclusive create is the correct "insert or ignore") and
    is afterwards only ever touched again by the exact call path that
    created it (receipt_metadata()/finish_receipt() for that same
    receipt_id) — never by a second, independent writer — so no locking
    is needed for those updates either.
    """

    def __init__(self, root: Path):
        self.receipts_root = root / "receipts"
        self.sessions_root = root / "sessions"
        self.receipts_root.mkdir(parents=True, exist_ok=True)
        self.sessions_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.sessions_root, 0o700)

    # ── receipts ─────────────────────────────────────────────────────

    def _receipt_path(self, job_id: str, receipt_id: str) -> Path:
        return self.receipts_root / job_id / f"{receipt_id}.json"

    def receipt(self, receipt_id, job_id, received_at, filename, source):
        path = self._receipt_path(job_id, receipt_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        body = json.dumps({
            "receipt_id": receipt_id, "job_id": job_id, "received_at": received_at,
            "filename": filename, "source": source, "status": "received",
            "metadata": "{}",
        })
        try:
            with atomic_write(path, exclusive=True) as tmp:
                tmp.write_text(body)
        except FileAlreadyExists:
            pass  # insert-or-ignore: this receipt_id already exists

    def receipt_metadata(self, job_id, receipt_id, metadata):
        path = self._receipt_path(job_id, receipt_id)
        record = _read_json(path)
        if record is None:
            return
        record["metadata"] = json.dumps(metadata, sort_keys=True)
        write_atomically(path, json.dumps(record))

    def finish_receipt(self, job_id, receipt_id, status):
        path = self._receipt_path(job_id, receipt_id)
        record = _read_json(path)
        if record is None:
            return
        record["status"] = status
        write_atomically(path, json.dumps(record))

    def receipts(self, job_id):
        rows = []
        for path in (self.receipts_root / job_id).glob("*.json"):
            record = _read_json(path)
            if record is not None:
                rows.append(record)
        rows.sort(key=lambda r: r.get("received_at", ""), reverse=True)
        return rows

    def display_names(self, job_ids=None):
        if job_ids is None:
            job_dirs = [p for p in self.receipts_root.iterdir() if p.is_dir()]
        else:
            ids = list(dict.fromkeys(job_ids))
            job_dirs = [self.receipts_root / jid for jid in ids]

        names: dict[str, str] = {}
        for job_dir in job_dirs:
            if not job_dir.is_dir():
                continue
            earliest: dict | None = None
            for path in job_dir.glob("*.json"):
                record = _read_json(path)
                if record is None:
                    continue
                if earliest is None or record.get("received_at", "") < earliest.get("received_at", ""):
                    earliest = record
            if earliest is not None:
                names[job_dir.name] = earliest["filename"]
        return names

    # ── sessions ─────────────────────────────────────────────────────

    def _session_path(self, token: str) -> Path:
        # The token is already high-entropy (secrets.token_urlsafe(32));
        # hashing it for the filename just avoids ever writing the raw
        # token itself to disk as a directory entry.
        digest = hashlib.sha256(token.encode()).hexdigest()
        return self.sessions_root / f"{digest}.json"

    def _prune_expired_sessions(self) -> None:
        now = datetime.now(UTC).timestamp()
        for path in self.sessions_root.glob("*.json"):
            record = _read_json(path)
            if record is None or record.get("expires", 0) < now:
                path.unlink(missing_ok=True)

    def create_session(self, token, username, expires):
        self._prune_expired_sessions()
        path = self._session_path(token)
        write_atomically(path, json.dumps({"username": username, "expires": expires}))
        os.chmod(path, 0o600)
        logger.debug("session created for %s, expires=%s", username, expires)  # never the token

    def session_active(self, token, username):
        record = _read_json(self._session_path(token))
        return (
            record is not None
            and record.get("username") == username
            and record.get("expires", 0) > datetime.now(UTC).timestamp()
        )

    def revoke(self, *, token=None, username=None):
        if token:
            self._session_path(token).unlink(missing_ok=True)
            logger.debug("session revoked by token")  # never the token itself
        elif username:
            for path in self.sessions_root.glob("*.json"):
                record = _read_json(path)
                if record is not None and record.get("username") == username:
                    path.unlink(missing_ok=True)
            logger.debug("all sessions revoked for %s", username)
