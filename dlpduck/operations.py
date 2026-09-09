"""Operational state, kept separate from permanent Parquet evidence.

A reentrant process/thread lock serializes filesystem transitions. SQLite holds
receipts and revocable sessions; neither changes the identity of historical jobs.
The database and lock belong on the local work volume, not a network share.
"""
from __future__ import annotations

import functools
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

_LOCAL_LOCKS: dict[str, threading.RLock] = {}
_REGISTRY_LOCK = threading.Lock()
_HELD = threading.local()


@contextmanager
def operation_lock(root: Path):
    import fcntl

    root.mkdir(parents=True, exist_ok=True)
    key = str(root.resolve())
    with _REGISTRY_LOCK:
        mutex = _LOCAL_LOCKS.setdefault(key, threading.RLock())
    with mutex:
        held: set[str] = getattr(_HELD, "roots", set())
        if key in held:
            yield
            return
        with open(root / ".operations.lock", "a+b") as lock:
            os.chmod(lock.name, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            _HELD.roots = held | {key}
            try:
                yield
            finally:
                _HELD.roots = held
                fcntl.flock(lock, fcntl.LOCK_UN)


def serialized(method):
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        pipeline = getattr(self, "pipeline", self)
        with operation_lock(pipeline.config.destination.work_dir):
            return method(self, *args, **kwargs)

    return wrapped


class OperationalStore:
    def __init__(self, root: Path):
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "operations.sqlite3"
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id TEXT PRIMARY KEY, job_id TEXT NOT NULL,
                    received_at TEXT NOT NULL, filename TEXT NOT NULL,
                    source TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'received',
                    metadata TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS receipt_job ON receipts(job_id, received_at);
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY, username TEXT NOT NULL, expires REAL NOT NULL
                );
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(receipts)")}
            if "metadata" not in columns:
                db.execute(
                    "ALTER TABLE receipts ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'"
                )
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def receipt(self, receipt_id, job_id, received_at, filename, source):
        with self.connect() as db:
            db.execute(
                """INSERT OR IGNORE INTO receipts
                   (receipt_id, job_id, received_at, filename, source, status)
                   VALUES (?, ?, ?, ?, ?, 'received')""",
                (receipt_id, job_id, received_at, filename, source),
            )

    def receipt_metadata(self, receipt_id, metadata):
        import json

        with self.connect() as db:
            db.execute(
                "UPDATE receipts SET metadata=? WHERE receipt_id=?",
                (json.dumps(metadata, sort_keys=True), receipt_id),
            )

    def finish_receipt(self, receipt_id, status):
        with self.connect() as db:
            db.execute("UPDATE receipts SET status=? WHERE receipt_id=?", (status, receipt_id))

    def receipts(self, job_id):
        with self.connect() as db:
            return [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM receipts WHERE job_id=? ORDER BY received_at DESC",
                    (job_id,),
                )
            ]

    def display_names(self, job_ids=None):
        with self.connect() as db:
            if job_ids is None:
                rows = db.execute("SELECT job_id, filename FROM receipts ORDER BY received_at")
            else:
                ids = list(dict.fromkeys(job_ids))
                if not ids:
                    return {}
                placeholders = ",".join("?" for _ in ids)
                rows = db.execute(
                    f"SELECT job_id, filename FROM receipts WHERE job_id IN ({placeholders}) "
                    "ORDER BY received_at",
                    ids,
                )
            return {r["job_id"]: r["filename"] for r in rows}

    def create_session(self, token, username, expires):
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE expires < ?", (datetime.now(UTC).timestamp(),))
            db.execute("INSERT INTO sessions VALUES (?, ?, ?)", (token, username, expires))

    def session_active(self, token, username):
        with self.connect() as db:
            return (
                db.execute(
                    "SELECT 1 FROM sessions WHERE token=? AND username=? AND expires>?",
                    (token, username, datetime.now(UTC).timestamp()),
                ).fetchone()
                is not None
            )

    def revoke(self, *, token=None, username=None):
        with self.connect() as db:
            if token:
                db.execute("DELETE FROM sessions WHERE token=?", (token,))
            elif username:
                db.execute("DELETE FROM sessions WHERE username=?", (username,))
