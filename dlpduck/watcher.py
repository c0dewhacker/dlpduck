"""Discover PDFs (and, when one shows up, their companion metadata file)
and wait for the PDF to be size-stable before claiming — MFPs write
non-atomically and a naive create-event watch reads half-written PDFs.

A companion file is a convenience, never a requirement: even with
`metadata_format` configured, a bare PDF dropped with nothing alongside
it — a person, or a process, just dropping a file — is still processed,
after a bounded grace period in case a companion is genuinely en route.
There simply won't be the richer metadata a companion would have carried;
Pipeline.claim() still derives what it can from the PDF itself.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from dlpduck.config import Config
from dlpduck.durability import write_atomically
from dlpduck.pipeline import Pipeline
from dlpduck.types import DocumentTooLarge, UnsafeSourceFile

logger = logging.getLogger("dlpduck.watcher")


@dataclass
class _Tracked:
    size: int
    stable_polls: int = 0
    grace_polls: int = 0  # extra polls waited, once size-stable, for a metadata companion


class Watcher:
    def __init__(self, config: Config, pipeline: Pipeline):
        self.config = config
        self.pipeline = pipeline
        self.staging_root = config.destination.work_dir / "_processing"
        self.staging_root.mkdir(parents=True, exist_ok=True)
        self._tracked: dict[Path, _Tracked] = {}
        self._state = "Starting"
        self._current: str | None = None

    def _heartbeat(self):
        write_atomically(self.config.destination.work_dir / "watcher.json", json.dumps({
            "updated_at": datetime.now(UTC).isoformat(), "state": self._state,
            "current_job": self._current,
            "backlog": sum(1 for _ in self.config.source.path.glob(f"*{self.config.source.pdf_suffix}")),
        }))

    def discover_ready(self) -> list[tuple[Path, Path | None]]:
        """One poll: update size-stability tracking for every candidate PDF
        in source.path, and return the (pdf, metadata) pairs ready to
        claim — stable for `stability_polls` consecutive polls, and either
        their companion has shown up or `metadata_grace_polls` extra polls
        have passed waiting for one that never did.
        """
        src = self.config.source.path
        cfg = self.config.source
        ready: list[tuple[Path, Path | None]] = []
        seen_this_poll: set[Path] = set()

        for pdf_path in sorted(src.glob(f"*{cfg.pdf_suffix}")):
            seen_this_poll.add(pdf_path)
            try:
                size = pdf_path.stat().st_size
            except FileNotFoundError:
                continue

            prev = self._tracked.get(pdf_path)
            if prev is None or prev.size != size:
                tracked = _Tracked(size=size, stable_polls=1)
                self._tracked[pdf_path] = tracked
            else:
                prev.stable_polls += 1
                tracked = prev

            # Checked on the same poll as a first sighting too — with
            # stability_polls=1, "stable for one poll" means exactly that,
            # not "stable for one poll after the first one that doesn't count".
            if tracked.stable_polls < cfg.stability_polls:
                continue

            meta_path: Path | None = None
            if cfg.metadata_format != "none":
                candidate = pdf_path.with_suffix(cfg.metadata_suffix)
                if candidate.is_file():
                    meta_path = candidate
                else:
                    tracked.grace_polls += 1
                    if tracked.grace_polls <= cfg.metadata_grace_polls:
                        continue  # still within the grace window
                    logger.info(
                        "no metadata companion for %s after %d poll(s) — processing without one",
                        pdf_path,
                        tracked.grace_polls,
                    )

            ready.append((pdf_path, meta_path))
            del self._tracked[pdf_path]

        # Stop tracking files that disappeared (claimed by a prior run, or
        # removed externally).
        for stale in set(self._tracked) - seen_this_poll:
            del self._tracked[stale]

        return ready

    def run_forever(self, stop_event=None) -> None:
        finished = threading.Event()
        def heartbeat():
            while not finished.is_set():
                try:
                    self._heartbeat()
                except OSError:
                    logger.exception("could not update worker heartbeat")
                finished.wait(5)
        thread = threading.Thread(target=heartbeat, daemon=True)
        thread.start()
        try:
            self._run(stop_event)
        finally:
            self._state, self._current = "Stopped", None
            finished.set()
            thread.join(timeout=6)
            self._heartbeat()

    def _run(self, stop_event=None) -> None:
        logger.info("watching %s (poll every %ss)", self.config.source.path, self.config.source.poll_seconds)
        while stop_event is None or not stop_event.is_set():
            self._state, self._current = "Watching", None
            for pdf_path, meta_path in self.discover_ready():
                try:
                    self._state, self._current = "Processing", pdf_path.name
                    ctx = self.pipeline.run_job(pdf_path, meta_path, self.staging_root)
                    logger.info("job %s -> %s", ctx.job_id, ctx.disposition)
                except (DocumentTooLarge, UnsafeSourceFile) as exc:
                    # run_job has already moved it to failed/ and audited
                    # the refusal. Logged at warning, not exception: this
                    # is the system working, and a stack trace here would
                    # read as a bug in the daemon rather than a document
                    # the daemon declined.
                    logger.warning("refused %s: %s", pdf_path.name, exc)
                except Exception:
                    # Anything else really is unhandled. The file is either
                    # still in the drop folder (and will be retried, which
                    # is right for a transient fault) or already staged,
                    # where the startup sweep will find it.
                    logger.exception("unhandled error processing %s", pdf_path)
            # Waiting on the event rather than sleeping blindly: a SIGTERM
            # arriving one second into a 30-second poll should not hold
            # shutdown open for the other 29, which is long enough for an
            # init system to escalate to SIGKILL mid-job.
            if stop_event is None:
                time.sleep(self.config.source.poll_seconds)
            elif stop_event.wait(self.config.source.poll_seconds):
                break
