"""On-disk spool for a sink's undelivered events. A sink's `run()` writes
here on delivery failure so a down SIEM endpoint never blocks the pipeline
— `replay-sink` drains it later.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from dlpduck.durability import write_atomically

logger = logging.getLogger("dlpduck.spool")


class Spool:
    def __init__(self, root: Path, name: str):
        self.dir = Path(root) / name
        self.dir.mkdir(parents=True, exist_ok=True)

    def append(self, job_id: str, payload: dict[str, Any]) -> Path:
        # Sortable filename: replay processes events in the order they
        # failed, same as they'd have been delivered live.
        path = self.dir / f"{time.time():020.6f}_{job_id}.json"
        # Written via a temp file, fsync and an atomic rename: a crash (or
        # a full disk) partway through a plain write leaves a half-JSON
        # entry that nothing can ever deliver, and the spool exists
        # precisely for the case where things are already going wrong. A
        # reader only ever sees a complete file, or no file — and an entry
        # this call has returned from is on the disk, not in the page
        # cache waiting for a flush that a crash will cancel.
        write_atomically(path, json.dumps(payload, sort_keys=True, default=str))
        return path

    def pending(self) -> list[Path]:
        return sorted(self.dir.glob("*.json"))

    def drain(self, deliver: Callable[[dict[str, Any]], None]) -> tuple[int, int]:
        """Attempt every pending event in order. A delivered event is
        removed; the first failure stops the drain, so later events don't
        overtake it and delivery order is preserved.

        An entry that can't be parsed is set aside rather than raised: it
        would otherwise stop this drain and every future one at the same
        file, so a single unreadable byte would strand every undelivered
        event behind it forever. It's renamed rather than deleted — a
        failed delivery is evidence, and an operator should be able to see
        what was lost.
        """
        delivered = 0
        for path in self.pending():
            try:
                payload = json.loads(path.read_text())
            except (ValueError, OSError):
                quarantined = path.with_suffix(".json.corrupt")
                logger.error(
                    "spool entry %s is unreadable — setting it aside as %s so the "
                    "queue behind it can still drain",
                    path.name,
                    quarantined.name,
                )
                os.replace(path, quarantined)
                continue
            try:
                deliver(payload)
            except Exception:
                return delivered, len(self.pending())
            path.unlink()
            delivered += 1
        return delivered, 0
