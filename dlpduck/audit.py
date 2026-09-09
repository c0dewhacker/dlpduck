"""Hash-chained JSONL audit log. The audit trail is the source of truth for
what happened (design doc §3, §8.2) — the Parquet index is derived from it
and from the archived PDFs, and is rebuildable if lost.

Chaining is a feature flag (`audit.integrity: chained | none`, §8.2): a
development install, or a deployment that would rather not run an
integrity-sealed ledger at all, can turn it off.

Two things have to be able to remove content from an append-only log, and
both are handled here without making `verify()` cry tampering. Per-event
redaction (§8.5, `redact()`) empties named fields from a single event when
something that should not be permanent lands in the trail; the event keeps
its place in the chain and the removal is itself a chained event, so this
loses the proof of one event's contents but never happens silently.

Retention (§8.3) is the other: it deletes whole old partitions, and naively
doing that would make `verify()` report the resulting gap as tampering, since
the oldest surviving event's `prev` would point at a hash nothing on disk can
produce any more. `write_trim_checkpoint` records that hash *before* the deletion
happens, in a small sidecar file, and both `_resume()` and `verify()` treat
it as the trusted starting point instead of assuming a chain always starts
at `None`. That turns "the history before this point was authorisedly
discarded" into a recorded fact rather than an unexplained hole.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from dlpduck.durability import write_atomically


def _canonical(event: dict[str, Any]) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), default=_default)


def _default(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError(f"not JSON serialisable: {type(value)}")


def _protected_fields(event: dict[str, Any]) -> set[str]:
    """Fields `redact()` will not empty.

    `seq`/`ts`/`event`/`prev`/`hash` carry the chain — removing them
    would break linkage rather than remove content, and `redacted` is the
    marker that says content went. On an `audit.redacted` event,
    `redacted_seq` and `fields` are the accountability record itself: a
    redaction that could erase which event it emptied, and which fields,
    would let one authorised removal cover an unlimited number of later
    ones.
    """
    protected = {"seq", "ts", "event", "prev", "hash", "redacted"}
    if event.get("event") == "audit.redacted":
        protected |= {"redacted_seq", "fields"}
    return protected


class ChainBroken(Exception):
    def __init__(self, path: Path, line_no: int, detail: str):
        super().__init__(f"{path}:{line_no}: {detail}")
        self.path = path
        self.line_no = line_no
        self.detail = detail


# What a redacted field's value is replaced with. Chosen to be obvious in a
# console table rather than to look like data.
REDACTION_MARKER = "[redacted]"


@dataclass
class Redaction:
    """One event whose content was removed after it was written."""

    path: Path
    line_no: int
    seq: int
    fields: list[str]

    def __str__(self) -> str:
        return f"{self.path}:{self.line_no}: seq {self.seq} redacted {', '.join(self.fields)}"


@dataclass
class VerifyResult:
    """Unpacks as `(ok, breaks)`, so existing callers keep working, while
    carrying redactions for anything that reports to a human — and
    everything user-facing should, because "intact" and "intact, with three
    events emptied" are different answers.
    """

    ok: bool
    breaks: list[ChainBroken]
    redactions: list[Redaction]

    def __iter__(self):
        return iter((self.ok, self.breaks))


_CHECKPOINT_NAME = ".chain_checkpoint.json"
# The cross-process write lock. Never read as data; its existence and its
# flock state are the whole content.
_LOCK_NAME = ".write.lock"

logger = logging.getLogger("dlpduck.audit")


def _parse_line(raw: str | bytes, path: Path, line_no: int) -> dict[str, Any] | None:
    """Decode one JSONL record, or None if it isn't valid JSON.

    A truncated final line is the normal shape of a crash or a full disk —
    which is precisely when the audit trail matters most. Letting the
    decode error escape made one bad byte unreadable into *everything*
    unreadable: the /audit screen, every job page that renders a timeline,
    verify-audit, and the daemon's own startup. A record that can't be
    read is reported (and, by verify(), treated as a break in the chain),
    but it never takes the surrounding history down with it.
    """
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        logger.warning("unreadable audit record at %s:%d — skipping", path, line_no)
        return None


def _last_parseable_event(path: Path, chunk: int = 65536) -> dict[str, Any] | None:
    """The newest complete record in a partition file, read from the end.

    Read from the end rather than by scanning forward because this now
    runs on *every* append (the chain state has to be re-read under the
    lock, not trusted from memory), and a forward scan would make a day's
    appends quadratic in the size of that day's file.

    Silent about records that don't parse: a truncated final line is the
    normal shape of an unclean shutdown, and this is the one caller that
    is supposed to step over it and carry on. `verify()` and `events()`
    still report it — that is where a hole in the ledger belongs, not in
    a warning emitted on every single append.
    """
    size = path.stat().st_size
    if size == 0:
        return None
    window = chunk
    while True:
        start = max(0, size - window)
        with open(path, "rb") as f:
            f.seek(start)
            data = f.read(size - start)
        lines = data.split(b"\n")
        if start > 0:
            # The first line in the window is cut off on its left.
            lines = lines[1:]
        for raw in reversed(lines):
            raw = raw.strip()
            if not raw:
                continue
            try:
                return json.loads(raw)  # type: ignore[no-any-return]
            except ValueError:
                continue
        if start == 0:
            return None
        window *= 4


class AuditLog:
    """Appends events to `root/dt=YYYY-MM-DD/events.jsonl`, one file per day.

    Safe for concurrent writers, threads and processes alike. That is not
    a luxury: the recommended deployment runs the daemon and the console
    as two processes over one work_dir (§1), and the console appends on
    every search, PDF view, purge and login — so "one writer" was an
    assumption the documented setup broke on the first search anyone ran.
    See `_appending` for how it is held, and why the chain state is
    re-read from disk rather than cached.
    """

    def __init__(self, root: Path, integrity: str = "chained"):
        if integrity not in ("chained", "none"):
            raise ValueError(f"audit.integrity must be 'chained' or 'none', got {integrity!r}")
        self.root = Path(root)
        self.integrity = integrity
        self._lock = threading.Lock()
        self._seq, self._prev_hash = self._resume()

    def _partition_files(self) -> list[Path]:
        if not self.root.is_dir():
            return []
        return sorted(self.root.glob("dt=*/events.jsonl"))

    def _checkpoint_path(self) -> Path:
        return self.root / _CHECKPOINT_NAME

    def _read_checkpoint(self) -> dict[str, Any] | None:
        path = self._checkpoint_path()
        if not path.is_file():
            return None
        # A checkpoint that won't parse must not stop the process starting.
        # `_resume` runs in the constructor, so raising here would take the
        # daemon and every CLI command down over a single unreadable
        # sidecar — the same failure a corrupt event record used to cause.
        # Treated as absent instead: verify() then reports the trimmed
        # history as an unexplained gap, which is the honest answer and a
        # loud one, rather than a system that refuses to run.
        try:
            checkpoint = json.loads(path.read_text())
        except (OSError, ValueError):
            logger.warning("audit trim checkpoint at %s is unreadable; ignoring it", path)
            return None
        if not isinstance(checkpoint, dict) or "seq" not in checkpoint:
            logger.warning(
                "audit trim checkpoint at %s is not a checkpoint; ignoring it", path
            )
            return None
        return checkpoint

    def write_trim_checkpoint(self, partitions_being_removed: list[Path]) -> dict[str, Any] | None:
        """Call this before deleting any dt= partition directories (as
        retention, §8.3, does): records the hash of the last event in the
        newest of the partitions about to go — exactly the hash the
        earliest surviving event's `prev` already points to — so
        `verify()` treats that as the trusted start of the chain instead
        of expecting it to begin at `None`. No-op if chaining is off, or
        there's nothing to checkpoint.
        """
        if self.integrity != "chained" or not partitions_being_removed:
            return None
        newest = max(partitions_being_removed, key=lambda p: p.name)
        events_file = newest / "events.jsonl"
        if not events_file.is_file():
            return None
        event = None
        with open(events_file, "rb") as f:
            for line_no, raw in enumerate(f, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                parsed = _parse_line(raw, events_file, line_no)
                if parsed is not None:
                    event = parsed
        if event is None:
            return None
        checkpoint = {"seq": event.get("seq", 0), "hash": event.get("hash")}
        existing = self._read_checkpoint()
        # Never move the checkpoint backwards — a later, smaller trim
        # must not un-checkpoint history an earlier trim already discarded.
        if existing and existing.get("seq", 0) >= checkpoint["seq"]:
            return existing
        # Durable and atomic, because retention deletes the partitions
        # immediately after this returns. A plain write_text can still be
        # sitting in the page cache when the power goes: the events are
        # gone, the checkpoint that explains their absence never landed,
        # and verify() reports an authorised trim as tampering forever —
        # with nothing left on disk to prove otherwise. A half-written
        # checkpoint would be worse still.
        write_atomically(self._checkpoint_path(), json.dumps(checkpoint, sort_keys=True))
        return checkpoint

    def _resume(self) -> tuple[int, str | None]:
        files = self._partition_files()
        if not files:
            checkpoint = self._read_checkpoint()
            if checkpoint:
                return checkpoint["seq"], checkpoint["hash"]
            return 0, None
        # Resume from the last record that actually parses. A half-written
        # trailing line is exactly what an unclean shutdown leaves, and it
        # must not stop the daemon coming back up.
        event = _last_parseable_event(files[-1])
        if event is None:
            return 0, None
        return event.get("seq", 0), event.get("hash")

    @contextmanager
    def _appending(self) -> Iterator[None]:
        """Hold the write lock and refresh the chain state from disk.

        The single-writer assumption this class was built on is one the
        recommended deployment does not meet: `dlpduck run` and `dlpduck
        console run` are two processes over one work_dir, and the console
        appends on every search, PDF view, purge and login. Each process
        cached `_prev_hash` at construction, so the first console event
        after the daemon's would chain from a stale hash and reuse a
        sequence number — breaking the chain in the documented default
        setup, with no tampering anywhere near it. False alarms are worse
        than no alarm: they teach an operator that verify-audit failing
        means nothing.

        So the lock is a real file lock, not just a thread lock, and the
        seq/prev are re-read inside it rather than trusted from memory.
        The in-process lock stays too — `flock` is held per open file
        description, so two threads sharing this one would both pass it.

        (`flock` needs a filesystem that implements it. Local disk and
        NFSv4 do; if a work_dir ever lives somewhere that doesn't, this
        degrades to the single-writer assumption it replaced.)
        """
        with self._lock:
            self._lock_path().parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self._lock_path()), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                # Whatever another process wrote while we weren't holding
                # the lock is now the chain's real tail.
                self._seq, self._prev_hash = self._resume()
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def _lock_path(self) -> Path:
        return self.root / _LOCK_NAME

    def append(self, event_type: str, **fields: Any) -> dict[str, Any]:
        with self._appending():
            now = datetime.now(UTC)
            self._seq += 1
            event: dict[str, Any] = {
                "seq": self._seq,
                "ts": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "event": event_type,
                **fields,
            }
            if self.integrity == "chained":
                event["prev"] = self._prev_hash
                digest = hashlib.sha256(_canonical(event).encode("utf-8")).hexdigest()
                event["hash"] = digest
                self._prev_hash = digest

            partition = self.root / f"dt={now.date().isoformat()}"
            partition.mkdir(parents=True, exist_ok=True)
            path = partition / "events.jsonl"
            with open(path, "a", encoding="utf-8") as f:
                f.write(_canonical(event) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return event

    def redact(self, seq: int, fields: list[str], *, reason: str, actor: str) -> dict[str, Any]:
        """Remove named fields from one event that is already written.

        The trail is append-only and hash-chained, which is what makes it
        evidence — but "append-only" and "an erasure request" eventually
        collide. Something sensitive does land in here: a search term
        (§10.6), a filename inside a parse error, an allowlisted metadata
        value. Until now the only options were to keep it forever or drop
        a whole partition.

        What survives and what does not:

        - The event keeps its `hash` and `prev`, so the CHAIN still proves
          nothing around it was inserted, removed or reordered.
        - Its own content can no longer be recomputed into that hash, so
          `verify()` stops attesting to this event's contents and reports
          it as redacted instead.
        - The redaction is appended as an ordinary chained
          `audit.redacted` event naming the actor, reason and fields.
          Suppressing that record would itself break the chain.

        The trade-off, stated plainly: this is a way to remove content
        while `verify()` still passes. It is deliberately not a way to do
        it quietly — an operator who removes evidence leaves a chained
        record saying so, and every surface that reports on the chain
        reports redactions alongside it.
        """
        if not fields:
            raise ValueError("redact requires at least one field name")

        # The same lock appends take: this rewrites a whole partition, and
        # another process appending into it mid-rewrite would have its
        # event silently dropped when the rewritten lines are written back.
        # Released before the `audit.redacted` append below, which takes
        # the lock itself — flock does not nest across two open files.
        with self._appending():
            path, line_no, event = self._find_event(seq)
            protected = _protected_fields(event)
            # Refused loudly rather than filtered quietly. An operator who
            # asks to remove three fields and is told "done" must not be
            # left with one of them still on disk — in an erasure request
            # that is the whole job, silently half-finished.
            unredactable = sorted(f for f in fields if f in protected)
            if unredactable:
                raise KeyError(
                    f"event {seq}: {', '.join(unredactable)} cannot be redacted — "
                    "these carry the chain and the record of the redaction itself"
                )
            absent = sorted(f for f in fields if f not in event)
            if absent:
                raise KeyError(
                    f"event {seq} has no {', '.join(absent)} to redact — it carries "
                    f"{sorted(set(event) - protected)}"
                )

            removable = sorted(set(fields))
            for field in removable:
                event[field] = REDACTION_MARKER
            already = event.get("redacted", {}).get("fields", [])
            event["redacted"] = {"fields": sorted(set(already) | set(removable))}

            lines = path.read_text(encoding="utf-8").splitlines()
            lines[line_no - 1] = _canonical(event)
            write_atomically(path, "\n".join(lines) + "\n")

        # Appended after the rewrite, through the ordinary path, so it is
        # chained and fsync'd like any other event. Ordering matters: if
        # this crashes in between, the content is already gone and the
        # explanation is missing, which verify() reports as a break. The
        # other order would leave a record claiming a removal that never
        # happened — quietly wrong instead of loudly incomplete.
        self.append(
            "audit.redacted", redacted_seq=seq, fields=removable, reason=reason, actor=actor
        )
        return event

    def _find_event(self, seq: int) -> tuple[Path, int, dict[str, Any]]:
        for path in self._partition_files():
            with open(path, encoding="utf-8") as f:
                for line_no, raw in enumerate(f, start=1):
                    raw = raw.strip()
                    if not raw:
                        continue
                    event = _parse_line(raw, path, line_no)
                    if event is not None and event.get("seq") == seq:
                        return path, line_no, event
        raise KeyError(f"no audit event with seq {seq}")

    def events_for_job(self, job_id: str) -> list[dict[str, Any]]:
        """Every event mentioning this job, oldest first — the console's
        job-detail timeline. A linear scan of every partition; fine at
        MFP volumes, the first thing to revisit if this ever isn't.
        """
        # A job's events can be spread across any partition — a purge or a
        # reassessment lands years after ingest — so this genuinely has to
        # look everywhere. What it does not have to do is JSON-decode every
        # record on the way: the job id appears verbatim in any line that
        # mentions it, so a substring test rejects the overwhelming
        # majority for a fraction of the cost. Correctness is unchanged;
        # the parse still decides, the pre-filter only skips lines that
        # cannot possibly match.
        needle = f'"{job_id}"'
        out: list[dict[str, Any]] = []
        for path in self._partition_files():
            with open(path, encoding="utf-8") as f:
                for line_no, raw in enumerate(f, start=1):
                    if needle not in raw:
                        continue
                    event = _parse_line(raw.strip(), path, line_no)
                    if event is not None and event.get("job_id") == job_id:
                        out.append(event)
        out.sort(key=lambda e: e.get("seq", 0))
        return out

    def job_ids_with_event(self, *event_types: str) -> set[str]:
        """Every job id named by an event of any of these types.

        Exists for disaster recovery (§12), which needs to know what was
        purged before it rebuilds anything — the audit trail is the only
        surviving record of that once the index is gone, which is exactly
        the situation a rebuild is for. Same substring pre-filter as
        `events_for_job`: the event type appears verbatim in any line that
        carries it, so most lines are rejected without a JSON decode.
        """
        wanted = set(event_types)
        needles = tuple(f'"{t}"' for t in wanted)
        out: set[str] = set()
        for path in self._partition_files():
            with open(path, encoding="utf-8") as f:
                for line_no, raw in enumerate(f, start=1):
                    if not any(n in raw for n in needles):
                        continue
                    event = _parse_line(raw.strip(), path, line_no)
                    if event is None or event.get("event") not in wanted:
                        continue
                    job_id = event.get("job_id")
                    if isinstance(job_id, str):
                        out.add(job_id)
        return out

    def events(
        self, start: date | None = None, end: date | None = None, limit: int = 500, before: int | None = None
    ) -> list[dict[str, Any]]:
        """Every event in the given date range (both ends inclusive),
        newest first, capped at `limit` — the console's audit-trail
        browser. Unlike events_for_job, this only reads partitions in
        range rather than every one on disk.
        """
        # Newest partition first, stopping as soon as `limit` events are in
        # hand. Reading the whole range and truncating afterwards meant a
        # 500-row page loaded a year of history into memory to throw nearly
        # all of it away — 127MB and 2.6s on a year of modest traffic, and
        # growing forever, since audit retention is opt-in.
        #
        # Stopping early is safe because seq increases monotonically with
        # time and appends always go to the current UTC date's partition:
        # every event in an older partition therefore has a lower seq than
        # every event in a newer one, so once `limit` events have been read
        # from the newest partitions, nothing older can displace them.
        out: list[dict[str, Any]] = []
        for path in reversed(self._partition_files()):
            partition_name = path.parent.name.removeprefix("dt=")
            try:
                partition_date = date.fromisoformat(partition_name)
            except ValueError:
                continue
            if start is not None and partition_date < start:
                continue
            if end is not None and partition_date > end:
                continue
            with open(path, encoding="utf-8") as f:
                for line_no, raw in enumerate(f, start=1):
                    raw = raw.strip()
                    if not raw:
                        continue
                    event = _parse_line(raw, path, line_no)
                    if event is not None and (before is None or event.get("seq", 0) < before):
                        out.append(event)
            if len(out) >= limit:
                break
        out.sort(key=lambda e: e.get("seq", 0), reverse=True)
        return out[:limit]

    def verify(self) -> VerifyResult:
        """Walk every partition in order and confirm the chain is intact.

        Redacted events (see `redact`) are reported rather than failed:
        their content was removed deliberately, so it can no longer be
        recomputed into the hash they carry. The links either side of them
        are still checked, so insertion, removal and reordering are still
        caught — what stops being attested is that one event's contents.
        """
        if self.integrity == "none":
            return VerifyResult(True, [], [])

        breaks: list[ChainBroken] = []
        redactions: list[Redaction] = []
        # Every legitimate redaction appends a chained `audit.redacted`
        # naming the event it emptied. Collecting those lets an emptied
        # event with no such record be reported as a break rather than as
        # a redaction — otherwise marking an event "redacted" would be a
        # way to blank content and still verify clean.
        explained: dict[int, set[str]] = {}
        checkpoint = self._read_checkpoint()
        prev_hash: str | None = checkpoint["hash"] if checkpoint else None
        for path in self._partition_files():
            with open(path, encoding="utf-8") as f:
                for line_no, raw in enumerate(f, start=1):
                    raw = raw.strip()
                    if not raw:
                        continue
                    event = _parse_line(raw, path, line_no)
                    if event is None:
                        # A record that cannot be read is itself a finding:
                        # it is a hole in the ledger, whether it came from
                        # a crash mid-write or from someone editing the
                        # file. Report it and carry on so the rest of the
                        # chain still gets checked — but never pass.
                        breaks.append(
                            ChainBroken(path, line_no, "record is not readable JSON")
                        )
                        continue
                    if event.get("prev") != prev_hash:
                        breaks.append(
                            ChainBroken(
                                path,
                                line_no,
                                f"prev={event.get('prev')!r} does not match "
                                f"expected {prev_hash!r}",
                            )
                        )
                    claimed = event.get("hash")
                    if event.get("event") == "audit.redacted":
                        recorded = explained.setdefault(event.get("redacted_seq", -1), set())
                        recorded.update(event.get("fields") or [])
                    marker = event.get("redacted")
                    if marker:
                        redactions.append(
                            Redaction(
                                path=path,
                                line_no=line_no,
                                seq=event.get("seq", 0),
                                fields=list(marker.get("fields", [])),
                            )
                        )
                        # The link is what still carries; the content is
                        # gone by design and cannot rehash to `claimed`.
                        prev_hash = claimed
                        continue
                    recomputed_input = {k: v for k, v in event.items() if k != "hash"}
                    recomputed = hashlib.sha256(
                        _canonical(recomputed_input).encode("utf-8")
                    ).hexdigest()
                    if claimed != recomputed:
                        breaks.append(
                            ChainBroken(
                                path,
                                line_no,
                                f"hash={claimed!r} does not match recomputed {recomputed!r}",
                            )
                        )
                    prev_hash = claimed

        # An emptied event that nothing accounts for is tampering wearing
        # a redaction's clothes. So is one that emptied more than the
        # record admits to: without this second check, a single authorised
        # redaction would license blanking every other field of that event
        # by hand, since the seq alone would still be "explained".
        for redaction in redactions:
            if redaction.seq not in explained:
                breaks.append(
                    ChainBroken(
                        redaction.path,
                        redaction.line_no,
                        f"seq {redaction.seq} is marked redacted but no audit.redacted "
                        "event records who removed it or why",
                    )
                )
                continue
            unaccounted = sorted(set(redaction.fields) - explained[redaction.seq])
            if unaccounted:
                breaks.append(
                    ChainBroken(
                        redaction.path,
                        redaction.line_no,
                        f"seq {redaction.seq} is marked redacted in "
                        f"{', '.join(unaccounted)}, which no audit.redacted event records",
                    )
                )
        return VerifyResult(not breaks, breaks, redactions)
