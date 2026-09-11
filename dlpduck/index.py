"""Write assessment rows to the metadata index. Never includes
`full_text` — that lives only in the content store (dlpduck.content), so
this file is permanent: nothing in it is ever a reason to delete it.

A job accumulates one row per assessment rather than being
overwritten — `write_index_row` is the normal ingest path (assessment_seq
1); `dlpduck.reprocess` appends further ones through the shared
`write_row` helper below.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from dlpduck.durability import FileAlreadyExists, atomic_write
from dlpduck.schema import INDEX_SCHEMA
from dlpduck.types import JobContext

logger = logging.getLogger("dlpduck.index")


def index_row(
    ctx: JobContext,
    archive_path: str,
    *,
    assessment_seq: int = 1,
    ruleset_version: str = "",
    supersedes_seq: int | None = None,
) -> dict:
    hits = [
        {
            "rule_id": h.rule_id,
            "rule_name": h.rule_name,
            "severity": h.severity.value,
            "action": h.action,
            "page_number": h.page_number,
            "line_number": h.line_number,
            "line_on_page": h.line_on_page,
            "start": h.start,
            "end": h.end,
            "masked_text": h.masked_text,  # never the raw value
            "match_hmac": h.match_hmac,
            "validator": h.validator,
        }
        for h in ctx.hits
    ]
    highest = ctx.highest_severity
    return {
        "job_id": ctx.job_id,
        "received_at": ctx.received_at,
        "assessed_at": ctx.received_at,  # first assessment: assessed at ingest time
        "assessment_seq": assessment_seq,
        "ruleset_version": ruleset_version,
        "supersedes_seq": supersedes_seq,
        "release_pending": False,
        "source_name": ctx.source_name,
        "page_count": ctx.text.page_count,
        "ocr_page_count": ctx.text.ocr_page_count,
        "min_ocr_confidence": ctx.text.min_ocr_confidence,
        "degraded": ctx.text.degraded,
        "disposition": ctx.disposition,
        "reason": ctx.reason,
        "archive_path": archive_path,
        "pdf_sha256": ctx.pdf_sha256,
        "flagged": ctx.flagged,
        "highest_severity": highest.value if highest else None,
        "hit_count": len(ctx.hits),
        "rule_ids": sorted({h.rule_id for h in ctx.hits}),
        "hits": hits,
        "metadata": json.dumps(ctx.metadata, sort_keys=True),
        "audit_fields": json.dumps(ctx.audit_fields, sort_keys=True),
    }


class AssessmentExists(Exception):
    """Raised when an assessment file already exists and the caller asked
    not to overwrite one — i.e. something else recorded this sequence
    number first."""

    def __init__(self, path: Path):
        super().__init__(f"assessment already recorded at {path}")
        self.path = path


def write_row(
    index_root: Path,
    row: dict[str, Any],
    *,
    dt: date,
    job_id: str,
    assessment_seq: int,
    exclusive: bool = False,
) -> Path:
    """Low-level writer shared by the ingest path (via write_index_row)
    and dlpduck.reprocess — one Parquet file per assessment, named so
    every assessment of a job coexists without clashing.

    `exclusive=True` refuses to overwrite an existing assessment. The
    history is append-only, but the sequence number is chosen by
    reading the current highest and adding one — so two writers racing
    (the console and the CLI, or two operators clicking commit) both pick
    the same number, and a plain write would silently destroy one of them
    while the audit trail recorded both. Ingest keeps the permissive
    default: its sequence is always 1, its job_id is derived from the
    content, and re-running it after a crash is meant to be a no-op.
    """
    table = pa.Table.from_pylist([row], schema=INDEX_SCHEMA)
    partition = Path(index_root) / f"dt={dt.isoformat()}"
    partition.mkdir(parents=True, exist_ok=True)
    out_path = partition / f"{job_id}_{assessment_seq:04d}.parquet"
    # Written to a temp file and linked (or renamed) into place, so the
    # name never exists over a partial file. This store is read through a
    # dt=*/*.parquet glob: one Parquet file without a footer fails every
    # query over it, taking down the jobs list, search and reprocess for
    # every job at once — not just the row that was being written.
    #
    # For the exclusive path that link is also the race guard. It has to
    # happen after the content is complete, which is why it isn't an
    # O_EXCL open on the real path: that claims the name first, and a
    # crash then leaves a zero-byte file that is exactly as unreadable.
    try:
        with atomic_write(out_path, exclusive=exclusive) as tmp:
            pq.write_table(table, tmp, compression="snappy")
    except FileAlreadyExists:
        logger.debug("write_row: assessment %s#%d already exists", job_id, assessment_seq)
        raise AssessmentExists(out_path) from None
    logger.debug("wrote index row: job=%s assessment=%d -> %s", job_id, assessment_seq, out_path)
    return out_path


def write_index_row(
    index_root: Path,
    ctx: JobContext,
    archive_path: str,
    *,
    assessment_seq: int = 1,
    ruleset_version: str = "",
    supersedes_seq: int | None = None,
) -> Path:
    row = index_row(
        ctx,
        archive_path,
        assessment_seq=assessment_seq,
        ruleset_version=ruleset_version,
        supersedes_seq=supersedes_seq,
    )
    return write_row(
        index_root, row, dt=ctx.received_at.date(), job_id=ctx.job_id, assessment_seq=assessment_seq
    )


@dataclass
class CompactionPlan:
    partition: Path
    files: list[Path]
    bytes_before: int

    @property
    def worth_doing(self) -> bool:
        return len(self.files) > 1


def plan_compaction(index_root: Path, today: date | None = None) -> list[CompactionPlan]:
    """Partitions holding more than one assessment file.

    One Parquet file per assessment is right for the write path — atomic,
    exclusively created, safe under contention (see `write_row`) — and
    wrong for the read path, where DuckDB opens every file in the glob.
    Each holds one row and a few KB of schema and footer, so a day of
    ingest costs far more in per-file overhead than in data, and the jobs
    list, the Overview counters and every reprocess scope slow down
    linearly with the number of documents ever ingested. Measured: 0.08s
    at 500 files, 3.3s at 20,000, on an index that is permanent by default.

    Today's partition is left alone. It is still being appended to, and
    compacting underneath a live writer would race the exclusive-create
    guard that stops two writers clobbering one assessment.
    """
    index_root = Path(index_root)
    today = today or datetime.now(UTC).date()
    skip = f"dt={today.isoformat()}"
    plans = []
    for partition in sorted(index_root.glob("dt=*")):
        if not partition.is_dir() or partition.name == skip:
            continue
        files = sorted(partition.glob("*.parquet"))
        plans.append(
            CompactionPlan(
                partition=partition,
                files=files,
                bytes_before=sum(f.stat().st_size for f in files),
            )
        )
    return [p for p in plans if p.worth_doing]


def compact_partition(plan: CompactionPlan) -> int:
    """Merge one partition's files into one. Returns bytes reclaimed.

    Crash-safe by ordering, and it needs no lock: the merged file is
    written and made visible *before* the originals are removed, so the
    only window is one in which every row is present twice. That is
    already harmless — every reader either QUALIFYs to one row per
    job_id or selects DISTINCT — so a crash mid-compaction costs disk
    space and nothing else, and re-running fixes it. The other order
    would have a window with no rows at all.
    """
    tables = [pq.read_table(f) for f in plan.files]
    merged = pa.concat_tables(tables, promote_options="permissive")
    # Named so it cannot collide with an assessment file, whose names are
    # always `<32 hex>_<4 digits>.parquet`.
    out_path = plan.partition / f"compacted-{plan.partition.name.removeprefix('dt=')}.parquet"
    with atomic_write(out_path) as tmp:
        pq.write_table(merged, tmp, compression="snappy")

    reclaimed = 0
    for path in plan.files:
        if path == out_path:
            continue
        reclaimed += path.stat().st_size
        path.unlink()
    reclaimed -= out_path.stat().st_size
    logger.debug(
        "compacted %s: %d file(s) -> 1, %d byte(s) reclaimed", plan.partition, len(plan.files), reclaimed
    )
    return reclaimed
