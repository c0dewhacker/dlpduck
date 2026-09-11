"""The content store: the one place raw `full_text` lives, kept out of the
metadata index (dlpduck.index) on purpose. A default (soft) purge is
exactly and only deleting a job's file here — the index row stays as
permanent proof the job happened, the archived PDF stays, and the audit
trail (which never held full_text) is untouched. See dlpduck/schema.py's
module docstring for the full reasoning.

A hard purge additionally deletes the archived PDF itself
(`purge_document`) — a real erasure, not just de-indexing. The index row
and audit trail still survive either way; nothing about them ever
depended on the document or its text existing.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from dlpduck.durability import atomic_write
from dlpduck.schema import CONTENT_SCHEMA
from dlpduck.types import DocumentText, JobContext, TextLine

logger = logging.getLogger("dlpduck.content")

# Job ids are content-derived (blake2b, digest_size=16 — see
# pipeline.content_job_id), so they are always exactly 32 hex characters.
# Everything below addresses files by interpolating a job id into a glob,
# which makes that shape a security boundary, not a formality: an
# unvalidated "*" would turn "purge this one job" into "purge every job",
# and "../.." would walk out of the store entirely. Validated here, at the
# only layer that touches the filesystem, so no caller can forget.
_JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")


class InvalidJobId(ValueError):
    pass


def validate_job_id(job_id: str) -> str:
    if not isinstance(job_id, str) or not _JOB_ID_RE.match(job_id):
        raise InvalidJobId(f"not a valid job id: {job_id!r}")
    return job_id


@dataclass
class PurgeResult:
    content_removed: bool
    # None means a hard purge wasn't requested, so the document was never
    # touched — distinct from False, which means it was requested but
    # there was nothing left to remove.
    document_removed: bool | None = None

    @property
    def hard(self) -> bool:
        return self.document_removed is not None


def write_content_row(content_root: Path, ctx: JobContext) -> Path:
    lines = [
        {
            "line_number": line.line_number,
            "page_number": line.page_number,
            "line_on_page": line.line_on_page,
            "lines_on_page": line.lines_on_page,
            "text": line.text,
            "source": line.source,
            "confidence": line.confidence,
        }
        for line in ctx.text.lines
    ]
    table = pa.Table.from_pylist(
        [{"job_id": ctx.job_id, "full_text": ctx.text.full_text, "lines": lines}],
        schema=CONTENT_SCHEMA,
    )
    partition = content_root / f"dt={ctx.received_at.date().isoformat()}"
    partition.mkdir(parents=True, exist_ok=True)
    out_path = partition / f"{ctx.job_id}.parquet"
    # Atomic: search reads this store through a dt=*/*.parquet glob, and a
    # single footerless file fails the whole query — so a crash while
    # writing one job's content would otherwise break search for every job
    # until someone found and deleted it.
    with atomic_write(out_path) as tmp:
        pq.write_table(table, tmp, compression="snappy")
    logger.debug("wrote content row for job %s (%d line(s)) to %s", ctx.job_id, len(lines), out_path)
    return out_path


def read_document_text(content_root: Path, job_id: str) -> DocumentText | None:
    """Reconstruct a DocumentText from the content store — everything the
    DLP engine needs to re-run rules without reopening the PDF,
    without re-opening the PDF. Returns None if the job's content was
    purged, or never existed.

    `page_count`/`ocr_page_count`/`degraded` are not reconstructed here —
    they describe the ORIGINAL extraction and belong to that job's index
    row, not to the text itself; a caller doing reprocessing should read
    them from the index rather than assume anything from this object.
    """
    validate_job_id(job_id)
    matches = list(Path(content_root).glob(f"dt=*/{job_id}.parquet"))
    if not matches:
        logger.debug("no content row for job %s (purged, or never existed)", job_id)
        return None
    row = pq.read_table(matches[0]).to_pylist()[0]
    doc = DocumentText()
    for raw in row["lines"]:
        doc.add_line(
            TextLine(
                line_number=raw["line_number"],
                page_number=raw["page_number"],
                line_on_page=raw["line_on_page"],
                lines_on_page=raw["lines_on_page"],
                text=raw["text"],
                source=raw["source"],
                confidence=raw["confidence"],
            )
        )
    return doc


def purge_content(content_root: Path, job_id: str) -> bool:
    """Delete a job's content file wherever it lives (content files are
    named `<job_id>.parquet`, so no date needs to be known up front).
    Returns True if a file was actually removed — False means it was
    already purged, or never existed, which the caller should treat as a
    fact worth recording either way, not an error.
    """
    validate_job_id(job_id)
    matches = list(Path(content_root).glob(f"dt=*/{job_id}.parquet"))
    for path in matches:
        path.unlink()
    logger.debug("purge_content(%s): removed %d file(s)", job_id, len(matches))
    return bool(matches)


def has_content(content_root: Path, job_id: str) -> bool:
    validate_job_id(job_id)
    return any(Path(content_root).glob(f"dt=*/{job_id}.parquet"))


def purge_document(destination_roots: list[Path], job_id: str) -> bool:
    """Delete a job's archived PDF — a hard purge, not the default. The
    document is already routed by disposition into one of two roots
    (destination.archive / destination.quarantine per the running config),
    so both are checked; the job's actual disposition determines which one
    actually has a file to remove. Same "no date needed up front, no error
    on a second call" contract as purge_content.
    """
    validate_job_id(job_id)
    removed = False
    for root in destination_roots:
        for path in Path(root).glob(f"dt=*/{job_id}.pdf"):
            path.unlink()
            removed = True
    return removed
