"""Claim -> process -> commit -> release. Each boundary is durable so
this ordering is load-bearing: each step is safe to repeat, and a crash
between any two steps leaves a state the startup sweep can resolve.
"""

from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import shutil
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dlpduck.audit import AuditLog
from dlpduck.config import Config
from dlpduck.content import PurgeResult, write_content_row
from dlpduck.content import purge_content as delete_content_file
from dlpduck.content import purge_document as delete_document_file
from dlpduck.disposition import decide
from dlpduck.durability import (
    copy_durably,
    write_atomically,
    write_bytes_durably,
)
from dlpduck.engine import DLPEngine
from dlpduck.extract import LineExtractor
from dlpduck.extract_worker import convert_isolated, inspect_isolated
from dlpduck.images import IMAGE_FORMATS, UnreadableImage, image_to_pdf, sniff
from dlpduck.index import write_index_row
from dlpduck.metadata import MetadataParserFactory, allowlist
from dlpduck.operations import LockContended, OperationalStore, operation_lock, serialized
from dlpduck.pdf_metadata import extract_pdf_metadata
from dlpduck.plugins.base import PluginError, PluginRunner
from dlpduck.rules import ruleset_version
from dlpduck.tracing import content_trace_enabled
from dlpduck.types import (
    AUDIT_HIT_FIELDS,
    DLPHit,
    DocumentText,
    DocumentTooLarge,
    EncryptedDocument,
    JobContext,
    RuleBudgetExceeded,
    Severity,
    TextLine,
    TooManyPages,
    UnsafeSourceFile,
    hit_record,
)

logger = logging.getLogger("dlpduck.pipeline")


# What claim refuses outright, before a job exists: routed to failed/ by
# reject_at_claim() rather than retried from the drop folder forever.
CLAIM_REFUSALS = (DocumentTooLarge, UnsafeSourceFile, UnreadableImage)


@dataclass(frozen=True)
class _Source:
    """A drop-folder file, read once and in the form the pipeline stores:
    `data` is always PDF bytes. `origin` describes the scanner image it was
    converted from, or is None for a file that arrived as a PDF."""

    data: bytes
    opened: os.stat_result
    origin: dict | None = None


def content_job_id(pdf_bytes: bytes) -> str:
    return hashlib.blake2b(pdf_bytes, digest_size=16).hexdigest()


# Bumped when the staging manifest gains something older readers lacked.
# 2: `audit_started` precedes the completion append; `metadata` is recorded.
MANIFEST_VERSION = 2

# Names this pipeline writes into a job's staging directory itself. A
# sender's companion file is never staged under its own name, so none of
# these can be overwritten from the drop folder.
STAGED_COMPANION = "companion.meta"
STAGED_REJECTED_COMPANION = "companion.rejected-symlink"
_RESERVED_STAGING_NAMES = frozenset(
    {"document.pdf", "manifest.json", "resolution.json", STAGED_COMPANION,
     STAGED_REJECTED_COMPANION}
)


def is_resolved(job_dir: Path) -> bool:
    """Has an operator marked this staged or failed job resolved?

    Only a record FailureQueue.resolve() actually wrote counts. Before
    companions were staged under a fixed name, a sender could drop
    `resolution.pdf` with a `resolution.json` beside it and have the
    never-scanned document skipped by every sweep and filed straight into
    the resolved queue; a directory staged by that release must not keep
    that effect after an upgrade.
    """
    path = job_dir / "resolution.json"
    if not path.is_file() or path.is_symlink():
        return False
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError):
        return False
    return isinstance(record, dict) and {"reason", "actor"} <= record.keys()


def _read_bounded_with_stat(
    path: Path, limit: int
) -> tuple[bytes | None, os.stat_result]:
    """Read at most `limit` bytes without following a symlink. Returns
    (None, stat) if the file is bigger than `limit`: companion metadata
    arrives from the same drop folder as the PDF and so gets the same
    "bounded by what is actually read" treatment."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UnsafeSourceFile(f"{path} is a symlink — refusing to follow it") from None
        raise
    try:
        stat = os.fstat(fd)
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as file:
        data = file.read(limit + 1)
    return (None if len(data) > limit else data), stat


def _older_than(job_dir: Path, cutoff: float) -> bool:
    """Was this staged job last touched before `cutoff`? Judged by its
    manifest, which every step of a job's progress rewrites."""
    marker = job_dir / "manifest.json"
    try:
        return (marker if marker.exists() else job_dir).stat().st_mtime < cutoff
    except FileNotFoundError:
        return False


def _unlink_if_same(path: Path, opened: os.stat_result) -> None:
    """Remove only the directory entry that was actually read."""
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
        path.unlink()


class Pipeline:
    def __init__(self, config: Config):
        self.config = config
        self.operations = OperationalStore(config.destination.work_dir)
        self.extractor = LineExtractor(
            dpi=config.extraction.dpi,
            isolate=config.extraction.isolate_worker,
            timeout=config.extraction.timeout_seconds,
            max_pages=config.limits.max_pages,
            memory_mb=config.extraction.worker_memory_mb,
            blank_max_ink=config.extraction.blank_page_max_ink,
        )
        self.extractor.NATIVE_MIN_CHARS = config.extraction.native_min_chars
        self.engine = DLPEngine(
            rules=config.load_rules(),
            hmac_key=config.hmac_key(),
            rule_budget_seconds=config.rule_budget_seconds,
        )
        self.ruleset_version = ruleset_version(self.engine.rules)
        self.metadata_parser = MetadataParserFactory.get_parser(
            config.source.metadata_format
        )
        self.audit = AuditLog(config.audit_dir, integrity=config.audit.integrity)
        self.index_root = config.destination.work_dir / "index"
        self.content_root = config.destination.work_dir / "content"
        self.plugins = PluginRunner(config.load_plugins(), self.audit)
        self._warned_uncertain: set[str] = set()

    def job_lock(self, job_id: str, *, blocking: bool = True):
        """Per-job_id lock: stops two attempts to claim, recover, or
        retry the *same* job from racing, without making unrelated
        job_ids contend."""
        return operation_lock(self.config.destination.work_dir / "_locks" / job_id, blocking=blocking)

    def _pdf_metadata(self, pdf_bytes: bytes) -> dict:
        """The PDF's own Info dictionary. Reading it means parsing the PDF,
        so it happens in the isolated worker whenever extraction does."""
        if self.config.extraction.isolate_worker:
            # Bounded well below the extraction budget: this runs inside
            # claim, on the watcher's single poll thread, and reading an
            # Info dictionary is milliseconds of work for any honest PDF.
            return inspect_isolated(
                pdf_bytes,
                timeout=min(30.0, self.config.extraction.timeout_seconds),
                memory_mb=self.config.extraction.worker_memory_mb,
            )
        return extract_pdf_metadata(pdf_bytes)

    def _read_source(self, path: Path) -> _Source:
        """Read a drop-folder file without following a symlink, bounded by
        limits.max_bytes, and convert a scanner image to PDF.

        The format is decided from the content, not the filename: a retry
        restores a failed job under its original name (scan.tif) while the
        stored document is already the converted PDF, and a scanner that
        mislabels its output should not decide how it is parsed.
        """
        limit = self.config.limits.max_bytes
        raw, opened = _read_bounded_with_stat(path, limit)
        if opened.st_size > limit:
            raise DocumentTooLarge(f"{path} is {opened.st_size} bytes, over the configured limit")
        # Read with the limit as a hard ceiling rather than trusting the
        # stat above: the file can still grow between the two (a writer
        # that wasn't finished after all), and the limit exists to bound
        # what actually reaches memory.
        if raw is None:
            raise DocumentTooLarge(f"{path} exceeds the configured {limit}-byte limit")

        kind = sniff(raw)
        if kind in IMAGE_FORMATS:
            pdf = self._convert_image(raw)
            origin = {
                "source_format": kind,
                "source_sha256": hashlib.sha256(raw).hexdigest(),
                "source_bytes": len(raw),
            }
            return _Source(pdf, opened, origin)
        if kind is None and path.suffix.lower() in {
            s.lower() for s in self.config.source.image_suffixes
        }:
            raise UnreadableImage(f"{path.name} is not a TIFF, JPEG or PNG image")
        return _Source(raw, opened)

    def _convert_image(self, raw: bytes) -> bytes:
        limits, extraction = self.config.limits, self.config.extraction
        if extraction.isolate_worker:
            return convert_isolated(
                raw,
                max_pages=limits.max_pages,
                max_pixels=limits.max_image_pixels,
                timeout=extraction.timeout_seconds,
                memory_mb=extraction.worker_memory_mb,
            )
        return image_to_pdf(raw, max_pages=limits.max_pages, max_pixels=limits.max_image_pixels)

    def _discard_job_lock_dir(self, job_id: str) -> None:
        """claim() now takes job_lock() for every arrival, not just
        retries and crash recovery, so leaving _locks/<job_id> behind
        forever would accumulate one directory and lock file per job
        ever processed. Safe to remove while the calling with-block still
        holds the lock: unlinking doesn't affect an already-open file
        descriptor, and job_lock() recreates the directory on demand for
        whatever comes next."""
        shutil.rmtree(
            self.config.destination.work_dir / "_locks" / job_id, ignore_errors=True
        )

    def _record_duplicate_arrival(
        self,
        job_id: str,
        pdf_path: Path,
        opened_pdf,
        metadata_path: Path | None,
        content_bytes: bytes,
        event: str,
    ) -> tuple[datetime, dict]:
        """A source pair that isn't going to be staged (or isn't staging
        anything new) still gets a receipt and an audit event — silently
        dropping it would look, from the console, exactly like it never
        arrived. Shared by the pre-claim "already indexed" short-circuit
        and claim()'s own "someone already holds job_lock for this exact
        content right now" case. Cleans up the incoming file either way
        and returns (received_at, allowlisted metadata) for the caller's
        JobContext.
        """
        receipt_id = uuid.uuid4().hex
        received_at = datetime.now(UTC)
        receipt_metadata = self._pdf_metadata(content_bytes)
        opened_metadata = None
        if metadata_path is not None and metadata_path.is_symlink():
            self.audit.append(
                "metadata.rejected", job_id=job_id, receipt_id=receipt_id,
                companion=metadata_path.name, error="symlink refused",
            )
        elif metadata_path is not None and metadata_path.is_file():
            try:
                companion, opened_metadata = _read_bounded_with_stat(
                    metadata_path, self.config.limits.max_metadata_bytes
                )
            except UnsafeSourceFile:
                companion = None
                self.audit.append(
                    "metadata.rejected", job_id=job_id, receipt_id=receipt_id,
                    companion=metadata_path.name, error="symlink refused",
                )
            if companion is not None:
                try:
                    receipt_metadata = {**receipt_metadata, **self.metadata_parser.parse(companion)}
                except Exception as exc:
                    self.audit.append(
                        "metadata.rejected", job_id=job_id, receipt_id=receipt_id,
                        companion=metadata_path.name, error=str(exc),
                    )
        receipt_metadata = allowlist(receipt_metadata, self.config.source.metadata_fields)
        self.operations.receipt(
            receipt_id, job_id, received_at.isoformat(), pdf_path.name, self.config.source.name
        )
        self.operations.receipt_metadata(job_id, receipt_id, receipt_metadata)
        self.operations.finish_receipt(job_id, receipt_id, "duplicate")
        self.audit.append(event, job_id=job_id, receipt_id=receipt_id, source_name=pdf_path.name)
        _unlink_if_same(pdf_path, opened_pdf)
        if metadata_path is not None:
            if opened_metadata is not None:
                _unlink_if_same(metadata_path, opened_metadata)
            elif metadata_path.is_symlink():
                metadata_path.unlink(missing_ok=True)
        return received_at, receipt_metadata

    # ── claim ────────────────────────────────────────────────────────

    def claim(
        self,
        pdf_path: Path,
        metadata_path: Path | None,
        staging_root: Path,
        *,
        source: _Source | None = None,
    ) -> JobContext:
        """Safely read and claim a source pair into a job-scoped staging
        directory, then build its initial JobContext. Raises
        DocumentTooLarge / IOError before a complete file is accepted if
        limits are exceeded.

        If another actor already holds job_lock(job_id) for this exact
        content right now, nothing is staged at all — this returns a
        JobContext with reason="duplicate_in_progress" instead (the same
        shape the already-indexed pre-check in run_job() returns for a
        settled duplicate), rather than raising, since the source file
        has already been recorded as a receipt and cleaned up: there is
        nothing left to treat as an error.
        """
        # A drop folder is usually writable by something less trusted than
        # this daemon (an MFP's account, a share). A symlink there would
        # otherwise be followed straight through to whatever it points at,
        # and that file's contents would end up extracted into the content
        # store — searchable, and downloadable through the console.
        logger.debug("claiming %s (source=%s)", pdf_path.name, self.config.source.name)
        if source is None:
            source = self._read_source(pdf_path)
        pdf_bytes, opened_pdf = source.data, source.opened
        job_id = content_job_id(pdf_bytes)
        pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()

        # Claiming writes into _processing/<job_id>/, the exact directory
        # a sweep or a retry already holding job_lock(job_id) is reading
        # from or committing right now — without this, a fresh arrival of
        # byte-identical content could overwrite that manifest mid-flight
        # (a real, reproduced bug: the in-flight commit ends up finishing
        # under the new arrival's receipt_id, leaving the original receipt
        # stuck at "received" forever). Non-blocking, not blocking: this
        # runs on the watcher's single poll thread, and the whole point of
        # job_lock is that a slow job elsewhere must never stall it.
        try:
            with self.job_lock(job_id, blocking=False):
                return self._claim_locked(
                    pdf_path, opened_pdf, metadata_path, staging_root, job_id, pdf_bytes,
                    pdf_sha256, source.origin,
                )
        except LockContended:
            received_at, metadata = self._record_duplicate_arrival(
                job_id, pdf_path, opened_pdf, metadata_path, pdf_bytes,
                event="job.received_while_processing",
            )
            return JobContext(
                job_id=job_id,
                received_at=received_at,
                source_name=self.config.source.name,
                staging_dir=staging_root / job_id,
                pdf_path=pdf_path,
                pdf_sha256=pdf_sha256,
                metadata=metadata,
                reason="duplicate_in_progress",
            )

    def _claim_locked(
        self,
        pdf_path: Path,
        opened_pdf,
        metadata_path: Path | None,
        staging_root: Path,
        job_id: str,
        pdf_bytes: bytes,
        pdf_sha256: str,
        origin: dict | None = None,
    ) -> JobContext:
        staging_dir = staging_root / job_id
        staging_dir.mkdir(parents=True, exist_ok=True)
        staged_pdf = staging_dir / "document.pdf"
        # Publish the exact bytes read through the no-follow descriptor.
        # Moving the path after reading would reopen a TOCTOU window where
        # an attacker swaps that directory entry for a symlink.
        receipt_id = uuid.uuid4().hex
        received_at = datetime.now(UTC)
        manifest: dict[str, Any] = {"receipt_id": receipt_id, "received_at": received_at.isoformat(),
                    "filename": pdf_path.name, "source_name": self.config.source.name,
                    "steps": [], "version": MANIFEST_VERSION}
        if origin is not None:
            manifest["origin"] = origin
        write_atomically(staging_dir / "manifest.json", json.dumps(manifest))
        write_bytes_durably(staged_pdf, pdf_bytes)
        _unlink_if_same(pdf_path, opened_pdf)
        self.operations.receipt(
            receipt_id,
            job_id,
            received_at.isoformat(),
            manifest["filename"],
            self.config.source.name,
        )
        if origin is not None:
            # The archived PDF is not byte-identical to what the scanner
            # wrote, so what it was converted from is part of the record.
            self.audit.append(
                "document.converted", job_id=job_id, receipt_id=receipt_id,
                filename=pdf_path.name, **origin,
            )

        # Read the PDF's own Info dictionary first; a companion
        # file, when one exists, wins on any key they both set.
        raw_metadata: dict = self._pdf_metadata(pdf_bytes)
        if metadata_path is not None and metadata_path.is_symlink():
            shutil.move(str(metadata_path), str(staging_dir / STAGED_REJECTED_COMPANION))
            self.audit.append(
                "metadata.rejected",
                job_id=job_id,
                companion=metadata_path.name,
                error="symlink refused",
            )
        elif metadata_path is not None and metadata_path.is_file():
            content, opened_metadata = _read_bounded_with_stat(
                metadata_path, self.config.limits.max_metadata_bytes
            )
            if content is not None:
                # Under a fixed name, never the sender's. The staging
                # directory also holds this job's own manifest.json and,
                # once an operator acts, resolution.json — a companion
                # called either of those would overwrite the manifest (and
                # wedge the job) or mark a never-scanned document resolved.
                write_bytes_durably(staging_dir / STAGED_COMPANION, content)
                manifest["companion"] = metadata_path.name
                write_atomically(staging_dir / "manifest.json", json.dumps(manifest))
            _unlink_if_same(metadata_path, opened_metadata)
            if content is None:
                logger.warning(
                    "companion %s exceeds limits.max_metadata_bytes — ignoring it",
                    metadata_path.name,
                )
                self.audit.append(
                    "metadata.rejected",
                    job_id=job_id,
                    companion=metadata_path.name,
                    error="exceeds limits.max_metadata_bytes",
                )
            else:
                try:
                    raw_metadata = {**raw_metadata, **self.metadata_parser.parse(content)}
                except Exception as exc:
                    # Processing continues without the companion — the
                    # document itself is what matters and still gets
                    # scanned. But this is also how a malformed or hostile
                    # companion file (an XML entity bomb, say) shows up, so
                    # it belongs in the audit trail and not only in a log
                    # nobody reads.
                    logger.warning("metadata parse failed for %s: %s", job_id, exc)
                    self.audit.append(
                        "metadata.rejected",
                        job_id=job_id,
                        companion=metadata_path.name,
                        error=str(exc),
                    )

        metadata = allowlist(raw_metadata, self.config.source.metadata_fields)
        self.operations.receipt_metadata(job_id, receipt_id, metadata)
        # Kept with the job, so whichever replica's sweep picks it up uses
        # what was decided here instead of parsing the PDF (in another
        # worker process) and the companion all over again.
        manifest["metadata"] = metadata
        write_atomically(staging_dir / "manifest.json", json.dumps(manifest))
        if content_trace_enabled():
            logger.debug("job %s claimed metadata: %r", job_id, metadata)
        else:
            logger.debug("job %s claimed with %d metadata field(s) kept", job_id, len(metadata))

        return JobContext(
            job_id=job_id,
            received_at=received_at,
            source_name=self.config.source.name,
            staging_dir=staging_dir,
            pdf_path=staged_pdf,
            pdf_sha256=pdf_sha256,
            metadata=metadata,
            text=None,  # set in process()
        )

    # ── process ──────────────────────────────────────────────────────

    def process(self, ctx: JobContext) -> None:
        pdf_bytes = ctx.pdf_path.read_bytes()

        logger.debug("job %s extracting (%d bytes)", ctx.job_id, len(pdf_bytes))
        try:
            ctx.text = self.extractor.extract(pdf_bytes)
        except TooManyPages as exc:
            ctx.disposition = "failed"
            ctx.reason = "page_count_exceeds_limit"
            self.audit.append(
                "job.failed", job_id=ctx.job_id, reason=ctx.reason, page_count=exc.page_count
            )
            return
        except EncryptedDocument:
            ctx.disposition = "failed"
            ctx.reason = "encrypted"
            self.audit.append("job.failed", job_id=ctx.job_id, reason=ctx.reason)
            return
        except Exception as exc:
            ctx.disposition = "failed"
            ctx.reason = f"extraction_error: {exc}"
            self.audit.append("job.failed", job_id=ctx.job_id, reason=ctx.reason)
            return
        logger.debug(
            "job %s extracted %d page(s), %d via OCR, degraded=%s",
            ctx.job_id, ctx.text.page_count, ctx.text.ocr_page_count, ctx.text.degraded,
        )
        if content_trace_enabled():
            for line in ctx.text.lines:
                logger.debug(
                    "job %s p%d L%d (%s, conf=%s): %r",
                    ctx.job_id, line.page_number, line.line_number,
                    line.source, line.confidence, line.text,
                )

        try:
            ctx.hits = self.engine.scan(ctx.text)
        except RuleBudgetExceeded as exc:
            ctx.disposition = "failed"
            ctx.reason = f"rule_budget_exceeded: {exc.rule_id}"
            self.audit.append(
                "job.failed", job_id=ctx.job_id, reason=ctx.reason, rule_id=exc.rule_id
            )
            return
        except Exception as exc:
            # A rule or validator that raises (a custom validator meeting
            # input it didn't expect, say) means this document could not
            # be assessed. That is a failure to route, not a crash to let
            # escape: escaping left the job staged and retried on every
            # sweep, failing identically each time.
            logger.exception("job %s: scanning raised", ctx.job_id)
            ctx.disposition = "failed"
            ctx.reason = f"scan_error: {type(exc).__name__}"
            self.audit.append("job.failed", job_id=ctx.job_id, reason=ctx.reason)
            return
        logger.debug("job %s scanned: %d hit(s)", ctx.job_id, len(ctx.hits))

        # Enrich runs before disposition so it can inform routing (e.g. a
        # department attached here could feed a future per-department
        # rule). PluginRunner already logged the failure; a critical one
        # routes the job to failed/ same as any other unprocessable input.
        try:
            self.plugins.run(ctx, phase="enrich")
        except PluginError as exc:
            ctx.disposition = "failed"
            ctx.reason = f"enrich_plugin_failed: {exc.plugin_name}"
            self.audit.append("job.failed", job_id=ctx.job_id, reason=ctx.reason)
            return

        self._disposition(ctx)

    def _disposition(self, ctx: JobContext) -> None:
        if ctx.text is None:
            raise ValueError("Cannot assess a document without extraction")
        ctx.disposition, ctx.reason = decide(ctx.text, ctx.hits, self.config.dlp.quarantine_on_degraded)
        logger.debug("job %s disposition: %s (%s)", ctx.job_id, ctx.disposition, ctx.reason)

    # ── commit ───────────────────────────────────────────────────────

    def _manifest(self, ctx: JobContext) -> dict:
        path = ctx.staging_dir / "manifest.json"
        return json.loads(path.read_text()) if path.is_file() else {"steps": []}

    def _checkpoint(self, ctx: JobContext, manifest: dict, step: str) -> None:
        if step not in manifest["steps"]:
            manifest["steps"].append(step)
        write_atomically(ctx.staging_dir / "manifest.json", json.dumps(manifest))

    def _snapshot_assessment(self, ctx: JobContext, manifest: dict) -> None:
        if "assessment" in manifest:
            return
        manifest["assessment"] = {
            "text": asdict(ctx.text) if ctx.text is not None else None,
            "hits": [asdict(hit) for hit in ctx.hits],
            "disposition": ctx.disposition,
            "reason": ctx.reason,
            "metadata": ctx.metadata,
            "audit_fields": ctx.audit_fields,
            "ruleset_version": self.ruleset_version,
        }
        self._checkpoint(ctx, manifest, "assessed")

    def _completion_already_audited(self, ctx: JobContext, manifest: dict) -> bool:
        """Did a previous attempt append this receipt's job.completed and
        crash before checkpointing it?

        Only answerable by reading the trail, which used to happen on every
        commit — a scan of the whole audit history per document, growing
        without bound. Now the manifest records `audit_started` just before
        the append, so the trail is read only when that marker says an
        append may have happened, and then only from the receipt's own day.
        """
        if not manifest.get("receipt_id"):
            return False
        # A manifest from before `audit_started` existed cannot say either
        # way, so it gets the old full check.
        legacy = manifest.get("version", 1) < MANIFEST_VERSION
        if not legacy and "audit_started" not in manifest["steps"]:
            return False
        since = None
        if manifest.get("received_at"):
            since = datetime.fromisoformat(manifest["received_at"]).date()
        return any(
            e.get("receipt_id") == manifest["receipt_id"] and e.get("event") == "job.completed"
            for e in self.audit.events_for_job(ctx.job_id, since=since)
        )

    @serialized
    def commit(self, ctx: JobContext) -> Path:
        """1) copy the PDF, 2) append+fsync the audit event, 3) write the
        index row, 4) release staging. Each step is idempotent: job_id is
        content-derived, so re-running this on the same
        input is a no-op once the index row exists.
        """
        # A job only reaches commit after process() extracted successfully;
        # a failure routes to commit_failed instead. That invariant was
        # implicit — every consumer below reads ctx.text.lines and would
        # have raised AttributeError on None, several frames from the
        # actual mistake. Stating it here makes a wrong call site say so.
        if ctx.text is None:
            raise ValueError(
                f"commit called for job {ctx.job_id} with no extracted text — "
                "an unprocessable job belongs in commit_failed"
            )
        manifest = self._manifest(ctx)
        self._snapshot_assessment(ctx, manifest)
        dest_root = (
            self.config.destination.quarantine
            if ctx.disposition == "quarantine"
            else self.config.destination.archive
        )
        partition = dest_root / f"dt={ctx.received_at.date().isoformat()}"
        partition.mkdir(parents=True, exist_ok=True)
        dest_path = partition / f"{ctx.job_id}.pdf"
        if "pdf" not in manifest["steps"]:
            copy_durably(ctx.pdf_path, dest_path)
            self._checkpoint(ctx, manifest, "pdf")

        if "audit" not in manifest["steps"] and not self._completion_already_audited(ctx, manifest):
            self._checkpoint(ctx, manifest, "audit_started")
            self.audit.append(
                "job.completed",
                receipt_id=manifest.get("receipt_id"),
                job_id=ctx.job_id,
                disposition=ctx.disposition,
                reason=ctx.reason,
                page_count=ctx.text.page_count,
                ocr_page_count=ctx.text.ocr_page_count,
                failed_page_count=ctx.text.failed_page_count,
                degraded=ctx.text.degraded,
                highest_severity=ctx.highest_severity.value if ctx.highest_severity else None,
                hit_count=len(ctx.hits),
                hits=[hit_record(h, AUDIT_HIT_FIELDS) for h in ctx.hits],
                audit_fields=ctx.audit_fields,
            )
        self._checkpoint(ctx, manifest, "audit")

        if "stores" not in manifest["steps"]:
            write_index_row(
                self.index_root,
                ctx,
                archive_path=str(dest_path),
                assessment_seq=1,
                ruleset_version=manifest["assessment"]["ruleset_version"],
                supersedes_seq=None,
            )
            write_content_row(self.content_root, ctx)
            self._checkpoint(ctx, manifest, "stores")

        # Emit-phase sinks run last and are best-effort — a non-critical
        # failure is already logged and spooled by PluginRunner/the sink
        # itself. A critical one re-raises here: the PDF, audit event, and
        # index row are already durable by this point, so unlike an
        # extraction failure this can't be "routed to failed/" — instead
        # staging is deliberately NOT released (the rmtree below never
        # runs), leaving it for an operator to find.
        if "emit_started" in manifest["steps"] and "emitted" not in manifest["steps"]:
            # An external side effect may have happened before the crash. Do not
            # guess and replay it; preserve staging for an explicit operator retry.
            raise RuntimeError("emit outcome uncertain; inspect staged job before retrying delivery")
        if "emitted" not in manifest["steps"]:
            self._checkpoint(ctx, manifest, "emit_started")
            self.plugins.run(ctx, phase="emit")
            self._checkpoint(ctx, manifest, "emitted")
        if manifest.get("receipt_id"):
            self.operations.finish_receipt(ctx.job_id, manifest["receipt_id"], ctx.disposition)

        # If retry() died before its own cleanup ran, the original
        # failed/<job_id> folder is left behind even though this commit
        # just superseded it — remove it so Needs Attention doesn't show
        # a stale failure for an already-archived job.
        stale_failed = self.config.destination.work_dir / "failed" / ctx.job_id
        if stale_failed.is_dir() and not stale_failed.is_symlink():
            shutil.rmtree(stale_failed, ignore_errors=True)

        shutil.rmtree(ctx.staging_dir, ignore_errors=True)
        self._discard_job_lock_dir(ctx.job_id)
        logger.debug("job %s committed to %s", ctx.job_id, dest_path)
        return dest_path

    @serialized
    def commit_failed(self, ctx: JobContext) -> Path:
        """Route an unprocessable job to failed/ for operator attention
        rather than losing it or pretending it succeeded."""
        logger.debug("job %s committing to failed/: %s", ctx.job_id, ctx.reason)
        manifest = self._manifest(ctx)
        self._snapshot_assessment(ctx, manifest)
        failed_root = self.config.destination.work_dir / "failed" / ctx.job_id
        failed_root.mkdir(parents=True, exist_ok=True)
        dest = failed_root / "document.pdf"
        copy_durably(ctx.pdf_path, dest)
        # Atomic and fsync'd: this file is the only thing that says *why*
        # the PDF sitting next to it failed, and a crash here is exactly
        # the kind of event that produces failed jobs in the first place.
        # A truncated metadata.json would leave an operator with a
        # document and no explanation.
        write_atomically(
            failed_root / "metadata.json",
            json.dumps(
                {
                    "job_id": ctx.job_id,
                    "reason": ctx.reason,
                    "filename": manifest.get("filename", "document.pdf"),
                    "received_at": ctx.received_at.isoformat(),
                },
                indent=2,
            ),
        )
        if manifest.get("receipt_id"):
            self.operations.finish_receipt(ctx.job_id, manifest["receipt_id"], "failed")
        shutil.rmtree(ctx.staging_dir, ignore_errors=True)
        self._discard_job_lock_dir(ctx.job_id)
        return dest

    def reject_at_claim(self, pdf_path: Path, reason: str, detail: str) -> Path:
        """Route a file that could not be claimed to the failed directory.

        `claim()` refuses some files before a JobContext exists: one over
        `limits.max_bytes`, or a symlink that would lead out of the drop
        folder. Those are policy decisions, not crashes, and they need the
        same fail-closed handling as everything else — otherwise the file
        stays in the drop folder, gets re-attempted on every poll forever,
        and the only trace is a log line nobody is reading. A document the
        system declined to assess must be visible as such.

        The id can't be content-derived here: refusing to read the content
        is the whole point of the size limit. It comes from the file's
        identity instead — name, size, mtime — which is stable across
        retries, so a file rejected twice lands in one place rather than
        accumulating directories.
        """
        # lstat, not stat: one of the two things that gets rejected here is
        # a symlink, and following it to size the target is exactly what
        # claim() just refused to do. (`shutil.move` below relocates the
        # link itself rather than its target, for the same reason.)
        stat = pdf_path.lstat()
        fingerprint = f"{pdf_path.name}:{stat.st_size}:{stat.st_mtime_ns}".encode()
        job_id = hashlib.blake2b(fingerprint, digest_size=16).hexdigest()
        received_at = datetime.now(UTC)

        failed_root = self.config.destination.work_dir / "failed" / job_id
        failed_root.mkdir(parents=True, exist_ok=True)
        # Moved, not copied. Leaving it in place is what produced the
        # forever-retry loop; the operator finds it under failed/ instead.
        shutil.move(str(pdf_path), str(failed_root / "document.pdf"))
        write_atomically(
            failed_root / "metadata.json",
            json.dumps(
                {
                    "job_id": job_id,
                    "reason": reason,
                    "detail": detail,
                    "source_name": pdf_path.name,
                    "received_at": received_at.isoformat(),
                },
                indent=2,
            ),
        )
        self.audit.append(
            "job.failed",
            job_id=job_id,
            reason=reason,
            detail=detail,
            source_name=pdf_path.name,
            size_bytes=stat.st_size,
        )
        logger.warning("refused %s at claim (%s) — moved to %s", pdf_path.name, reason, failed_root)
        return failed_root / "document.pdf"

    # ── content lifecycle ────────────────────────────────────────────

    @serialized
    def purge_content(
        self, job_id: str, reason: str, actor: str, hard: bool = False
    ) -> PurgeResult:
        """Delete a job's raw text from the content store — and, if
        `hard`, the archived PDF as well, a real erasure rather than just
        de-indexing.

        Either way, the index row (proof the job happened, with
        already-masked hits) and every prior audit event are untouched —
        neither ever held `full_text` or the document, so there is nothing
        there that needed deleting. One new, append-only audit event
        records what happened; the chain never breaks and nothing is
        rewritten. A False/None component means there was nothing left to
        remove (already purged, or never existed) — the caller should
        still treat that as worth recording, not as an error.
        """
        # Intent is recorded BEFORE anything is deleted. The append is
        # fsync'd, so a crash between the two leaves a purge.started with
        # no matching content.purged — visible, reconcilable evidence that
        # a deletion was in flight. Auditing only afterwards meant a crash
        # mid-purge destroyed data and left no record that anyone had
        # asked for it, which is the one outcome this tool must not have.
        self.audit.append(
            "purge.started",
            job_id=job_id,
            reason=reason,
            actor=actor,
            mode="hard" if hard else "soft",
        )
        content_removed = delete_content_file(self.content_root, job_id)
        text_dropped = self._drop_pending_transition_text(job_id)
        document_removed = None
        if hard:
            document_removed = delete_document_file(
                [self.config.destination.archive, self.config.destination.quarantine], job_id
            )
        self.audit.append(
            "content.purged",
            job_id=job_id,
            reason=reason,
            actor=actor,
            mode="hard" if hard else "soft",
            content_removed=content_removed,
            document_removed=document_removed,
            **({"pending_transition_text_dropped": True} if text_dropped else {}),
        )
        return PurgeResult(content_removed=content_removed, document_removed=document_removed)

    def _drop_pending_transition_text(self, job_id: str) -> bool:
        """An extract-mode reassessment that crashed part-way leaves its
        transition (dlpduck.reprocess) on disk, carrying the freshly
        extracted text, to be finished on the next start. Finishing it
        after a purge would write that text straight back into the content
        store — undoing the erasure with nothing recording it. The
        assessment itself is still worth completing; only its text goes.
        Runs under the same lock recovery does (purge is @serialized)."""
        path = self.config.destination.work_dir / "transitions" / f"{job_id}.json"
        if not path.is_file():
            return False
        payload = json.loads(path.read_text())
        if payload.get("text") is None:
            return False
        payload["text"] = None
        write_atomically(path, json.dumps(payload))
        return True

    def run_job(self, pdf_path: Path, metadata_path: Path | None, staging_root: Path) -> JobContext:
        # Deliberately NOT @serialized: extraction (the slow part) used to
        # run under the global work_dir lock, blocking every unrelated
        # purge/retry/resolve/reprocess for as long as it took. commit()/
        # commit_failed() are still @serialized and idempotent (a repeat
        # commit sees "stores" already checkpointed and no-ops), so that
        # boundary is enough. Detect a duplicate arrival before claiming so
        # an earlier job staged during an uncertain emit isn't overwritten.
        #
        # The file is read (and, for a scanner image, converted) exactly
        # once here and handed to claim(), rather than read for this check
        # and then again to claim it.
        try:
            source = None if pdf_path.is_symlink() else self._read_source(pdf_path)
            if source is not None:
                duplicate_id = content_job_id(source.data)
                from dlpduck.reprocess import latest_index_rows

                existing = latest_index_rows(self.index_root, job_ids=[duplicate_id])
                if existing:
                    received_at, receipt_metadata = self._record_duplicate_arrival(
                        duplicate_id, pdf_path, source.opened, metadata_path, source.data,
                        event="job.received_again",
                    )
                    return JobContext(
                        job_id=duplicate_id,
                        received_at=received_at,
                        source_name=self.config.source.name,
                        staging_dir=staging_root / duplicate_id,
                        pdf_path=pdf_path,
                        pdf_sha256=hashlib.sha256(source.data).hexdigest(),
                        metadata=receipt_metadata,
                        disposition=existing[0]["disposition"],
                        reason="duplicate_receipt",
                    )
            ctx = self.claim(pdf_path, metadata_path, staging_root, source=source)
        except CLAIM_REFUSALS as exc:
            # A refusal, not a crash — route it fail-closed rather than
            # letting it escape to a caller whose only option is to log it
            # and try the same file again next poll.
            self.reject_at_claim(pdf_path, type(exc).__name__, str(exc))
            raise
        if ctx.reason == "duplicate_in_progress":
            # claim() already recorded this as a duplicate arrival and
            # cleaned up the source file — nothing was staged, so there
            # is nothing left for this call to do.
            return ctx

        # claim() already released this same lock the moment it returned,
        # so re-acquiring it here closes the one gap that leaves open: two
        # independent claims of the same content landing at nearly the
        # same instant (neither racing an in-progress job — claim()'s own
        # check already rules that out — just each other). Blocking here
        # is deliberate and bounded, not a regression of the "never stall
        # the watcher" goal: this can only contend against another equally
        # fresh claim of the identical content, never a slow extraction —
        # nothing could be mid-extraction on this job_id yet, since ours
        # only just succeeded. Whichever call loses this race blocks until
        # the winner's commit() finishes, then finds the job already
        # indexed and resolves as a duplicate — exactly the outcome
        # intended, not a stall.
        with self.job_lock(ctx.job_id):
            return self._finish_staged(ctx)

    def stage(self, pdf_path: Path, metadata_path: Path | None, staging_root: Path) -> JobContext | None:
        """claim() a file and stop — no extraction, no commit. Used by the
        watcher when a sweep (resume_staged(), run continuously — see
        cli.py) is doing the actual processing, so the poll loop stays
        fast and single-writer while extraction can happen on any
        replica. Returns None for a claim-time refusal (already routed to
        failed/ and audited, same as run_job()) rather than raising, since
        the watcher's poll loop treats that as "handled", not an error.
        claim() itself already resolves an in-progress duplicate without
        staging anything, so that case just flows through like any other
        successful claim — there's nothing further for a sweep to do
        with it either way.
        """
        try:
            return self.claim(pdf_path, metadata_path, staging_root)
        except CLAIM_REFUSALS as exc:
            self.reject_at_claim(pdf_path, type(exc).__name__, str(exc))
            return None

    def _finish_staged(self, ctx: JobContext) -> JobContext:
        """A claimed job with no extraction done yet: short-circuit it as
        a duplicate of an already-indexed job, or extract, scan, and
        commit it. Shared by run_job() (synchronous — retry(), the CLI)
        and resume_staged() (asynchronous — crash recovery and, run
        continuously, the parallel-extraction sweep), so a job staged by
        one and picked up by the other still gets this check exactly
        once."""
        from dlpduck.reprocess import latest_index_rows

        existing = latest_index_rows(self.index_root, job_ids=[ctx.job_id])
        if existing:
            prior = existing[0]
            ctx.disposition, ctx.reason = prior["disposition"], "duplicate_receipt"
            manifest = self._manifest(ctx)
            if manifest.get("receipt_id"):
                self.operations.finish_receipt(ctx.job_id, manifest["receipt_id"], "duplicate")
                self.audit.append(
                    "job.received_again", job_id=ctx.job_id, receipt_id=manifest["receipt_id"]
                )
            shutil.rmtree(ctx.staging_dir, ignore_errors=True)
            logger.debug("job %s is a duplicate receipt of an existing assessment", ctx.job_id)
            return ctx
        self.process(ctx)
        if ctx.disposition == "failed":
            self.commit_failed(ctx)
        else:
            self.commit(ctx)
        return ctx

    # ── crash recovery ───────────────────────────────────────────────

    def resume_staged(
        self, staging_root: Path, job_id: str | None = None, *, min_age_seconds: float = 0
    ) -> list[JobContext]:
        """Process anything sitting claimed-but-unfinished in
        `_processing/` — a job a crashed process never got back to, or
        (when run continuously; see cli.py) one the watcher only just
        staged. job_id is content-derived, so re-running is idempotent.

        Deliberately NOT @serialized: a large staged queue would otherwise
        hold the global lock (and block console readiness) for as long as
        the whole sweep took. Each job is guarded instead by its own
        non-blocking job_lock(), so two resumes of the *same* job can't
        race — which is also what makes it safe to run this on every
        replica at once: whichever gets a job's lock first extracts it,
        everyone else skips it and moves on to a different one.
        """
        resumed: list[JobContext] = []
        if not staging_root.is_dir():
            return resumed

        cutoff = time.time() - min_age_seconds
        for job_dir in sorted(staging_root.iterdir()):
            if job_id is not None and job_dir.name != job_id:
                continue
            if min_age_seconds and not _older_than(job_dir, cutoff):
                continue
            if is_resolved(job_dir):
                continue
            staged_pdf = job_dir / "document.pdf"
            if not job_dir.is_dir() or not staged_pdf.is_file():
                continue

            try:
                with self.job_lock(job_dir.name, blocking=False):
                    ctx = self._resume_one(job_dir, staged_pdf)
            except LockContended:
                logger.debug(
                    "resume_staged: job %s is already being handled elsewhere; skipping this pass",
                    job_dir.name,
                )
                continue
            if ctx is not None:
                resumed.append(ctx)
        return resumed

    def _staged_companion(self, job_dir: Path) -> Path | None:
        """The companion staged beside this job's PDF, if any.

        Current claims always write it as STAGED_COMPANION. A directory
        staged by an older release holds it under the sender's own
        filename instead, so that is still looked for — but never one of
        the names this pipeline writes itself, and in a fixed order rather
        than whatever order the filesystem lists entries in.
        """
        fixed = job_dir / STAGED_COMPANION
        if fixed.is_file() and not fixed.is_symlink():
            return fixed
        suffix = self.config.source.metadata_suffix.lower()
        legacy = sorted(
            p
            for p in job_dir.iterdir()
            if p.name.lower().endswith(suffix)
            and p.name not in _RESERVED_STAGING_NAMES
            and p.is_file()
            and not p.is_symlink()
        )
        return legacy[0] if legacy else None

    def _staged_metadata(self, job_dir: Path, manifest: dict, pdf_bytes: bytes) -> dict:
        """The allowlisted metadata claim settled on for this job. A
        directory staged by an older release has none recorded, so it is
        derived again from the PDF and the staged companion."""
        if isinstance(manifest.get("metadata"), dict):
            return manifest["metadata"]
        raw_metadata: dict = self._pdf_metadata(pdf_bytes)
        companion = self._staged_companion(job_dir)
        if companion is not None:
            content, _ = _read_bounded_with_stat(companion, self.config.limits.max_metadata_bytes)
            if content is None:
                logger.warning(
                    "companion %s exceeds limits.max_metadata_bytes — ignoring it",
                    companion.name,
                )
            else:
                try:
                    raw_metadata = {**raw_metadata, **self.metadata_parser.parse(content)}
                except Exception as exc:
                    logger.warning("metadata parse failed resuming %s: %s", job_dir.name, exc)
        return allowlist(raw_metadata, self.config.source.metadata_fields)

    def _resume_one(self, job_dir: Path, staged_pdf: Path) -> JobContext | None:
        logger.debug("resume_staged: found staged job %s", job_dir.name)
        pdf_bytes = staged_pdf.read_bytes()
        recovered_id = content_job_id(pdf_bytes)
        if recovered_id != job_dir.name:
            logger.warning(
                "staged job %s content hash is %s — leaving in place for inspection",
                job_dir.name,
                recovered_id,
            )
            return None

        manifest_path = job_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
        if "emit_started" in manifest.get("steps", []) and "emitted" not in manifest.get("steps", []):
            # Once per process, not on every periodic sweep.
            log = logger.debug if recovered_id in self._warned_uncertain else logger.warning
            self._warned_uncertain.add(recovered_id)
            log("job %s needs explicit delivery retry; leaving staged", recovered_id)
            return None
        if manifest.get("receipt_id"):
            self.operations.receipt(
                manifest["receipt_id"],
                recovered_id,
                manifest.get("received_at", datetime.now(UTC).isoformat()),
                manifest.get("filename", "document.pdf"),
                manifest.get("source_name", self.config.source.name),
            )
        ctx = JobContext(
            job_id=recovered_id,
            received_at=datetime.fromisoformat(manifest["received_at"]) if manifest.get("received_at") else datetime.fromtimestamp(staged_pdf.stat().st_mtime, UTC),
            source_name=manifest.get("source_name", self.config.source.name),
            staging_dir=job_dir,
            pdf_path=staged_pdf,
            pdf_sha256=hashlib.sha256(pdf_bytes).hexdigest(),
            metadata=self._staged_metadata(job_dir, manifest, pdf_bytes),
        )
        if not manifest.get("assessment"):
            # No extraction done yet — this is either a genuinely fresh
            # claim (the watcher only claims now; a sweep does the rest)
            # or a crash before extraction finished. Either way it's the
            # same "claimed, unprocessed" state, so it gets the same
            # duplicate check and process/commit dispatch as run_job().
            return self._finish_staged(ctx)

        assessment = manifest["assessment"]
        raw_text = assessment["text"]
        if raw_text is not None:
            ctx.text = DocumentText(
                **{
                    **raw_text,
                    "lines": [TextLine(**line) for line in raw_text["lines"]],
                }
            )
        ctx.hits = [DLPHit(**{**hit, "severity": Severity(hit["severity"])}) for hit in assessment["hits"]]
        ctx.disposition, ctx.reason = assessment["disposition"], assessment["reason"]
        ctx.metadata, ctx.audit_fields = assessment["metadata"], assessment["audit_fields"]
        if ctx.disposition == "failed":
            self.commit_failed(ctx)
        else:
            self.commit(ctx)
        return ctx
