"""Claim -> process -> commit -> release. See the design doc §3 for why
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
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

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
from dlpduck.index import write_index_row
from dlpduck.metadata import MetadataParserFactory, allowlist
from dlpduck.operations import OperationalStore, serialized
from dlpduck.pdf_metadata import extract_pdf_metadata
from dlpduck.plugins.base import PluginError, PluginRunner
from dlpduck.rules import ruleset_version
from dlpduck.types import (
    DLPHit,
    DocumentText,
    DocumentTooLarge,
    EncryptedDocument,
    JobContext,
    RuleBudgetExceeded,
    Severity,
    TextLine,
    UnsafeSourceFile,
)

logger = logging.getLogger("dlpduck.pipeline")


def content_job_id(pdf_bytes: bytes) -> str:
    return hashlib.blake2b(pdf_bytes, digest_size=16).hexdigest()


def _read_bounded(path: Path, limit: int) -> bytes | None:
    """Read at most `limit` bytes, or None if the file is bigger. Used for
    companion metadata, which arrives from the same drop folder as the PDF
    and so gets the same "bounded by what is actually read" treatment."""
    data, _ = _read_bounded_with_stat(path, limit)
    return data


def _read_bounded_with_stat(
    path: Path, limit: int
) -> tuple[bytes | None, os.stat_result]:
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
        self.audit = AuditLog(
            config.destination.work_dir / "audit", integrity=config.audit.integrity
        )
        self.index_root = config.destination.work_dir / "index"
        self.content_root = config.destination.work_dir / "content"
        self.plugins = PluginRunner(config.load_plugins(), self.audit)

    # ── claim ────────────────────────────────────────────────────────

    def claim(self, pdf_path: Path, metadata_path: Path | None, staging_root: Path) -> JobContext:
        """Safely read and claim a source pair into a job-scoped staging
        directory, then build its initial JobContext. Raises
        DocumentTooLarge / IOError before a complete file is accepted if
        limits are exceeded (§3.2).
        """
        # A drop folder is usually writable by something less trusted than
        # this daemon (an MFP's account, a share). A symlink there would
        # otherwise be followed straight through to whatever it points at,
        # and that file's contents would end up extracted into the content
        # store — searchable, and downloadable through the console.
        pdf_bytes, opened_pdf = _read_bounded_with_stat(
            pdf_path, self.config.limits.max_bytes
        )
        size = opened_pdf.st_size
        if size > self.config.limits.max_bytes:
            raise DocumentTooLarge(f"{pdf_path} is {size} bytes, over the configured limit")

        # Read with the limit as a hard ceiling rather than trusting the
        # stat above: the file can still grow between the two (a writer
        # that wasn't finished after all), and the limit exists to bound
        # what actually reaches memory.
        if pdf_bytes is None:
            raise DocumentTooLarge(
                f"{pdf_path} exceeds the configured {self.config.limits.max_bytes}-byte limit"
            )
        job_id = content_job_id(pdf_bytes)
        pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()

        staging_dir = staging_root / job_id
        staging_dir.mkdir(parents=True, exist_ok=True)
        staged_pdf = staging_dir / "document.pdf"
        # Publish the exact bytes read through the no-follow descriptor.
        # Moving the path after reading would reopen a TOCTOU window where
        # an attacker swaps that directory entry for a symlink.
        receipt_id = uuid.uuid4().hex
        received_at = datetime.now(UTC)
        manifest = {"receipt_id": receipt_id, "received_at": received_at.isoformat(),
                    "filename": pdf_path.name, "source_name": self.config.source.name,
                    "steps": []}
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

        # The PDF's own Info dictionary first (§2/§6.4) — a companion
        # file, when one exists, wins on any key they both set.
        raw_metadata: dict = extract_pdf_metadata(pdf_bytes)
        if metadata_path is not None and metadata_path.is_symlink():
            shutil.move(
                str(metadata_path),
                str(staging_dir / f"{metadata_path.name}.rejected-symlink"),
            )
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
                write_bytes_durably(staging_dir / metadata_path.name, content)
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
        self.operations.receipt_metadata(receipt_id, metadata)

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

        doc = pymupdf_open_for_page_count(pdf_bytes)
        if doc is not None and len(doc) > self.config.limits.max_pages:
            ctx.disposition = "failed"
            ctx.reason = "page_count_exceeds_limit"
            self.audit.append(
                "job.failed",
                job_id=ctx.job_id,
                reason=ctx.reason,
                page_count=len(doc),
            )
            return

        try:
            ctx.text = self.extractor.extract(pdf_bytes)
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

        try:
            ctx.hits = self.engine.scan(ctx.text)
        except RuleBudgetExceeded as exc:
            ctx.disposition = "failed"
            ctx.reason = f"rule_budget_exceeded: {exc.rule_id}"
            self.audit.append(
                "job.failed", job_id=ctx.job_id, reason=ctx.reason, rule_id=exc.rule_id
            )
            return

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

    @serialized
    def commit(self, ctx: JobContext) -> Path:
        """1) copy the PDF, 2) append+fsync the audit event, 3) write the
        index row, 4) release staging. Each step is idempotent to replay
        (§3.1) — job_id is content-derived, so re-running this on the same
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

        already_audited = any(e.get("receipt_id") == manifest.get("receipt_id") and e.get("event") == "job.completed"
                              for e in self.audit.events_for_job(ctx.job_id)) if manifest.get("receipt_id") else False
        if "audit" not in manifest["steps"] and not already_audited:
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
                hits=[
                    {
                        "rule_id": h.rule_id,
                        "severity": h.severity.value,
                        "page_number": h.page_number,
                        "line_number": h.line_number,
                        "masked_text": h.masked_text,
                    }
                    for h in ctx.hits
                ],
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
            self.operations.finish_receipt(manifest["receipt_id"], ctx.disposition)

        shutil.rmtree(ctx.staging_dir, ignore_errors=True)
        return dest_path

    @serialized
    def commit_failed(self, ctx: JobContext) -> Path:
        """Route an unprocessable job to failed/ for operator attention
        rather than losing it or pretending it succeeded (§3.2)."""
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
            self.operations.finish_receipt(manifest["receipt_id"], "failed")
        shutil.rmtree(ctx.staging_dir, ignore_errors=True)
        return dest

    def reject_at_claim(self, pdf_path: Path, reason: str, detail: str) -> Path:
        """Route a file that could not even be claimed to failed/ (§3.2).

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
        )
        return PurgeResult(content_removed=content_removed, document_removed=document_removed)

    @serialized
    def run_job(self, pdf_path: Path, metadata_path: Path | None, staging_root: Path) -> JobContext:
        # A repeat arrival is a distinct receipt but not a distinct document
        # assessment. Detect it before claiming so an earlier job left staged
        # during an uncertain emit cannot be overwritten by the same bytes.
        if not pdf_path.is_symlink():
            try:
                duplicate_bytes, opened_pdf = _read_bounded_with_stat(
                    pdf_path, self.config.limits.max_bytes
                )
            except UnsafeSourceFile:
                duplicate_bytes = None
            if duplicate_bytes is not None:
                duplicate_id = content_job_id(duplicate_bytes)
                from dlpduck.reprocess import latest_index_rows

                existing = latest_index_rows(self.index_root, job_ids=[duplicate_id])
                if existing:
                    receipt_id = uuid.uuid4().hex
                    received_at = datetime.now(UTC)
                    receipt_metadata = extract_pdf_metadata(duplicate_bytes)
                    opened_metadata = None
                    if metadata_path is not None and metadata_path.is_symlink():
                        companion = None
                        self.audit.append(
                            "metadata.rejected",
                            job_id=duplicate_id,
                            receipt_id=receipt_id,
                            companion=metadata_path.name,
                            error="symlink refused",
                        )
                    elif metadata_path is not None and metadata_path.is_file():
                        try:
                            companion, opened_metadata = _read_bounded_with_stat(
                                metadata_path,
                                self.config.limits.max_metadata_bytes,
                            )
                        except UnsafeSourceFile:
                            companion = None
                            self.audit.append(
                                "metadata.rejected",
                                job_id=duplicate_id,
                                receipt_id=receipt_id,
                                companion=metadata_path.name,
                                error="symlink refused",
                            )
                        if companion is not None:
                            try:
                                receipt_metadata = {
                                    **receipt_metadata,
                                    **self.metadata_parser.parse(companion),
                                }
                            except Exception as exc:
                                self.audit.append(
                                    "metadata.rejected",
                                    job_id=duplicate_id,
                                    receipt_id=receipt_id,
                                    companion=metadata_path.name,
                                    error=str(exc),
                                )
                    receipt_metadata = allowlist(
                        receipt_metadata, self.config.source.metadata_fields
                    )
                    self.operations.receipt(
                        receipt_id,
                        duplicate_id,
                        received_at.isoformat(),
                        pdf_path.name,
                        self.config.source.name,
                    )
                    self.operations.receipt_metadata(receipt_id, receipt_metadata)
                    self.operations.finish_receipt(receipt_id, "duplicate")
                    self.audit.append(
                        "job.received_again",
                        job_id=duplicate_id,
                        receipt_id=receipt_id,
                        source_name=pdf_path.name,
                    )
                    _unlink_if_same(pdf_path, opened_pdf)
                    if metadata_path is not None:
                        if opened_metadata is not None:
                            _unlink_if_same(metadata_path, opened_metadata)
                        elif metadata_path.is_symlink():
                            metadata_path.unlink(missing_ok=True)
                    return JobContext(
                        job_id=duplicate_id,
                        received_at=received_at,
                        source_name=self.config.source.name,
                        staging_dir=staging_root / duplicate_id,
                        pdf_path=pdf_path,
                        pdf_sha256=hashlib.sha256(duplicate_bytes).hexdigest(),
                        metadata=receipt_metadata,
                        disposition=existing[0]["disposition"],
                        reason="duplicate_receipt",
                    )
        try:
            ctx = self.claim(pdf_path, metadata_path, staging_root)
        except (DocumentTooLarge, UnsafeSourceFile) as exc:
            # A refusal, not a crash — route it fail-closed rather than
            # letting it escape to a caller whose only option is to log it
            # and try the same file again next poll.
            self.reject_at_claim(pdf_path, type(exc).__name__, str(exc))
            raise
        from dlpduck.reprocess import latest_index_rows

        existing = latest_index_rows(self.index_root, job_ids=[ctx.job_id])
        if existing:
            prior = existing[0]
            ctx.disposition, ctx.reason = prior["disposition"], "duplicate_receipt"
            manifest = self._manifest(ctx)
            self.operations.finish_receipt(manifest["receipt_id"], "duplicate")
            self.audit.append("job.received_again", job_id=ctx.job_id, receipt_id=manifest["receipt_id"])
            shutil.rmtree(ctx.staging_dir)
            return ctx
        self.process(ctx)
        if ctx.disposition == "failed":
            self.commit_failed(ctx)
        else:
            self.commit(ctx)
        return ctx

    # ── crash recovery ───────────────────────────────────────────────

    @serialized
    def resume_staged(self, staging_root: Path, job_id: str | None = None) -> list[JobContext]:
        """Re-claim any job left in `_processing/` by a process that died
        between claim and commit (§3). job_id is content-derived, so
        re-running is idempotent — it produces the same identity and the
        same verdict, not a duplicate.
        """
        resumed: list[JobContext] = []
        if not staging_root.is_dir():
            return resumed

        for job_dir in sorted(staging_root.iterdir()):
            if job_id is not None and job_dir.name != job_id:
                continue
            if (job_dir / "resolution.json").is_file():
                continue
            staged_pdf = job_dir / "document.pdf"
            if not job_dir.is_dir() or not staged_pdf.is_file():
                continue

            pdf_bytes = staged_pdf.read_bytes()
            recovered_id = content_job_id(pdf_bytes)
            if recovered_id != job_dir.name:
                logger.warning(
                    "staged job %s content hash is %s — leaving in place for inspection",
                    job_dir.name,
                    recovered_id,
                )
                continue

            manifest_path = job_dir / "manifest.json"
            manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
            if "emit_started" in manifest.get("steps", []) and "emitted" not in manifest.get("steps", []):
                logger.warning("job %s needs explicit delivery retry; leaving staged", recovered_id)
                continue
            raw_metadata: dict = extract_pdf_metadata(pdf_bytes)
            if manifest.get("receipt_id"):
                self.operations.receipt(
                    manifest["receipt_id"],
                    recovered_id,
                    manifest.get("received_at", datetime.now(UTC).isoformat()),
                    manifest.get("filename", "document.pdf"),
                    manifest.get("source_name", self.config.source.name),
                )
            meta_files = [
                p
                for p in job_dir.iterdir()
                if p.name.endswith(self.config.source.metadata_suffix)
            ]
            if meta_files:
                content = _read_bounded(meta_files[0], self.config.limits.max_metadata_bytes)
                if content is None:
                    logger.warning(
                        "companion %s exceeds limits.max_metadata_bytes — ignoring it",
                        meta_files[0].name,
                    )
                else:
                    try:
                        raw_metadata = {**raw_metadata, **self.metadata_parser.parse(content)}
                    except Exception as exc:
                        logger.warning("metadata parse failed resuming %s: %s", job_id, exc)

            ctx = JobContext(
                job_id=recovered_id,
                received_at=datetime.fromisoformat(manifest["received_at"]) if manifest.get("received_at") else datetime.fromtimestamp(staged_pdf.stat().st_mtime, UTC),
                source_name=self.config.source.name,
                staging_dir=job_dir,
                pdf_path=staged_pdf,
                pdf_sha256=hashlib.sha256(pdf_bytes).hexdigest(),
                metadata=allowlist(raw_metadata, self.config.source.metadata_fields),
            )
            if manifest.get("assessment"):
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
            else:
                self.process(ctx)
            if ctx.disposition == "failed":
                self.commit_failed(ctx)
            else:
                self.commit(ctx)
            resumed.append(ctx)
        return resumed


def pymupdf_open_for_page_count(pdf_bytes: bytes):
    import pymupdf

    try:
        return pymupdf.open(stream=pdf_bytes, filetype="pdf")
    except Exception:
        return None
