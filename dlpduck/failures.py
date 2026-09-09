"""Operator work queue for refused, unprocessable, and interrupted jobs."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from dlpduck.content import validate_job_id
from dlpduck.durability import copy_durably, write_atomically
from dlpduck.operations import serialized
from dlpduck.types import DocumentTooLarge, UnsafeSourceFile


class FailureQueue:
    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.root = pipeline.config.destination.work_dir

    def items(self, resolved=False):
        rows = []
        for kind, root in (("failed", self.root / "failed"), ("staged", self.root / "_processing")):
            for folder in root.glob("*"):
                if not folder.is_dir() or folder.is_symlink():
                    continue
                try:
                    validate_job_id(folder.name)
                except ValueError:
                    continue
                done = (folder / "resolution.json").is_file()
                if done != resolved:
                    continue
                path = folder / ("metadata.json" if kind == "failed" else "manifest.json")
                try:
                    info = json.loads(path.read_text())
                except (OSError, ValueError):
                    info = {}
                uncertain = "emit_started" in info.get("steps", []) and "emitted" not in info.get("steps", [])
                rows.append({"job_id": folder.name, "kind": kind, "filename": info.get("filename", info.get("source_name", folder.name[:12])),
                             "reason": info.get("reason") or ("Delivery outcome uncertain" if uncertain else "Interrupted processing"),
                             "received_at": info.get("received_at", ""), "uncertain": uncertain,
                             "resolved": done, "safe_pdf": (folder / "document.pdf").is_file() and not (folder / "document.pdf").is_symlink()})
        return sorted(rows, key=lambda row: (row["received_at"], row["job_id"]), reverse=True)

    def folder(self, kind, job_id):
        validate_job_id(job_id)
        if kind not in ("failed", "staged"):
            raise ValueError("Unknown queue")
        root = self.root / ("failed" if kind == "failed" else "_processing")
        folder = root / job_id
        if folder.is_symlink() or not folder.is_dir():
            raise ValueError("Queue item not found")
        return folder

    @serialized
    def resolve(self, kind, job_id, reason, actor):
        if not reason.strip():
            raise ValueError("A reason is required")
        folder = self.folder(kind, job_id)
        self.pipeline.audit.append(
            "job.failure_resolution_requested",
            job_id=job_id,
            reason=reason,
            actor=actor,
            kind=kind,
        )
        write_atomically(folder / "resolution.json", json.dumps({"reason": reason, "actor": actor}))
        self.pipeline.audit.append(
            "job.failure_resolved", job_id=job_id, reason=reason, actor=actor, kind=kind
        )

    @serialized
    def retry(self, kind, job_id, reason, actor, confirm_delivery=False):
        if not reason.strip():
            raise ValueError("A reason is required")
        folder = self.folder(kind, job_id)
        pdf = folder / "document.pdf"
        if pdf.is_symlink() or not pdf.is_file():
            raise ValueError("This item is not a regular PDF; replace the source before retrying")
        if kind == "staged":
            manifest_path = folder / "manifest.json"
            manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {"steps": []}
            steps = manifest.setdefault("steps", [])
            if "emit_started" in steps and "emitted" not in steps:
                if not confirm_delivery:
                    raise ValueError("Confirm possible duplicate delivery before retrying")
                steps.remove("emit_started")
                write_atomically(manifest_path, json.dumps(manifest))
            self.pipeline.audit.append(
                "job.retry_requested", job_id=job_id, actor=actor, reason=reason, kind=kind
            )
            (folder / "resolution.json").unlink(missing_ok=True)
            self.pipeline.resume_staged(self.root / "_processing", job_id=job_id)
            if folder.exists():
                raise ValueError("Recovery did not complete; review this item's state")
            self.pipeline.audit.append(
                "job.retry_completed", job_id=job_id, actor=actor, kind=kind
            )
            return
        self.pipeline.audit.append(
            "job.retry_requested", job_id=job_id, actor=actor, reason=reason, kind=kind
        )
        metadata_path = folder / "metadata.json"
        original_name = "document.pdf"
        if metadata_path.is_file():
            try:
                original_name = json.loads(metadata_path.read_text()).get("source_name", original_name)
            except ValueError:
                pass
        with tempfile.TemporaryDirectory(dir=self.root, prefix="retry-") as directory:
            source = Path(directory) / original_name
            original_stat = pdf.stat()
            copy_durably(pdf, source)
            # reject_at_claim() derives its job id from name/size/mtime (a
            # claim-time refusal is exactly a refusal to read content), on
            # the documented promise that a file rejected twice lands in
            # one place. Its "name" is the name the file had when it was
            # first claimed (metadata.json's source_name) — this folder's
            # own document.pdf is renamed on the way in — and
            # copy_durably() gives the staged copy a fresh mtime. Either
            # one drifting would silently break that promise: an oversized
            # file retried twice would mint two different ids and orphan a
            # duplicate failed/ folder on every attempt. Restoring both
            # keeps the fingerprint, and so the folder, stable.
            os.utime(source, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            try:
                ctx = self.pipeline.run_job(source, None, self.root / "_processing")
            except (DocumentTooLarge, UnsafeSourceFile):
                # Same refusal as before — reject_at_claim already routed
                # it back to this folder (same fingerprint) with the
                # failure reason refreshed; nothing else to do here.
                raise ValueError("The retry failed again; the failure reason has been updated") from None
        if ctx.disposition == "failed":
            raise ValueError("The retry failed again; the failure reason has been updated")
        self.pipeline.audit.append(
            "job.retry_completed", job_id=job_id, actor=actor, kind=kind
        )
        shutil.rmtree(folder)
