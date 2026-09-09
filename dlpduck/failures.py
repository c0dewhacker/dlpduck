"""Operator work queue for refused, unprocessable, and interrupted jobs."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from dlpduck.content import validate_job_id
from dlpduck.durability import copy_durably, write_atomically
from dlpduck.operations import serialized


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
        with tempfile.TemporaryDirectory(dir=self.root, prefix="retry-") as directory:
            source = Path(directory) / "document.pdf"
            copy_durably(pdf, source)
            ctx = self.pipeline.run_job(source, None, self.root / "_processing")
        if ctx.disposition == "failed":
            raise ValueError("The retry failed again; the failure reason has been updated")
        self.pipeline.audit.append(
            "job.retry_completed", job_id=job_id, actor=actor, kind=kind
        )
        shutil.rmtree(folder)
