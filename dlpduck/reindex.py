"""Rebuild the metadata index after losing it — from the content store
where that survives, and from the archived PDFs themselves (a real
re-extraction, via the same LineExtractor the ingest path uses) where
content was lost too. See the design doc §12.

Content survives independently of the index (§8.1's split), so the common
recovery case never re-runs OCR — only a job whose content was ALSO lost
falls back to re-extracting. Rebuilt rows start a fresh assessment history
at seq=1: the index being rebuilt is precisely what recorded any prior
reassessments, so that history is not recoverable from content or the PDF
alone — reindexing restores current state, not history. The audit trail
is untouched; reindexing appends one summary event, never rewrites one.

A rebuilt row's disposition comes from WHERE the PDF is filed, not from
re-running the current ruleset over it. The archive/quarantine split is
itself a surviving record of a decision that was made and audited; a
rebuild restores that record rather than re-litigating it. Re-deriving it
instead would let a ruleset change silently declassify a quarantined
document — marking it archived, with no release_pending and no
job.released event, while the file sat in quarantine forever. Where the
current ruleset disagrees with where a document is filed, that is counted
and reported so an operator can run `dlpduck reprocess`, which is the
explicit, audited, human-gated way to change a verdict.

One disclosed limitation: a job rebuilt from content alone cannot recover
whether its ORIGINAL extraction was degraded — that fact lived only in the
index row now being reconstructed. Such rows are marked
`reason="reindexed:content"` rather than silently assumed clean, so an
operator can find and review them; a job rebuilt from the PDF re-extracts
for real and its degraded flag is trustworthy again.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal

import duckdb

from dlpduck.content import read_document_text, write_content_row
from dlpduck.index import write_index_row
from dlpduck.types import JobContext

Source = Literal["content", "pdf", "failed"]


def indexed_job_ids(index_root: Path) -> set[str]:
    index_root = Path(index_root)
    if not any(index_root.glob("dt=*/*.parquet")):
        return set()
    glob = str(index_root / "dt=*" / "*.parquet")
    con = duckdb.connect()
    try:
        rows = con.execute(
            "SELECT DISTINCT job_id FROM read_parquet(?, hive_partitioning = true, "
            "union_by_name = true)",
            [glob],
        ).fetchall()
    finally:
        con.close()
    return {r[0] for r in rows}


@dataclass
class ReindexOutcome:
    job_id: str
    source: Source
    written: bool
    detail: str | None = None
    # The current ruleset would have judged this document differently from
    # where it is filed. Recorded, never acted on — see _rebuild_one.
    ruleset_disagrees: bool = False
    # This job's content was purged, so the index row was rebuilt but the
    # text was deliberately not written back. See _rebuild_one.
    content_withheld: bool = False


@dataclass
class ReindexSummary:
    scanned_pdfs: int = 0
    already_indexed: int = 0
    outcomes: list[ReindexOutcome] = field(default_factory=list)

    def count(self, source: Source) -> int:
        return sum(1 for o in self.outcomes if o.source == source)

    @property
    def ruleset_disagreements(self) -> int:
        return sum(1 for o in self.outcomes if o.ruleset_disagrees)

    @property
    def content_withheld(self) -> int:
        return sum(1 for o in self.outcomes if o.content_withheld)


class Reindexer:
    def __init__(self, pipeline):
        self.pipeline = pipeline

    def discover_pdfs(self) -> dict[str, Path]:
        """job_id -> archived PDF path, found by scanning the archive and
        quarantine roots directly — this works even with no index at all,
        since the filename alone (`<job_id>.pdf`) carries the identity.
        """
        out: dict[str, Path] = {}
        for root in (
            self.pipeline.config.destination.archive,
            self.pipeline.config.destination.quarantine,
        ):
            for path in Path(root).glob("dt=*/*.pdf"):
                out[path.stem] = path
        return out

    def _is_in_quarantine(self, pdf_path: Path) -> bool:
        try:
            return pdf_path.resolve().is_relative_to(
                self.pipeline.config.destination.quarantine.resolve()
            )
        except (OSError, ValueError):
            return True  # can't tell where it lives — treat it as contained

    def purged_job_ids(self) -> set[str]:
        """Jobs whose content was erased on purpose.

        A soft purge deletes the content row and leaves the PDF, so a
        rebuild that re-extracts from the PDF would put the erased text
        straight back — searchable again, with nothing recording that the
        erasure had been reversed. For a tool whose purge is somebody's
        right-to-erasure being exercised, disaster recovery quietly undoing
        it is about the worst outcome available.

        The audit trail is what makes this knowable: it survives the index
        loss that a rebuild exists to repair, and it is the only surviving
        record of the purge. `purge.started` counts as well as
        `content.purged` — an interrupted purge may have deleted the
        content already, and the safe reading of "we are not sure" is not
        to resurrect it.
        """
        return self.pipeline.audit.job_ids_with_event("purge.started", "content.purged")

    def run(self, commit: bool = False) -> ReindexSummary:
        already = indexed_job_ids(self.pipeline.index_root)
        pdfs = self.discover_pdfs()
        purged = self.purged_job_ids()
        summary = ReindexSummary(scanned_pdfs=len(pdfs), already_indexed=0)

        for job_id, pdf_path in sorted(pdfs.items()):
            if job_id in already:
                summary.already_indexed += 1
                continue

            outcome = self._rebuild_one(
                job_id, pdf_path, commit=commit, was_purged=job_id in purged
            )
            summary.outcomes.append(outcome)

        if commit:
            self.pipeline.audit.append(
                "index.rebuilt",
                scanned_pdfs=summary.scanned_pdfs,
                already_indexed=summary.already_indexed,
                rebuilt_from_content=summary.count("content"),
                rebuilt_from_pdf=summary.count("pdf"),
                failed=summary.count("failed"),
                ruleset_disagreements=summary.ruleset_disagreements,
                content_withheld=summary.content_withheld,
            )
        return summary

    def _rebuild_one(
        self, job_id: str, pdf_path: Path, commit: bool, was_purged: bool = False
    ) -> ReindexOutcome:
        pdf_bytes = pdf_path.read_bytes()

        text = read_document_text(self.pipeline.content_root, job_id)
        source: Source = "content"
        if text is None:
            source = "pdf"
            try:
                text = self.pipeline.extractor.extract(pdf_bytes)
            except Exception as exc:
                return ReindexOutcome(job_id, "failed", written=False, detail=str(exc))

        try:
            hits = self.pipeline.engine.scan(text)
        except Exception as exc:
            return ReindexOutcome(job_id, "failed", written=False, detail=str(exc))

        degraded = text.degraded if source == "pdf" else False  # see module docstring
        # WHERE the PDF sits is a surviving record of the disposition that
        # was decided for it, exactly as its dt= partition is a surviving
        # record of when it arrived. A rebuild restores that record; it
        # does not re-litigate the decision.
        #
        # Re-deriving disposition from the CURRENT ruleset instead would
        # silently declassify: a document quarantined under an older
        # ruleset that no longer matches would come back marked "archive",
        # with release_pending unset and no job.released event — walking
        # straight past the human gate that a de-escalation (§8.4)
        # deliberately requires, while the file itself stayed in
        # quarantine forever. Re-judging a document against a new ruleset
        # is what `dlpduck reprocess` is for: explicit, audited, and
        # human-gated on the way out of quarantine.
        located_disposition = (
            "quarantine" if self._is_in_quarantine(pdf_path) else "archive"
        )
        ruleset_disposition = (
            "quarantine" if degraded or any(h.action == "quarantine" for h in hits) else "archive"
        )
        disposition = located_disposition
        disagrees = ruleset_disposition != located_disposition

        # The dt= partition the PDF is already sitting in is the only
        # surviving record of when it was originally received.
        received_dt = date.fromisoformat(pdf_path.parent.name.removeprefix("dt="))
        received_at = datetime(
            received_dt.year, received_dt.month, received_dt.day, tzinfo=UTC
        )

        if not commit:
            return ReindexOutcome(
                job_id,
                source,
                written=False,
                ruleset_disagrees=disagrees,
                content_withheld=was_purged and source == "pdf",
            )

        ctx = JobContext(
            job_id=job_id,
            received_at=received_at,
            source_name=self.pipeline.config.source.name,
            staging_dir=pdf_path.parent,
            pdf_path=pdf_path,
            pdf_sha256=hashlib.sha256(pdf_bytes).hexdigest(),
            metadata={},
            text=text,
            hits=hits,
            disposition=disposition,
            reason=(
                f"reindexed:{source}"
                + (":ruleset-differs" if disagrees else "")
                + (":content-withheld" if was_purged and source == "pdf" else "")
            ),
        )
        write_index_row(
            self.pipeline.index_root,
            ctx,
            archive_path=str(pdf_path),
            assessment_seq=1,
            ruleset_version=self.pipeline.ruleset_version,
            supersedes_seq=None,
        )
        withheld = False
        if source == "pdf":
            if was_purged:
                # Content was missing because somebody erased it, not
                # because the disaster took it. Writing it back would make
                # the erased text searchable again — a purge silently
                # reversed by routine recovery, with nothing recording that
                # it came back. The index row is still rebuilt: a soft
                # purge never touched it, and it is permanent proof the job
                # happened.
                withheld = True
            else:
                # Content was lost with the index — the re-extraction just
                # performed is the only copy of it now, so persist it back.
                write_content_row(self.pipeline.content_root, ctx)

        return ReindexOutcome(
            job_id, source, written=True, ruleset_disagrees=disagrees, content_withheld=withheld
        )
