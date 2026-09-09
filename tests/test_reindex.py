"""§12: rebuilding the index after losing it. The common case (content
survives) never re-runs OCR; only a job whose content was ALSO lost falls
back to re-extracting from the archived PDF. Already-indexed jobs are
left alone — reindex only fills gaps, never overwrites.
"""

import shutil
from pathlib import Path

import pymupdf
import pytest

from dlpduck.config import Config
from dlpduck.pipeline import Pipeline
from dlpduck.reindex import Reindexer, indexed_job_ids
from dlpduck.reprocess import latest_index_rows
from dlpduck.search import search

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


@pytest.fixture
def hmac_env(monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")


def _config(tmp_path: Path) -> Config:
    src = tmp_path / "drops"
    src.mkdir(exist_ok=True)
    return Config.model_validate(
        {
            "source": {"name": "test", "path": str(src), "metadata_format": "none"},
            "destination": {
                "archive": str(tmp_path / "archive"),
                "quarantine": str(tmp_path / "quarantine"),
                "work_dir": str(tmp_path / "work"),
            },
            "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
        }
    )


def _pdf(path: Path, lines: list[str]) -> Path:
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    y = 40
    for line in lines:
        page.insert_text((40, y), line)
        y += 20
    doc.save(path)
    return path


class TestDiscoverPdfs:
    def test_finds_pdfs_in_both_archive_and_quarantine(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        clean_ctx = pipeline.run_job(_pdf(tmp_path / "clean.pdf", ["ordinary memo"]), None, staging)
        sensitive_ctx = pipeline.run_job(
            _pdf(tmp_path / "card.pdf", ["Card 4111 1111 1111 1111"]), None, staging
        )

        found = Reindexer(pipeline).discover_pdfs()

        assert set(found) == {clean_ctx.job_id, sensitive_ctx.job_id}

    def test_empty_archive_finds_nothing(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        assert Reindexer(pipeline).discover_pdfs() == {}


class TestIndexedJobIds:
    def test_empty_index_returns_empty_set(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        assert indexed_job_ids(pipeline.index_root) == set()

    def test_reflects_committed_jobs(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(_pdf(tmp_path / "clean.pdf", ["content"]), None, staging)

        assert indexed_job_ids(pipeline.index_root) == {ctx.job_id}


class TestReindexFromContent:
    """The fast, common path: content survived, no OCR needed."""

    def test_dry_run_reports_without_writing(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        pipeline.run_job(_pdf(tmp_path / "clean.pdf", ["ordinary content"]), None, staging)

        # Simulate losing the index: delete it, keep content and the PDF.
        shutil.rmtree(pipeline.index_root)

        summary = Reindexer(pipeline).run(commit=False)

        assert summary.count("content") == 1
        assert indexed_job_ids(pipeline.index_root) == set()  # still nothing written

    def test_commit_rebuilds_the_row_correctly(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(
            _pdf(tmp_path / "card.pdf", ["Card 4111 1111 1111 1111 on file"]), None, staging
        )
        original_disposition = ctx.disposition
        assert original_disposition == "quarantine"
        shutil.rmtree(pipeline.index_root)

        summary = Reindexer(pipeline).run(commit=True)

        assert summary.count("content") == 1
        rows = latest_index_rows(pipeline.index_root, job_ids=[ctx.job_id])
        assert len(rows) == 1
        assert rows[0]["disposition"] == "quarantine"
        assert rows[0]["hit_count"] > 0
        assert rows[0]["assessment_seq"] == 1
        assert rows[0]["reason"] == "reindexed:content"

    def test_rebuilt_row_lands_in_the_pdfs_original_partition_not_today(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(_pdf(tmp_path / "clean.pdf", ["content"]), None, staging)

        [original_pdf] = config.destination.archive.glob(f"dt=*/{ctx.job_id}.pdf")
        original_dt = original_pdf.parent.name

        shutil.rmtree(pipeline.index_root)
        Reindexer(pipeline).run(commit=True)

        [rebuilt_file] = pipeline.index_root.glob(f"dt=*/{ctx.job_id}_0001.parquet")
        assert rebuilt_file.parent.name == original_dt

    def test_already_indexed_jobs_are_left_alone(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(_pdf(tmp_path / "clean.pdf", ["content"]), None, staging)
        [original_file] = pipeline.index_root.glob(f"dt=*/{ctx.job_id}_0001.parquet")
        original_bytes = original_file.read_bytes()

        summary = Reindexer(pipeline).run(commit=True)  # index is intact, nothing lost

        assert summary.already_indexed == 1
        assert summary.count("content") == 0
        assert original_file.read_bytes() == original_bytes  # byte-identical, untouched

    def test_content_only_reconstruction_does_not_claim_degraded(self, tmp_path, hmac_env):
        # Documented limitation: degraded is unrecoverable from content
        # alone, so it must default to False rather than silently guess
        # True (which would mass-quarantine everything reindexed).
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(_pdf(tmp_path / "clean.pdf", ["content"]), None, staging)
        shutil.rmtree(pipeline.index_root)

        Reindexer(pipeline).run(commit=True)

        rows = latest_index_rows(pipeline.index_root, job_ids=[ctx.job_id])
        assert rows[0]["degraded"] is False


class TestReindexFromPdf:
    """The slow, disaster-recovery path: content was ALSO lost, so the
    PDF is genuinely re-extracted and re-scanned.
    """

    def test_rebuilds_both_index_and_content_when_content_was_lost(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(
            _pdf(tmp_path / "card.pdf", ["Card 4111 1111 1111 1111 on file"]), None, staging
        )
        shutil.rmtree(pipeline.index_root)
        shutil.rmtree(pipeline.content_root)  # content lost too — the harder case

        summary = Reindexer(pipeline).run(commit=True)

        assert summary.count("pdf") == 1
        assert summary.count("content") == 0
        rows = latest_index_rows(pipeline.index_root, job_ids=[ctx.job_id])
        assert rows[0]["disposition"] == "quarantine"
        assert rows[0]["reason"] == "reindexed:pdf"
        assert list(pipeline.content_root.glob(f"dt=*/{ctx.job_id}.parquet"))  # content rebuilt too

    def test_reextraction_gives_a_trustworthy_degraded_flag(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(_pdf(tmp_path / "clean.pdf", ["ordinary content"]), None, staging)
        shutil.rmtree(pipeline.index_root)
        shutil.rmtree(pipeline.content_root)

        Reindexer(pipeline).run(commit=True)

        rows = latest_index_rows(pipeline.index_root, job_ids=[ctx.job_id])
        assert rows[0]["degraded"] is False  # genuinely re-extracted, native text, not degraded


class TestReindexAudit:
    def test_commit_appends_a_summary_event_without_breaking_the_chain(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        pipeline.run_job(_pdf(tmp_path / "clean.pdf", ["content"]), None, staging)
        shutil.rmtree(pipeline.index_root)

        Reindexer(pipeline).run(commit=True)

        ok, breaks = pipeline.audit.verify()
        assert ok is True
        assert breaks == []
        [log_file] = pipeline.audit.root.glob("dt=*/events.jsonl")
        assert '"event":"index.rebuilt"' in log_file.read_text()

    def test_dry_run_appends_no_audit_event(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        pipeline.run_job(_pdf(tmp_path / "clean.pdf", ["content"]), None, staging)
        shutil.rmtree(pipeline.index_root)

        Reindexer(pipeline).run(commit=False)

        [log_file] = pipeline.audit.root.glob("dt=*/events.jsonl")
        assert "index.rebuilt" not in log_file.read_text()


class TestFullDisasterRecovery:
    def test_losing_the_whole_index_is_fully_recoverable(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"

        clean_ctx = pipeline.run_job(_pdf(tmp_path / "a.pdf", ["memo about the office party"]), None, staging)
        sensitive_ctx = pipeline.run_job(
            _pdf(tmp_path / "b.pdf", ["Card 4111 1111 1111 1111 on file"]), None, staging
        )

        shutil.rmtree(pipeline.index_root)
        summary = Reindexer(pipeline).run(commit=True)

        assert summary.scanned_pdfs == 2
        rows = {r["job_id"]: r for r in latest_index_rows(pipeline.index_root)}
        assert rows[clean_ctx.job_id]["disposition"] == "archive"
        assert rows[sensitive_ctx.job_id]["disposition"] == "quarantine"


class TestReindexDoesNotDeclassify:
    """A rebuilt disposition comes from where the PDF is filed, not from
    re-running the current ruleset. Otherwise a ruleset change silently
    declassifies: a document quarantined under an older ruleset comes back
    marked "archive", with no release_pending and no job.released event,
    while the file itself stays in quarantine forever — walking straight
    past the human gate a de-escalation deliberately requires.
    """

    def _quarantined_then_narrowed(self, tmp_path):
        """Ingest something that quarantines, then lose the index and
        rebuild under a ruleset that no longer matches it."""
        strict = _config(tmp_path)
        ingest = Pipeline(strict)
        ctx = ingest.run_job(
            _pdf(tmp_path / "card.pdf", ["Card 4111 1111 1111 1111 on file"]),
            None,
            strict.destination.work_dir / "_processing",
        )
        assert ctx.disposition == "quarantine"
        shutil.rmtree(ingest.index_root)

        narrowed = _config(tmp_path)
        narrowed.dlp.rules = [{"id": "x.none", "name": "Nothing", "pattern": r"zzzznomatch"}]
        return ctx.job_id, Pipeline(narrowed)

    def test_a_quarantined_document_stays_quarantined(self, tmp_path, hmac_env):
        job_id, pipeline = self._quarantined_then_narrowed(tmp_path)

        Reindexer(pipeline).run(commit=True)

        row = latest_index_rows(pipeline.index_root, job_ids=[job_id])[0]
        assert row["disposition"] == "quarantine"
        assert "quarantine" in row["archive_path"]
        assert Path(row["archive_path"]).is_file()

    def test_the_disagreement_is_reported_rather_than_acted_on(self, tmp_path, hmac_env):
        job_id, pipeline = self._quarantined_then_narrowed(tmp_path)

        summary = Reindexer(pipeline).run(commit=True)

        assert summary.ruleset_disagreements == 1
        row = latest_index_rows(pipeline.index_root, job_ids=[job_id])[0]
        assert "ruleset-differs" in row["reason"]

    def test_no_release_is_implied_by_a_rebuild(self, tmp_path, hmac_env):
        # Only `dlpduck release` may take a document out of quarantine.
        job_id, pipeline = self._quarantined_then_narrowed(tmp_path)
        Reindexer(pipeline).run(commit=True)

        row = latest_index_rows(pipeline.index_root, job_ids=[job_id])[0]
        assert row["release_pending"] is False  # nothing is pending...
        assert row["disposition"] == "quarantine"  # ...because nothing was decided

    def test_an_agreeing_document_is_not_flagged(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        pipeline.run_job(
            _pdf(tmp_path / "clean.pdf", ["an ordinary memo"]),
            None,
            config.destination.work_dir / "_processing",
        )
        shutil.rmtree(pipeline.index_root)

        summary = Reindexer(Pipeline(_config(tmp_path))).run(commit=True)

        assert summary.ruleset_disagreements == 0


class TestReindexFailurePaths:
    """A corrupt or unreadable document must be reported and skipped, not
    abort the whole recovery — the point of reindex is to salvage what
    survived."""

    def test_an_unextractable_pdf_is_reported_and_the_rest_continue(self, tmp_path, hmac_env):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        good = pipeline.run_job(_pdf(tmp_path / "good.pdf", ["fine content"]), None, staging)

        # A file that is not a PDF at all, sitting where an archived one would be.
        partition = next(config.destination.archive.glob("dt=*"))
        (partition / f"{'b' * 32}.pdf").write_bytes(b"this is not a PDF")
        shutil.rmtree(pipeline.index_root)
        shutil.rmtree(pipeline.content_root)  # force the re-extract path

        summary = Reindexer(pipeline).run(commit=True)

        assert summary.count("failed") == 1
        assert any(o.detail for o in summary.outcomes if o.source == "failed")
        # the healthy document was still rebuilt
        assert indexed_job_ids(pipeline.index_root) == {good.job_id}

    def test_a_scan_failure_is_reported_rather_than_raised(self, tmp_path, hmac_env, monkeypatch):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        pipeline.run_job(_pdf(tmp_path / "doc.pdf", ["content"]), None, staging)
        shutil.rmtree(pipeline.index_root)

        def _boom(_text):
            raise RuntimeError("rule engine blew up")

        monkeypatch.setattr(pipeline.engine, "scan", _boom)
        summary = Reindexer(pipeline).run(commit=True)

        assert summary.count("failed") == 1
        assert "rule engine blew up" in summary.outcomes[0].detail

    def test_an_unresolvable_path_is_treated_as_contained(self, tmp_path, hmac_env):
        """Fail closed: if we cannot tell where a document lives, assume
        it is quarantined rather than assuming it is not."""
        pipeline = Pipeline(_config(tmp_path))
        reindexer = Reindexer(pipeline)

        class _Unresolvable:
            def resolve(self):
                raise OSError("path resolution failed")

        assert reindexer._is_in_quarantine(_Unresolvable()) is True


class TestRecoveryDoesNotResurrectPurgedContent:
    """A purge is somebody's right to erasure being exercised. Disaster
    recovery quietly undoing it — re-extracting the PDF and making the
    erased text searchable again, with nothing recording that it came
    back — is about the worst thing this tool could do.
    """

    def _ingested_and_purged(self, tmp_path, text="Patient Jane Doe, ref 88"):
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        ctx = pipeline.run_job(
            _pdf(tmp_path / "doc.pdf", [text]),
            None,
            config.destination.work_dir / "_processing",
        )
        pipeline.purge_content(ctx.job_id, reason="erasure request 41", actor="dpo")
        return pipeline, ctx.job_id

    def test_a_soft_purged_job_stays_unsearchable_after_a_rebuild(self, tmp_path, hmac_env):
        pipeline, job_id = self._ingested_and_purged(tmp_path)
        shutil.rmtree(pipeline.index_root)

        Reindexer(pipeline).run(commit=True)

        assert search(pipeline.content_root, pipeline.index_root, "Jane").results == []
        assert not list(pipeline.content_root.glob("dt=*/*.parquet"))

    def test_the_index_row_is_still_rebuilt(self, tmp_path, hmac_env):
        """A soft purge deliberately leaves the index row alone — it is
        permanent proof the job happened. Withholding content must not
        turn into losing the record of the document entirely."""
        pipeline, job_id = self._ingested_and_purged(tmp_path)
        shutil.rmtree(pipeline.index_root)

        Reindexer(pipeline).run(commit=True)

        rows = latest_index_rows(pipeline.index_root, job_ids=[job_id])
        assert len(rows) == 1
        assert "content-withheld" in rows[0]["reason"]

    def test_the_operator_is_told_rather_than_left_to_notice(self, tmp_path, hmac_env):
        pipeline, job_id = self._ingested_and_purged(tmp_path)
        shutil.rmtree(pipeline.index_root)

        summary = Reindexer(pipeline).run(commit=True)

        assert summary.content_withheld == 1
        [outcome] = [o for o in summary.outcomes if o.job_id == job_id]
        assert outcome.content_withheld is True

    def test_a_dry_run_reports_it_too(self, tmp_path, hmac_env):
        pipeline, job_id = self._ingested_and_purged(tmp_path)
        shutil.rmtree(pipeline.index_root)

        summary = Reindexer(pipeline).run(commit=False)

        assert summary.content_withheld == 1

    def test_an_interrupted_purge_is_treated_as_a_purge(self, tmp_path, hmac_env):
        """purge.started with no content.purged means the deletion may
        have happened. "Not sure" must not resolve to "resurrect it"."""
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        ctx = pipeline.run_job(
            _pdf(tmp_path / "doc.pdf", ["Patient Jane Doe, ref 88"]),
            None,
            config.destination.work_dir / "_processing",
        )
        pipeline.audit.append("purge.started", job_id=ctx.job_id, reason="interrupted")
        for p in pipeline.content_root.glob("dt=*/*.parquet"):
            p.unlink()
        shutil.rmtree(pipeline.index_root)

        Reindexer(pipeline).run(commit=True)

        assert not list(pipeline.content_root.glob("dt=*/*.parquet"))

    def test_content_lost_to_the_disaster_is_still_restored(self, tmp_path, hmac_env):
        """The fix must not stop recovery working for its actual purpose:
        a job whose content was lost with the index, not erased on
        purpose, still gets re-extracted."""
        config = _config(tmp_path)
        pipeline = Pipeline(config)
        ctx = pipeline.run_job(
            _pdf(tmp_path / "doc.pdf", ["An ordinary memo about lunch"]),
            None,
            config.destination.work_dir / "_processing",
        )
        shutil.rmtree(pipeline.index_root)
        shutil.rmtree(pipeline.content_root)  # the disaster took both

        summary = Reindexer(pipeline).run(commit=True)

        assert summary.content_withheld == 0
        assert list(pipeline.content_root.glob("dt=*/*.parquet"))
        assert search(pipeline.content_root, pipeline.index_root, "lunch").results
        assert latest_index_rows(pipeline.index_root, job_ids=[ctx.job_id])
