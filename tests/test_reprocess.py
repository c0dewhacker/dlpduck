"""Reprocessing appends a new assessment without rewriting history,
escalation is automatic, de-escalation is flagged for human release, and
a document whose original extraction was degraded stays quarantined
regardless of what the new ruleset finds — reprocessing "rules" mode
never re-examines extraction quality, so it must not be able to launder a
degraded document into a clean one.
"""

from datetime import UTC
from pathlib import Path

import pytest

from dlpduck.config import Config
from dlpduck.content import purge_content
from dlpduck.pipeline import Pipeline, content_job_id
from dlpduck.reprocess import Reprocessor, latest_index_rows
from tests.pdf_factory import write_pdf

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


def _base_config_dict(tmp_path: Path, rules: list[dict]) -> dict:
    src = tmp_path / "drops"
    src.mkdir(exist_ok=True)
    return {
        "source": {
            "name": "test-source",
            "path": str(src),
            "metadata_format": "none",
            "stability_polls": 1,
        },
        "destination": {
            "archive": str(tmp_path / "archive"),
            "quarantine": str(tmp_path / "quarantine"),
            "work_dir": str(tmp_path / "work"),
        },
        "extraction": {"isolate_worker": False, "native_min_chars": 0},
        "dlp": {"rules": rules},
    }


@pytest.fixture
def hmac_env(monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")


def _pdf(path: Path, lines: list[str]) -> Path:
    return write_pdf(path, lines)


class TestLatestIndexRows:
    def test_empty_index_returns_empty(self, tmp_path, hmac_env):
        config = Config.model_validate(
            _base_config_dict(tmp_path, [{"include": str(DEFAULT_RULES_PATH)}])
        )
        rows = latest_index_rows(config.destination.work_dir / "index")
        assert rows == []

    def test_only_one_assessment_returns_that_one(self, tmp_path, hmac_env):
        config = Config.model_validate(
            _base_config_dict(tmp_path, [{"include": str(DEFAULT_RULES_PATH)}])
        )
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["ordinary content"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)

        rows = latest_index_rows(pipeline.index_root)
        assert len(rows) == 1
        assert rows[0]["job_id"] == ctx.job_id
        assert rows[0]["assessment_seq"] == 1


class TestPreview:
    def test_preview_writes_nothing(self, tmp_path, hmac_env):
        rules = [{"include": str(DEFAULT_RULES_PATH)}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["ordinary memo, nothing sensitive"])
        staging = config.destination.work_dir / "_processing"
        pipeline.run_job(pdf, None, staging)

        before = list(pipeline.index_root.glob("dt=*/*.parquet"))
        Reprocessor(pipeline).preview()
        after = list(pipeline.index_root.glob("dt=*/*.parquet"))

        assert before == after

    def test_unchanged_ruleset_reports_everything_unchanged(self, tmp_path, hmac_env):
        rules = [{"include": str(DEFAULT_RULES_PATH)}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["ordinary memo, nothing sensitive"])
        staging = config.destination.work_dir / "_processing"
        pipeline.run_job(pdf, None, staging)

        # Same rules, fresh Pipeline instance — must recompute the exact
        # same ruleset_version and find nothing changed.
        summary = Reprocessor(Pipeline(config)).preview()

        assert summary.scope_size == 1
        assert summary.unchanged == 1
        assert summary.count("escalate") == 0


class TestEscalation:
    """A new rule now matches something in an already-clean document —
    must quarantine automatically on commit, and move the PDF.
    """

    def _configs(self, tmp_path):
        narrow = Config.model_validate(
            _base_config_dict(
                tmp_path,
                [{"id": "never_matches", "name": "x", "pattern": "ZZZ_NEVER_MATCHES_ZZZ"}],
            )
        )
        wide = Config.model_validate(
            _base_config_dict(
                tmp_path,
                [
                    {
                        "id": "acct_number",
                        "name": "Account number",
                        "pattern": r"ACCT-\d{6}",
                        "severity": "HIGH",
                        "action": "quarantine",
                    }
                ],
            )
        )
        return narrow, wide

    def test_preview_reports_the_escalation(self, tmp_path, hmac_env):
        narrow, wide = self._configs(tmp_path)
        pipeline = Pipeline(narrow)
        pdf = _pdf(tmp_path / "doc.pdf", ["Reference ACCT-482910 attached"])
        staging = narrow.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)
        assert ctx.disposition == "archive"

        summary = Reprocessor(Pipeline(wide)).preview()

        assert summary.count("escalate") == 1
        outcome = summary.outcomes[0]
        assert outcome.old_disposition == "archive"
        assert outcome.new_disposition == "quarantine"

    def test_commit_writes_a_new_assessment_and_moves_the_pdf(self, tmp_path, hmac_env):
        narrow, wide = self._configs(tmp_path)
        pipeline = Pipeline(narrow)
        pdf = _pdf(tmp_path / "doc.pdf", ["Reference ACCT-482910 attached"])
        staging = narrow.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)
        assert list(narrow.destination.archive.glob("dt=*/*.pdf"))

        summary = Reprocessor(Pipeline(wide)).commit()

        assert summary.written == 1
        rows = latest_index_rows(pipeline.index_root)
        assert len(rows) == 1
        assert rows[0]["assessment_seq"] == 2
        assert rows[0]["disposition"] == "quarantine"
        assert rows[0]["hit_count"] == 1

        # PDF physically moved: gone from archive, present in quarantine.
        assert list(narrow.destination.archive.glob("dt=*/*.pdf")) == []
        assert list(narrow.destination.quarantine.glob(f"dt=*/{ctx.job_id}.pdf"))

    def test_original_assessment_row_is_never_rewritten(self, tmp_path, hmac_env):
        narrow, wide = self._configs(tmp_path)
        pipeline = Pipeline(narrow)
        pdf = _pdf(tmp_path / "doc.pdf", ["Reference ACCT-482910 attached"])
        staging = narrow.destination.work_dir / "_processing"
        pipeline.run_job(pdf, None, staging)

        first_files = list(pipeline.index_root.glob("dt=*/*_0001.parquet"))
        assert len(first_files) == 1
        original_bytes = first_files[0].read_bytes()

        Reprocessor(Pipeline(wide)).commit()

        assert first_files[0].read_bytes() == original_bytes  # byte-identical, untouched
        assert list(pipeline.index_root.glob("dt=*/*_0002.parquet"))  # new one appended

    def test_escalation_audit_trail_and_chain_integrity(self, tmp_path, hmac_env):
        narrow, wide = self._configs(tmp_path)
        pipeline = Pipeline(narrow)
        pdf = _pdf(tmp_path / "doc.pdf", ["Reference ACCT-482910 attached"])
        staging = narrow.destination.work_dir / "_processing"
        pipeline.run_job(pdf, None, staging)

        Reprocessor(Pipeline(wide)).commit()

        ok, breaks = pipeline.audit.verify()
        assert ok is True
        assert breaks == []
        [log_file] = pipeline.audit.root.glob("dt=*/events.jsonl")
        events = log_file.read_text()
        assert '"event":"reprocess.started"' in events
        assert '"event":"reprocess.completed"' in events
        assert '"event":"job.reassessed"' in events
        assert '"direction":"escalate"' in events


class TestDeescalation:
    """A rule that used to fire no longer does — the new assessment is
    written (the logical verdict changes) but the PDF stays exactly where
    it is, flagged release_pending, until a human releases it.
    """

    def _configs(self, tmp_path):
        wide = Config.model_validate(
            _base_config_dict(
                tmp_path,
                [
                    {
                        "id": "acct_number",
                        "name": "Account number",
                        "pattern": r"ACCT-\d{6}",
                        "severity": "HIGH",
                        "action": "quarantine",
                    }
                ],
            )
        )
        narrow = Config.model_validate(
            _base_config_dict(
                tmp_path,
                [{"id": "never_matches", "name": "x", "pattern": "ZZZ_NEVER_MATCHES_ZZZ"}],
            )
        )
        return wide, narrow

    def test_deescalation_writes_release_pending_without_moving_the_pdf(self, tmp_path, hmac_env):
        wide, narrow = self._configs(tmp_path)
        pipeline = Pipeline(wide)
        pdf = _pdf(tmp_path / "doc.pdf", ["Reference ACCT-482910 attached"])
        staging = wide.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)
        assert ctx.disposition == "quarantine"
        quarantine_path_before = list(wide.destination.quarantine.glob("dt=*/*.pdf"))
        assert quarantine_path_before

        summary = Reprocessor(Pipeline(narrow)).commit()

        assert summary.count("deescalate") == 1
        rows = latest_index_rows(pipeline.index_root)
        assert rows[0]["disposition"] == "archive"  # the new logical verdict
        assert rows[0]["release_pending"] is True

        # The PDF was NOT moved — still sitting in quarantine.
        assert list(wide.destination.quarantine.glob("dt=*/*.pdf")) == quarantine_path_before
        assert list(wide.destination.archive.glob("dt=*/*.pdf")) == []

    def test_deescalation_audit_event_records_release_pending(self, tmp_path, hmac_env):
        wide, narrow = self._configs(tmp_path)
        pipeline = Pipeline(wide)
        pdf = _pdf(tmp_path / "doc.pdf", ["Reference ACCT-482910 attached"])
        staging = wide.destination.work_dir / "_processing"
        pipeline.run_job(pdf, None, staging)

        Reprocessor(Pipeline(narrow)).commit()

        [log_file] = pipeline.audit.root.glob("dt=*/events.jsonl")
        events = log_file.read_text()
        assert '"direction":"deescalate"' in events
        assert '"release_pending":true' in events


class TestRelease:
    """Carrying out a pending de-escalation: moves the PDF, writes one
    more assessment, and only that — the verdict itself was already
    decided by the reprocess commit that set release_pending.
    """

    def _configs(self, tmp_path):
        wide = Config.model_validate(
            _base_config_dict(
                tmp_path,
                [{"id": "acct", "name": "Account number", "pattern": r"ACCT-\d{6}",
                  "severity": "HIGH", "action": "quarantine"}],
            )
        )
        narrow = Config.model_validate(
            _base_config_dict(
                tmp_path, [{"id": "never_matches", "name": "x", "pattern": "ZZZ_NEVER_ZZZ"}]
            )
        )
        return wide, narrow

    def _quarantine_then_deescalate(self, tmp_path, hmac_env):
        wide, narrow = self._configs(tmp_path)
        pipeline = Pipeline(wide)
        pdf = _pdf(tmp_path / "doc.pdf", ["Reference ACCT-482910 attached"])
        staging = wide.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)
        Reprocessor(Pipeline(narrow)).commit()
        return wide, narrow, pipeline, ctx

    def test_release_moves_the_pdf_and_clears_release_pending(self, tmp_path, hmac_env):
        wide, narrow, pipeline, ctx = self._quarantine_then_deescalate(tmp_path, hmac_env)
        assert list(wide.destination.quarantine.glob(f"dt=*/{ctx.job_id}.pdf"))

        result = Reprocessor(Pipeline(narrow)).release(
            ctx.job_id, reason="reviewed and confirmed clean", actor="alice"
        )

        assert result.released is True
        assert list(wide.destination.quarantine.glob(f"dt=*/{ctx.job_id}.pdf")) == []
        assert list(wide.destination.archive.glob(f"dt=*/{ctx.job_id}.pdf"))

        rows = latest_index_rows(pipeline.index_root)
        assert rows[0]["release_pending"] is False
        assert rows[0]["assessment_seq"] == 3  # 1: ingest, 2: de-escalate, 3: release

    def test_release_is_denied_without_a_pending_deescalation(self, tmp_path, hmac_env):
        rules = [{"include": str(DEFAULT_RULES_PATH)}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["ordinary content"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)  # never quarantined at all

        result = Reprocessor(pipeline).release(ctx.job_id, reason="test", actor="alice")

        assert result.released is False
        assert "no release is pending" in result.reason_denied

    def test_release_of_an_unknown_job_is_denied_not_an_error(self, tmp_path, hmac_env):
        rules = [{"include": str(DEFAULT_RULES_PATH)}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)

        result = Reprocessor(pipeline).release("never-existed", reason="test", actor="alice")

        assert result.released is False
        assert "not found" in result.reason_denied

    def test_release_records_actor_and_reason_in_the_audit_trail(self, tmp_path, hmac_env):
        wide, narrow, pipeline, ctx = self._quarantine_then_deescalate(tmp_path, hmac_env)

        Reprocessor(Pipeline(narrow)).release(
            ctx.job_id, reason="reviewed, false positive", actor="s.iqbal"
        )

        [log_file] = pipeline.audit.root.glob("dt=*/events.jsonl")
        events = log_file.read_text()
        assert '"event":"job.released"' in events
        assert '"reason":"reviewed, false positive"' in events
        assert '"actor":"s.iqbal"' in events

    def test_release_does_not_break_the_audit_chain(self, tmp_path, hmac_env):
        wide, narrow, pipeline, ctx = self._quarantine_then_deescalate(tmp_path, hmac_env)

        Reprocessor(Pipeline(narrow)).release(ctx.job_id, reason="test", actor="alice")

        ok, breaks = pipeline.audit.verify()
        assert ok is True
        assert breaks == []

    def test_released_job_still_reflects_the_original_deescalation_ruleset_version(
        self, tmp_path, hmac_env
    ):
        # Release carries out a decision, it doesn't remake it — the
        # ruleset_version on record should stay the one that actually
        # produced this disposition, not silently update to "now".
        wide, narrow, pipeline, ctx = self._quarantine_then_deescalate(tmp_path, hmac_env)
        before = latest_index_rows(pipeline.index_root)[0]

        Reprocessor(Pipeline(narrow)).release(ctx.job_id, reason="test", actor="alice")

        after = latest_index_rows(pipeline.index_root)[0]
        assert after["ruleset_version"] == before["ruleset_version"]
        assert after["hit_count"] == before["hit_count"]


class TestDegradedStaysFailClosed:
    def test_degraded_document_stays_quarantined_even_with_zero_hits(self, tmp_path, hmac_env):
        # Simulate a degraded ingest by writing an index row with
        # degraded=True and no hits directly — reprocessing must not be
        # able to "clean" it just because the new ruleset finds nothing.
        rules = [{"id": "never_matches", "name": "x", "pattern": "ZZZ_NEVER_MATCHES_ZZZ"}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)

        from datetime import datetime

        from dlpduck.content import write_content_row
        from dlpduck.index import write_index_row
        from dlpduck.types import DocumentText, JobContext, TextLine

        text = DocumentText(page_count=1, degraded=True)
        text.add_line(
            TextLine(line_number=0, page_number=1, line_on_page=0, lines_on_page=1,
                      text="unreadable page, ocr failed", source="ocr", confidence=0.1)
        )
        ctx = JobContext(
            job_id="deadbeefdeadbeefdeadbeefdeadbeef",
            received_at=datetime.now(UTC),
            source_name="test",
            staging_dir=tmp_path,
            pdf_path=tmp_path / "nonexistent.pdf",
            pdf_sha256="x",
            metadata={},
            text=text,
            hits=[],
            disposition="quarantine",
            reason="degraded_extraction",
        )
        write_content_row(pipeline.content_root, ctx)
        write_index_row(
            pipeline.index_root, ctx, archive_path="/nonexistent/path.pdf",
            assessment_seq=1, ruleset_version="prior-version", supersedes_seq=None,
        )

        summary = Reprocessor(pipeline).commit()

        # Zero hits under the new ruleset, but degraded=True carries
        # forward, so this must NOT be reported as a clean de-escalation.
        assert summary.count("deescalate") == 0
        rows = latest_index_rows(pipeline.index_root)
        assert rows[0]["disposition"] == "quarantine"
        assert rows[0]["hit_count"] == 0


class TestContentUnavailable:
    def test_purged_job_is_reported_but_not_written(self, tmp_path, hmac_env):
        rules = [{"include": str(DEFAULT_RULES_PATH)}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "doc.pdf", ["ordinary content"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)

        purge_content(pipeline.content_root, ctx.job_id)

        summary = Reprocessor(Pipeline(config)).commit()

        assert summary.count("content_unavailable") == 1
        assert summary.written == 0
        rows = latest_index_rows(pipeline.index_root)
        assert rows[0]["assessment_seq"] == 1  # nothing new written for this job

    def test_content_unavailable_does_not_raise(self, tmp_path, hmac_env):
        rules = [{"include": str(DEFAULT_RULES_PATH)}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "doc.pdf", ["ordinary content"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)
        purge_content(pipeline.content_root, ctx.job_id)

        Reprocessor(Pipeline(config)).preview()  # must not raise


class TestScopeFiltering:
    def test_job_ids_filter_limits_scope(self, tmp_path, hmac_env):
        rules = [{"include": str(DEFAULT_RULES_PATH)}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ctx1 = pipeline.run_job(_pdf(tmp_path / "a.pdf", ["doc a content"]), None, staging)
        pipeline.run_job(_pdf(tmp_path / "b.pdf", ["doc b content"]), None, staging)

        summary = Reprocessor(Pipeline(config)).preview(job_ids=[ctx1.job_id])

        assert summary.scope_size == 1
        assert summary.outcomes[0].job_id == ctx1.job_id

    def test_date_range_limits_scope(self, tmp_path, hmac_env):
        rules = [{"include": str(DEFAULT_RULES_PATH)}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        pipeline.run_job(_pdf(tmp_path / "a.pdf", ["doc a content"]), None, staging)

        from datetime import date, timedelta

        tomorrow = date.today() + timedelta(days=1)
        summary = Reprocessor(Pipeline(config)).preview(start=tomorrow)

        assert summary.scope_size == 0  # today's job is outside a tomorrow-onward range


class TestReassessmentPartitionConsistency:
    def test_new_assessment_lands_in_the_same_dt_partition_as_the_original(
        self, tmp_path, hmac_env
    ):
        # DuckDB defaults to converting TIMESTAMPTZ to the LOCAL system
        # timezone on read. received_at is written as raw UTC, so reading
        # it back local-shifted and then taking .date() can land on a
        # different calendar day near local midnight — putting a
        # reassessment in the wrong dt= partition. This doesn't depend on
        # actually being near midnight: it directly checks that the
        # reassessment's file lands under the SAME dt= directory the
        # original assessment did, which only holds if received_at
        # round-trips through DuckDB as UTC.
        narrow = Config.model_validate(
            _base_config_dict(
                tmp_path, [{"id": "never_matches", "name": "x", "pattern": "ZZZ_NEVER_ZZZ"}]
            )
        )
        pipeline = Pipeline(narrow)
        pdf = _pdf(tmp_path / "doc.pdf", ["Reference ACCT-482910 attached"])
        staging = narrow.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)

        [original_file] = pipeline.index_root.glob(f"dt=*/{ctx.job_id}_0001.parquet")
        original_dt = original_file.parent.name  # e.g. "dt=2026-09-03"

        wide = Config.model_validate(
            _base_config_dict(
                tmp_path,
                [{"id": "acct", "name": "Account number", "pattern": r"ACCT-\d{6}",
                  "severity": "HIGH", "action": "quarantine"}],
            )
        )
        Reprocessor(Pipeline(wide)).commit()

        [new_file] = pipeline.index_root.glob(f"dt=*/{ctx.job_id}_0002.parquet")
        assert new_file.parent.name == original_dt

        # And the escalated PDF must have moved into a quarantine
        # partition with the SAME date, not today's wall-clock date.
        [quarantined_pdf] = narrow.destination.quarantine.glob(f"dt=*/{ctx.job_id}.pdf")
        assert quarantined_pdf.parent.name == original_dt


class TestEscalationWithAMissingPdf:
    def test_escalation_of_a_job_whose_pdf_is_already_gone_still_records_the_verdict(
        self, tmp_path, hmac_env
    ):
        # Content survived (e.g. a hard purge failed partway, or the
        # archive_path is stale) but the PDF file itself is gone. The
        # logical escalation must still be recorded rather than crashing
        # the whole batch over one inconsistent job.
        narrow = Config.model_validate(
            _base_config_dict(
                tmp_path, [{"id": "never_matches", "name": "x", "pattern": "ZZZ_NEVER_ZZZ"}]
            )
        )
        pipeline = Pipeline(narrow)
        pdf = _pdf(tmp_path / "doc.pdf", ["Reference ACCT-482910 attached"])
        staging = narrow.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)

        for p in narrow.destination.archive.glob(f"dt=*/{ctx.job_id}.pdf"):
            p.unlink()

        wide = Config.model_validate(
            _base_config_dict(
                tmp_path,
                [{"id": "acct", "name": "Account number", "pattern": r"ACCT-\d{6}",
                  "severity": "HIGH", "action": "quarantine"}],
            )
        )
        summary = Reprocessor(Pipeline(wide)).commit()

        assert summary.count("escalate") == 1  # recorded, not skipped or crashed
        rows = latest_index_rows(pipeline.index_root)
        assert rows[0]["disposition"] == "quarantine"



class TestRelocationIsSafeToRepeat:
    """The PDF is moved *before* the index row that records where it went.
    A crash in that gap leaves the file already at its destination while
    the index still names the old location — and answering "it's gone"
    writes the stale path into the new assessment, after which the console
    can never serve that document again even though the file is there.
    """

    def _ingest(self, tmp_path, hmac_env, text="An ordinary memo."):
        config = Config.model_validate(
            _base_config_dict(
                tmp_path, [{"id": "never", "name": "x", "pattern": "ZZZ_NEVER_ZZZ"}]
            )
        )
        pipeline = Pipeline(config)
        ctx = pipeline.run_job(
            _pdf(tmp_path / "doc.pdf", [text]), None,
            config.destination.work_dir / "_processing",
        )
        return config, pipeline, ctx

    def test_escalating_a_pdf_already_in_quarantine_adopts_it(self, tmp_path, hmac_env):
        config, pipeline, ctx = self._ingest(tmp_path, hmac_env)
        row = latest_index_rows(pipeline.index_root)[0]
        reprocessor = Reprocessor(pipeline)

        # The interrupted attempt: the move happened, nothing recorded it.
        moved = reprocessor._move_to_quarantine(
            ctx.job_id, row["received_at"], row["archive_path"]
        )
        # The operator re-runs it.
        again = reprocessor._move_to_quarantine(
            ctx.job_id, row["received_at"], row["archive_path"]
        )

        assert again == moved
        assert Path(again).is_file(), "the index would point at a path with no file"

    def test_releasing_a_pdf_already_in_the_archive_adopts_it(self, tmp_path, hmac_env):
        """Release is the same move pointed the other way, and had the
        same bug — worth its own test so the two cannot drift again."""
        config, pipeline, ctx = self._ingest(tmp_path, hmac_env)
        row = latest_index_rows(pipeline.index_root)[0]
        reprocessor = Reprocessor(pipeline)
        quarantined = reprocessor._move_to_quarantine(
            ctx.job_id, row["received_at"], row["archive_path"]
        )

        moved = reprocessor._relocate_pdf(
            ctx.job_id, row["received_at"], quarantined, config.destination.archive
        )
        again = reprocessor._relocate_pdf(
            ctx.job_id, row["received_at"], quarantined, config.destination.archive
        )

        assert again == moved
        assert Path(again).is_file()

    def test_a_genuinely_missing_pdf_is_still_reported_as_missing(self, tmp_path, hmac_env):
        """The fix must not turn "hard-purged" into "found it" — nothing
        is at either end in that case."""
        config, pipeline, ctx = self._ingest(tmp_path, hmac_env)
        row = latest_index_rows(pipeline.index_root)[0]
        Path(row["archive_path"]).unlink()

        where = Reprocessor(pipeline)._move_to_quarantine(
            ctx.job_id, row["received_at"], row["archive_path"]
        )

        assert where == row["archive_path"]
        assert not Path(where).is_file()

    def test_the_console_can_still_serve_a_pdf_after_an_interrupted_escalation(
        self, tmp_path, hmac_env
    ):
        """The consequence that actually matters, end to end: a full
        commit after the interrupted move records where the file really
        is, so the document stays reachable."""
        config, pipeline, ctx = self._ingest(tmp_path, hmac_env, "Reference ACCT-482910 attached")
        row = latest_index_rows(pipeline.index_root)[0]
        Reprocessor(pipeline)._move_to_quarantine(
            ctx.job_id, row["received_at"], row["archive_path"]
        )

        wide = Config.model_validate(
            _base_config_dict(
                tmp_path,
                [{"id": "acct", "name": "Account number", "pattern": r"ACCT-\d{6}",
                  "severity": "HIGH", "action": "quarantine"}],
            )
        )
        Reprocessor(Pipeline(wide)).commit()

        [after] = latest_index_rows(pipeline.index_root)
        assert after["disposition"] == "quarantine"
        assert Path(after["archive_path"]).is_file(), after["archive_path"]


class TestExtractMode:
    """mode="extract" genuinely re-runs OCR from the archived PDF —
    slower than "rules", but it can recover a job whose content was lost,
    and it re-derives page_count/degraded for real instead of carrying
    stale values forward.
    """

    def test_preview_extract_mode_writes_nothing(self, tmp_path, hmac_env):
        rules = [{"include": str(DEFAULT_RULES_PATH)}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["ordinary content"])
        staging = config.destination.work_dir / "_processing"
        pipeline.run_job(pdf, None, staging)

        before = list(pipeline.index_root.glob("dt=*/*.parquet"))
        Reprocessor(Pipeline(config)).preview(mode="extract")
        after = list(pipeline.index_root.glob("dt=*/*.parquet"))

        assert before == after

    def test_extract_mode_recovers_a_job_whose_content_was_purged(self, tmp_path, hmac_env):
        # This is exactly what "rules" mode cannot do — content_unavailable
        # there means content_unavailable, full stop. Extract mode has a
        # second source of truth: the PDF itself.
        rules = [{"include": str(DEFAULT_RULES_PATH)}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "card.pdf", ["Card 4111 1111 1111 1111 on file"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)

        purge_content(pipeline.content_root, ctx.job_id)

        rules_summary = Reprocessor(Pipeline(config)).preview(mode="rules")
        assert rules_summary.count("content_unavailable") == 1

        extract_summary = Reprocessor(Pipeline(config)).preview(mode="extract")
        assert extract_summary.count("content_unavailable") == 0
        assert extract_summary.outcomes[0].new_hit_count == 1

    def test_extract_mode_refreshes_the_content_store_on_commit(self, tmp_path, hmac_env):
        rules = [{"include": str(DEFAULT_RULES_PATH)}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "card.pdf", ["Card 4111 1111 1111 1111 on file"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)
        purge_content(pipeline.content_root, ctx.job_id)
        assert not list(pipeline.content_root.glob(f"dt=*/{ctx.job_id}.parquet"))

        summary = Reprocessor(Pipeline(config)).commit(mode="extract")

        assert list(pipeline.content_root.glob(f"dt=*/{ctx.job_id}.parquet"))  # rebuilt
        # The verdict didn't change (same ruleset, same hits) — so this
        # must NOT count as a written assessment, only a content refresh.
        assert summary.written == 0
        assert summary.content_refreshed == 1
        assert summary.count("unchanged") == 1
        rows = latest_index_rows(pipeline.index_root)
        assert rows[0]["assessment_seq"] == 1  # no new assessment row was written

    def test_extract_mode_still_reports_content_unavailable_when_the_pdf_is_also_gone(
        self, tmp_path, hmac_env
    ):
        rules = [{"include": str(DEFAULT_RULES_PATH)}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["ordinary content"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)
        purge_content(pipeline.content_root, ctx.job_id)
        for p in config.destination.archive.glob(f"dt=*/{ctx.job_id}.pdf"):
            p.unlink()

        summary = Reprocessor(Pipeline(config)).preview(mode="extract")

        assert summary.count("content_unavailable") == 1

    def test_extract_mode_rederives_page_count_for_real(self, tmp_path, hmac_env):
        rules = [{"include": str(DEFAULT_RULES_PATH)}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["page one content"])
        staging = config.destination.work_dir / "_processing"
        pipeline.run_job(pdf, None, staging)

        # Force a change so a new assessment actually gets written: widen
        # the ruleset between the original ingest and the extract-mode run.
        wide = Config.model_validate(
            _base_config_dict(
                tmp_path,
                [{"id": "always", "name": "x", "pattern": r"content"}],
            )
        )
        summary = Reprocessor(Pipeline(wide)).commit(mode="extract")

        assert summary.written == 1
        rows = latest_index_rows(pipeline.index_root)
        assert rows[0]["page_count"] == 1
        assert rows[0]["reason"].endswith(":extract")

    def test_extract_mode_can_clear_a_stale_degraded_flag(self, tmp_path, hmac_env):
        # Simulates recovering a job that was originally quarantined for
        # degraded extraction (e.g. a transient OCR failure) — "rules"
        # mode could never un-quarantine this (it can't see extraction
        # quality at all), but a genuine re-extraction can show the page
        # actually reads fine now.
        from datetime import datetime

        rules = [{"id": "never_matches", "name": "x", "pattern": "ZZZ_NEVER_ZZZ"}]
        config = Config.model_validate(_base_config_dict(tmp_path, rules))
        pipeline = Pipeline(config)

        pdf_path = _pdf(tmp_path / "recovered.pdf", ["perfectly readable native text"])
        pdf_bytes = pdf_path.read_bytes()
        job_id = content_job_id(pdf_bytes)
        dest = config.destination.quarantine / "dt=2026-01-01"
        dest.mkdir(parents=True)
        archived_pdf = dest / f"{job_id}.pdf"
        archived_pdf.write_bytes(pdf_bytes)

        from dlpduck.content import write_content_row
        from dlpduck.index import write_index_row
        from dlpduck.types import DocumentText, JobContext, TextLine

        text = DocumentText(page_count=1, degraded=True)  # marked degraded at original ingest
        text.add_line(
            TextLine(line_number=0, page_number=1, line_on_page=0, lines_on_page=1,
                      text="stale placeholder text", source="ocr", confidence=0.2)
        )
        ctx = JobContext(
            job_id=job_id, received_at=datetime(2026, 1, 1, tzinfo=UTC),
            source_name="test", staging_dir=tmp_path, pdf_path=archived_pdf,
            pdf_sha256="x", metadata={}, text=text, hits=[],
            disposition="quarantine", reason="degraded_extraction",
        )
        write_content_row(pipeline.content_root, ctx)
        write_index_row(
            pipeline.index_root, ctx, archive_path=str(archived_pdf),
            assessment_seq=1, ruleset_version="prior-version", supersedes_seq=None,
        )

        summary = Reprocessor(pipeline).commit(mode="extract")

        assert summary.count("deescalate") == 1
        rows = latest_index_rows(pipeline.index_root)
        assert rows[0]["degraded"] is False
        assert rows[0]["disposition"] == "archive"
        assert rows[0]["release_pending"] is True  # still needs a human release, same as any de-escalation


class TestAssessmentHistoryIsNotClobbered:
    """The assessment history is append-only, but the sequence
    number is chosen by reading the current highest and adding one. Two
    writers racing — the console and the CLI, or two operators clicking
    commit — both pick the same number, and a plain write silently
    destroyed one of them while the audit trail recorded both.
    """

    def test_a_second_writer_of_the_same_sequence_is_refused(self, tmp_path, hmac_env):
        from dlpduck.index import AssessmentExists, write_row

        config = Config.model_validate(
            _base_config_dict(tmp_path, [{"include": str(DEFAULT_RULES_PATH)}])
        )
        pipeline = Pipeline(config)
        ctx = pipeline.run_job(
            _pdf(tmp_path / "doc.pdf", ["ordinary content"]),
            None,
            config.destination.work_dir / "_processing",
        )
        row = latest_index_rows(pipeline.index_root, job_ids=[ctx.job_id])[0]

        write_row(
            pipeline.index_root, dict(row), dt=row["received_at"].date(),
            job_id=ctx.job_id, assessment_seq=2, exclusive=True,
        )
        with pytest.raises(AssessmentExists):
            write_row(
                pipeline.index_root, dict(row), dt=row["received_at"].date(),
                job_id=ctx.job_id, assessment_seq=2, exclusive=True,
            )

    def test_the_first_writers_assessment_survives_intact(self, tmp_path, hmac_env):
        import pyarrow.parquet as pq

        from dlpduck.index import AssessmentExists, write_row

        config = Config.model_validate(
            _base_config_dict(tmp_path, [{"include": str(DEFAULT_RULES_PATH)}])
        )
        pipeline = Pipeline(config)
        ctx = pipeline.run_job(
            _pdf(tmp_path / "doc.pdf", ["ordinary content"]),
            None,
            config.destination.work_dir / "_processing",
        )
        row = latest_index_rows(pipeline.index_root, job_ids=[ctx.job_id])[0]

        winner = dict(row)
        winner["reason"] = "the assessment that got there first"
        path = write_row(
            pipeline.index_root, winner, dt=row["received_at"].date(),
            job_id=ctx.job_id, assessment_seq=2, exclusive=True,
        )
        loser = dict(row)
        loser["reason"] = "the one that must not overwrite it"
        with pytest.raises(AssessmentExists):
            write_row(
                pipeline.index_root, loser, dt=row["received_at"].date(),
                job_id=ctx.job_id, assessment_seq=2, exclusive=True,
            )

        stored = pq.read_table(path).to_pylist()[0]
        assert stored["reason"] == "the assessment that got there first"

    def test_ingest_may_still_rewrite_its_own_row_after_a_crash(self, tmp_path, hmac_env):
        """Crash recovery re-runs commit for a job whose row may already
        exist. job_id is content-derived and the sequence is always 1, so
        that rewrite is a no-op by design and must stay permitted."""
        config = Config.model_validate(
            _base_config_dict(tmp_path, [{"include": str(DEFAULT_RULES_PATH)}])
        )
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        pdf = _pdf(tmp_path / "doc.pdf", ["ordinary content"])
        ctx = pipeline.run_job(pdf, None, staging)

        # Re-stage the same document and resume, as the startup sweep does.
        job_dir = staging / ctx.job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        archived = next(config.destination.archive.glob("dt=*/*.pdf"))
        (job_dir / "document.pdf").write_bytes(archived.read_bytes())

        resumed = pipeline.resume_staged(staging)  # must not raise

        assert len(resumed) == 1
