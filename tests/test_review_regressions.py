"""Lifecycle regressions from the codebase review, using real stores and PDFs."""
import subprocess
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from dlpduck.config import Config, RetentionConfig
from dlpduck.content import read_document_text
from dlpduck.extract import LineExtractor
from dlpduck.extract_worker import extract_isolated
from dlpduck.failures import FailureQueue
from dlpduck.index import AssessmentExists
from dlpduck.pipeline import Pipeline
from dlpduck.reprocess import Reprocessor, latest_index_rows
from dlpduck.types import DocumentText, TextLine
from tests.pdf_factory import blank_pdf, make_pdf


def document(text):
    result = DocumentText(page_count=1)
    if text:
        result.add_line(TextLine(0, 1, 0, 1, text, "native"))
    return result


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "review-tests-only")
    drops = tmp_path / "drops"
    drops.mkdir()
    config = Config.model_validate({
        "source": {"name": "scanner", "path": drops},
        "extraction": {"isolate_worker": False},
        "destination": {"archive": tmp_path / "archive", "quarantine": tmp_path / "quarantine", "work_dir": tmp_path / "work"},
        "dlp": {"rules": [{"id": "secret", "name": "Secret", "pattern": "SECRET", "action": "quarantine"}]},
    })
    return Pipeline(config)


def ingest(pipeline, text="An ordinary document with enough native text."):
    path = pipeline.config.source.path / "Recognizable name.pdf"
    path.write_bytes(make_pdf([[text]]))
    return pipeline.run_job(path, None, pipeline.config.destination.work_dir / "_processing")


def test_empty_text_never_deescalates_under_identical_policy(pipeline, monkeypatch):
    monkeypatch.setattr(pipeline.extractor, "extract", lambda _: document(""))
    ctx = ingest(pipeline)
    assert ctx.disposition == "quarantine"
    result = Reprocessor(pipeline).preview().outcomes[0]
    assert result.new_disposition == "quarantine"


def test_release_pending_survives_another_rules_change(pipeline):
    ctx = ingest(pipeline, "SECRET sensitive document with a native heading")
    pipeline.engine.rules = []
    pipeline.ruleset_version = "relaxed-1"
    Reprocessor(pipeline).commit()
    pipeline.ruleset_version = "relaxed-2"
    Reprocessor(pipeline).commit()
    row = latest_index_rows(pipeline.index_root)[0]
    assert row["release_pending"]
    assert Reprocessor(pipeline).release(ctx.job_id, "Reviewed", "admin").released


def test_stale_writer_cannot_replace_winning_text(pipeline):
    ingest(pipeline)
    prior = latest_index_rows(pipeline.index_root)[0]
    reprocessor = Reprocessor(pipeline)
    reprocessor._write_assessment(prior, [], "archive", "changed", document("Winner text"))
    with pytest.raises(AssessmentExists):
        reprocessor._write_assessment(prior, [], "archive", "changed", document("Loser text"))
    assert read_document_text(pipeline.content_root, prior["job_id"]).full_text == "Winner text"


def test_interrupted_transition_recovers_exact_assessment(pipeline, monkeypatch):
    ingest(pipeline)
    prior = latest_index_rows(pipeline.index_root)[0]
    reprocessor = Reprocessor(pipeline)
    import dlpduck.reprocess as module
    original = module.write_row
    monkeypatch.setattr(module, "write_row", Mock(side_effect=OSError("disk unavailable")))
    with pytest.raises(OSError):
        reprocessor._write_assessment(prior, [], "archive", "changed", document("Recovered text"))
    monkeypatch.setattr(module, "write_row", original)
    Reprocessor(pipeline)
    assert latest_index_rows(pipeline.index_root)[0]["assessment_seq"] == 2
    assert read_document_text(pipeline.content_root, prior["job_id"]).full_text == "Recovered text"
    assert not list((pipeline.config.destination.work_dir / "transitions").glob("*.json"))
    assert pipeline.audit.verify().ok


def test_reextract_equal_hit_counts_still_records_new_evidence(pipeline, monkeypatch):
    ingest(pipeline, "SECRET first text of the original document")
    monkeypatch.setattr(pipeline.extractor, "extract", lambda _: document("Different offset SECRET and new text"))
    summary = Reprocessor(pipeline).commit(mode="extract")
    assert summary.written == 1
    row = latest_index_rows(pipeline.index_root)[0]
    assert row["hits"][0]["start"] == len("Different offset ")


def test_duplicate_receipt_preserves_original_assessment(pipeline):
    ctx = ingest(pipeline)
    row = latest_index_rows(pipeline.index_root)[0]
    original = Path(row["archive_path"]).read_bytes()
    source = pipeline.config.source.path / "Second arrival.pdf"
    source.write_bytes(original)
    pipeline.run_job(source, None, pipeline.config.destination.work_dir / "_processing")
    assert len(list(pipeline.index_root.glob("dt=*/*.parquet"))) == 1
    assert latest_index_rows(pipeline.index_root)[0] == row
    receipts = pipeline.operations.receipts(ctx.job_id)
    assert len(receipts) == 2
    assert receipts[0]["filename"] == "Second arrival.pdf"
    assert receipts[0]["status"] == "duplicate"


def test_duplicate_cleanup_does_not_unlink_a_replacement(pipeline, monkeypatch):
    ctx = ingest(pipeline)
    original = Path(latest_index_rows(pipeline.index_root)[0]["archive_path"]).read_bytes()
    source = pipeline.config.source.path / "Second arrival.pdf"
    source.write_bytes(original)

    import dlpduck.pipeline as module

    read = module._read_bounded_with_stat

    def swap_after_read(path, limit):
        result = read(path, limit)
        if path == source:
            replacement = source.with_suffix(".replacement")
            replacement.write_bytes(b"new arrival while duplicate was handled")
            replacement.replace(source)
        return result

    monkeypatch.setattr(module, "_read_bounded_with_stat", swap_after_read)
    duplicate = pipeline.run_job(
        source, None, pipeline.config.destination.work_dir / "_processing"
    )

    assert duplicate.job_id == ctx.job_id
    assert source.read_bytes() == b"new arrival while duplicate was handled"


def test_recovery_keeps_original_date_and_does_not_repeat_completion(pipeline, monkeypatch):
    path = pipeline.config.source.path / "original.pdf"
    path.write_bytes(make_pdf([["A document with enough ordinary native text"]]))
    staging = pipeline.config.destination.work_dir / "_processing"
    ctx = pipeline.claim(path, None, staging)
    ctx.received_at -= timedelta(days=1)
    manifest = pipeline._manifest(ctx)
    manifest["received_at"] = ctx.received_at.isoformat()
    pipeline._checkpoint(ctx, manifest, "claimed")
    pipeline.process(ctx)
    import dlpduck.pipeline as module
    original = module.write_content_row
    monkeypatch.setattr(module, "write_content_row", Mock(side_effect=OSError("crash")))
    with pytest.raises(OSError):
        pipeline.commit(ctx)
    monkeypatch.setattr(module, "write_content_row", original)
    pipeline.resume_staged(staging)
    files = list(pipeline.index_root.glob("dt=*/*.parquet"))
    assert len(files) == 1
    assert files[0].parent.name == f"dt={ctx.received_at.date()}"
    assert len([e for e in pipeline.audit.events_for_job(ctx.job_id) if e["event"] == "job.completed"]) == 1


def test_disposition_filter_precedes_limit(pipeline):
    ingest(pipeline, "SECRET sensitive document with enough native text")
    ingest(pipeline)
    rows = latest_index_rows(pipeline.index_root, disposition="quarantine", newest_first=True, limit=1)
    assert len(rows) == 1 and rows[0]["disposition"] == "quarantine"
    assert latest_index_rows(pipeline.index_root, disposition="quarantine", offset=1, limit=1) == []


def test_failed_job_can_be_retried_and_resolved(pipeline, monkeypatch):
    original = pipeline.extractor.extract
    monkeypatch.setattr(pipeline.extractor, "extract", Mock(side_effect=RuntimeError("temporary error")))
    ctx = ingest(pipeline)
    queue = FailureQueue(pipeline)
    assert queue.items()[0]["job_id"] == ctx.job_id
    monkeypatch.setattr(pipeline.extractor, "extract", original)
    queue.retry("failed", ctx.job_id, "Parser recovered", "admin")
    assert not queue.items()
    assert latest_index_rows(pipeline.index_root)[0]["disposition"] == "archive"


def test_uncertain_delivery_requires_confirmation_before_retry_audit(pipeline):
    job_id = "a" * 32
    folder = pipeline.config.destination.work_dir / "_processing" / job_id
    folder.mkdir(parents=True)
    (folder / "document.pdf").write_bytes(b"not opened before confirmation")
    (folder / "manifest.json").write_text(
        '{"steps":["emit_started"],"received_at":"2026-09-08T00:00:00+00:00"}'
    )

    with pytest.raises(ValueError, match="Confirm possible duplicate delivery"):
        FailureQueue(pipeline).retry("staged", job_id, "Try delivery", "admin")

    events = pipeline.audit.events_for_job(job_id)
    assert not [event for event in events if event["event"] == "job.retry_requested"]


@pytest.mark.parametrize("field", ["documents_days", "index_days", "audit_days"])
def test_negative_retention_rejected(field):
    with pytest.raises(ValidationError):
        RetentionConfig(**{field: -1})


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("limits", "rule_budget_ms", 0),
        ("extraction", "native_min_chars", -1),
    ],
)
def test_nonpositive_processing_limits_rejected(pipeline, section, field, value):
    data = pipeline.config.model_dump()
    data[section][field] = value
    with pytest.raises(ValidationError):
        Config.model_validate(data)


def test_empty_page_in_multpage_document_is_incomplete(monkeypatch):
    extractor = LineExtractor()
    calls = iter([(["ordinary native text"], "native", None), ([], "ocr", None)])
    monkeypatch.setattr(extractor, "_page_rows", lambda _: next(calls))
    assert extractor.extract(blank_pdf([(595, 842), (595, 842)])).degraded


def test_native_heading_does_not_skip_image_ocr(monkeypatch):
    extractor = LineExtractor()
    page = Mock()
    text_page = page.get_textpage.return_value
    text_page.get_text_bounded.return_value = "Long native heading above an image"
    page.get_rotation.return_value = 0
    page.get_objects.return_value = [Mock()]
    bitmap = page.render.return_value
    bitmap.to_numpy.return_value = Mock()
    monkeypatch.setattr(extractor, "_safe_dpi", lambda _: 150)
    extractor._ocr = Mock(return_value=([([[0, 0], [100, 0], [100, 20], [0, 20]], "SECRET", .99)], None))
    rows, source, _ = extractor._page_rows(page)
    assert "SECRET" in rows and source == "ocr"
    extractor._ocr.assert_called_once()


def test_metadata_symlink_is_never_read(pipeline, tmp_path):
    target = tmp_path / "outside-secret.xml"
    target.write_text("<metadata><department>secret</department></metadata>")
    companion = pipeline.config.source.path / "Recognizable name.xml"
    companion.symlink_to(target)
    source = pipeline.config.source.path / "Recognizable name.pdf"
    source.write_bytes(make_pdf([["An ordinary document with native text"]]))

    ctx = pipeline.run_job(
        source,
        companion,
        pipeline.config.destination.work_dir / "_processing",
    )

    assert ctx.metadata == {}
    assert target.read_text().startswith("<metadata>")
    assert any(
        event["event"] == "metadata.rejected"
        for event in pipeline.audit.events_for_job(ctx.job_id)
    )


def test_isolated_worker_timeout_is_reported(monkeypatch):
    monkeypatch.setattr(subprocess, "run", Mock(side_effect=subprocess.TimeoutExpired("worker", .01)))
    with pytest.raises(TimeoutError, match="extraction exceeded"):
        extract_isolated(b"pdf", 150, 20, .01)


def test_isolated_worker_reads_real_pdf():
    result = extract_isolated(make_pdf([["Native document through an isolated worker"]]), 150, 20, 20)
    assert "isolated worker" in result.full_text
