import logging
from pathlib import Path

import pyarrow.parquet as pq
import pytest

from dlpduck.config import Config
from dlpduck.content import InvalidJobId
from dlpduck.pipeline import Pipeline, content_job_id
from dlpduck.types import UnsafeSourceFile
from tests.pdf_factory import encrypted_pdf, make_pdf, with_metadata, without_metadata, write_pdf

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
    src = tmp_path / "drops"
    src.mkdir()
    return Config.model_validate(
        {
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
            # These tests exercise pipeline behavior with native-text PDFs.
            # OCR and process isolation have dedicated integration tests.
            "extraction": {"isolate_worker": False, "native_min_chars": 0},
            "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
        }
    )


def _pdf(path: Path, lines: list[str]) -> Path:
    return write_pdf(path, lines)


def _pdf_with_metadata(path: Path, lines: list[str], metadata: dict) -> Path:
    path.write_bytes(with_metadata(make_pdf([lines]), metadata))
    return path


class TestDisposition:
    def test_clean_document_archives(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["Just an ordinary memo about lunch."])
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(pdf, None, staging)

        assert ctx.disposition == "archive"
        assert ctx.hits == []
        archived = list(config.destination.archive.glob("dt=*/*.pdf"))
        assert len(archived) == 1
        assert archived[0].stem == ctx.job_id

    def test_document_with_a_quarantine_rule_hit_quarantines(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "sensitive.pdf", ["Card 4111 1111 1111 1111 on file"])
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(pdf, None, staging)

        assert ctx.disposition == "quarantine"
        assert any(h.rule_id == "pan.generic" for h in ctx.hits)
        quarantined = list(config.destination.quarantine.glob("dt=*/*.pdf"))
        assert len(quarantined) == 1
        assert not list(config.destination.archive.glob("dt=*/*.pdf"))

    def test_flag_only_hit_still_archives(self, tmp_path, config):
        # mark.body_mention is action=flag, not quarantine — a MEDIUM hit
        # alone must not pull the document. Pad with filler lines so the
        # mention sits outside both the header (lines 0-3) and the footer
        # (last 3 lines) positional windows — otherwise, on a short page,
        # "the only line" trivially satisfies both of those too.
        pipeline = Pipeline(config)
        lines = (
            ["filler"] * 5
            + ["This memo mentions OFFICIAL-SENSITIVE in passing, mid-body."]
            + ["filler"] * 5
        )
        pdf = _pdf(tmp_path / "flagged.pdf", lines)
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(pdf, None, staging)

        assert ctx.disposition == "archive"
        assert ctx.hits  # it was flagged...
        assert all(h.action == "flag" for h in ctx.hits)  # ...just not quarantined

    def test_staging_directory_is_removed_after_commit(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["nothing sensitive here"])
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(pdf, None, staging)

        assert not ctx.staging_dir.exists()


class TestPdfDerivedMetadata:
    """A bare PDF with no companion still yields metadata,
    derived from the PDF's own Info dictionary — and it's exactly as
    subject to the allowlist as companion-file metadata is.
    """

    def test_derived_metadata_is_dropped_by_default_allowlist(self, tmp_path, config):
        # config fixture's metadata_fields defaults to [] — nothing kept
        # unless explicitly named, regardless of where it came from.
        pipeline = Pipeline(config)
        pdf = _pdf_with_metadata(
            tmp_path / "doc.pdf", ["ordinary content"], {"title": "Q3 Report", "author": "jsmith"}
        )
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(pdf, None, staging)

        assert ctx.metadata == {}

    def test_derived_metadata_appears_when_allowlisted(self, tmp_path, config):
        config.source.metadata_fields = ["pdf_title", "pdf_author"]
        pipeline = Pipeline(config)
        pdf = _pdf_with_metadata(
            tmp_path / "doc.pdf", ["ordinary content"], {"title": "Q3 Report", "author": "jsmith"}
        )
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(pdf, None, staging)

        assert ctx.metadata == {"pdf_title": "Q3 Report", "pdf_author": "jsmith"}

    def test_derived_metadata_reaches_the_index_row(self, tmp_path, config):
        import json

        config.source.metadata_fields = ["pdf_title"]
        pipeline = Pipeline(config)
        pdf = _pdf_with_metadata(tmp_path / "doc.pdf", ["content"], {"title": "Indexed Title"})
        staging = config.destination.work_dir / "_processing"

        pipeline.run_job(pdf, None, staging)

        [index_file] = pipeline.index_root.glob("dt=*/*.parquet")
        row = pq.read_table(index_file).to_pylist()[0]
        assert json.loads(row["metadata"]) == {"pdf_title": "Indexed Title"}

    def test_companion_metadata_wins_over_pdf_derived_on_overlapping_keys(self, tmp_path, config):
        config.source.metadata_format = "text"
        config.source.metadata_suffix = ".txt"
        config.source.metadata_fields = ["pdf_title"]
        pipeline = Pipeline(config)

        pdf = _pdf_with_metadata(
            tmp_path / "doc.pdf", ["content"], {"title": "Title From PDF Itself"}
        )
        meta_path = tmp_path / "doc.txt"
        meta_path.write_text("pdf_title=Title From Companion File\n")
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(pdf, meta_path, staging)

        assert ctx.metadata == {"pdf_title": "Title From Companion File"}

    def test_companion_metadata_and_pdf_derived_metadata_both_survive_when_distinct(
        self, tmp_path, config
    ):
        config.source.metadata_format = "text"
        config.source.metadata_suffix = ".txt"
        config.source.metadata_fields = ["pdf_title", "device_id"]
        pipeline = Pipeline(config)

        pdf = _pdf_with_metadata(tmp_path / "doc.pdf", ["content"], {"title": "From PDF"})
        meta_path = tmp_path / "doc.txt"
        meta_path.write_text("device_id=MFP-3F-04\n")
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(pdf, meta_path, staging)

        assert ctx.metadata == {"pdf_title": "From PDF", "device_id": "MFP-3F-04"}

    def test_pdf_with_no_embedded_metadata_and_no_companion_yields_empty_metadata(
        self, tmp_path, config
    ):
        config.source.metadata_fields = ["pdf_title", "device_id"]  # allowlist non-empty
        pipeline = Pipeline(config)
        pdf = tmp_path / "plain.pdf"
        pdf.write_bytes(without_metadata(make_pdf([["nothing declared"]])))
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(pdf, None, staging)

        assert ctx.metadata == {}  # nothing to allowlist, not an error


class TestIdempotency:
    def test_job_id_is_a_pure_function_of_pdf_content(self, tmp_path, config):
        # job_id dedupes identical BYTES (e.g. an MFP retrying delivery
        # after a crash) — not documents that merely render the same text.
        # Two independently-authored PDFs differ in creation timestamp and
        # /ID even with identical visible content, so build one and copy it.
        original = _pdf(tmp_path / "a.pdf", ["identical content"]).read_bytes()
        copy_path = tmp_path / "b.pdf"
        copy_path.write_bytes(original)
        assert content_job_id(original) == content_job_id(copy_path.read_bytes())

    def test_reprocessing_the_same_content_produces_the_same_job_id(self, tmp_path, config):
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"

        original = _pdf(tmp_path / "one.pdf", ["same text, different filename"]).read_bytes()
        ctx1 = pipeline.run_job(tmp_path / "one.pdf", None, staging)

        pdf2 = tmp_path / "two.pdf"
        pdf2.write_bytes(original)
        ctx2 = pipeline.run_job(pdf2, None, staging)

        assert ctx1.job_id == ctx2.job_id


class TestCrashRecovery:
    def test_a_job_left_mid_processing_is_resumed_on_startup(self, tmp_path, config):
        pipeline = Pipeline(config)
        staging_root = config.destination.work_dir / "_processing"

        # Simulate claim() having run, then the process dying before commit:
        # stage the PDF under _processing/<job_id>/document.pdf by hand.
        pdf_bytes = _pdf(tmp_path / "orphan.pdf", ["Card 4111 1111 1111 1111"]).read_bytes()
        job_id = content_job_id(pdf_bytes)
        job_dir = staging_root / job_id
        job_dir.mkdir(parents=True)
        (job_dir / "document.pdf").write_bytes(pdf_bytes)

        resumed = pipeline.resume_staged(staging_root)

        assert len(resumed) == 1
        assert resumed[0].job_id == job_id
        assert resumed[0].disposition == "quarantine"
        assert not job_dir.exists()  # released after commit
        quarantined = list(config.destination.quarantine.glob("dt=*/*.pdf"))
        assert len(quarantined) == 1

    def test_resume_is_a_noop_when_nothing_is_staged(self, tmp_path, config):
        pipeline = Pipeline(config)
        staging_root = config.destination.work_dir / "_processing"
        staging_root.mkdir(parents=True)
        assert pipeline.resume_staged(staging_root) == []

    def test_resume_on_a_directory_that_does_not_exist_yet(self, tmp_path, config):
        pipeline = Pipeline(config)
        assert pipeline.resume_staged(tmp_path / "never_created") == []


class TestFailClosed:
    def test_encrypted_document_is_routed_to_failed(self, tmp_path, config):
        pipeline = Pipeline(config)
        enc_path = tmp_path / "encrypted.pdf"
        enc_path.write_bytes(encrypted_pdf(make_pdf([["secret"]])))
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(enc_path, None, staging)

        assert ctx.disposition == "failed"
        assert ctx.reason == "encrypted"
        failed_dir = config.destination.work_dir / "failed" / ctx.job_id
        assert (failed_dir / "document.pdf").exists()
        # An encrypted document must never land in the clean archive.
        assert not list(config.destination.archive.glob("dt=*/*.pdf"))

    def test_oversized_document_is_rejected_at_claim(self, tmp_path, config):
        config.limits.max_bytes = 10  # smaller than any real PDF
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "big.pdf", ["some content"])
        staging = config.destination.work_dir / "_processing"

        with pytest.raises(Exception):
            pipeline.claim(pdf, None, staging)


class TestIndexAndAudit:
    def test_committed_job_has_a_matching_index_row(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["ordinary content"])
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(pdf, None, staging)

        parquet_files = list(pipeline.index_root.glob("dt=*/*.parquet"))
        assert len(parquet_files) == 1
        row = pq.read_table(parquet_files[0]).to_pylist()[0]
        assert row["job_id"] == ctx.job_id
        assert row["disposition"] == "archive"

    def test_quarantined_job_index_row_never_contains_the_raw_matched_value(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "card.pdf", ["Card 4111 1111 1111 1111 on file"])
        staging = config.destination.work_dir / "_processing"

        pipeline.run_job(pdf, None, staging)

        parquet_files = list(pipeline.index_root.glob("dt=*/*.parquet"))
        row = pq.read_table(parquet_files[0]).to_pylist()[0]
        assert "4111111111111111" not in str(row["hits"])
        assert "4111 1111 1111 1111" not in str(row["hits"])

    def test_audit_chain_is_intact_after_multiple_jobs(self, tmp_path, config):
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        for i in range(3):
            pdf = _pdf(tmp_path / f"doc{i}.pdf", [f"content number {i}"])
            pipeline.run_job(pdf, None, staging)

        ok, breaks = pipeline.audit.verify()
        assert ok is True
        assert breaks == []


class TestPluginIntegration:
    """Plugins are wired into the real pipeline, not just PluginRunner in isolation:
    enrich runs before disposition and can be observed in the committed
    audit_fields; a critical emit failure leaves staging in place instead
    of silently discarding evidence that the sink never got the job.
    """

    def test_enrich_plugin_output_reaches_the_index_row(self, tmp_path, config):
        config.source.metadata_fields = ["device_id"]
        config.source.metadata_format = "xml"
        config.plugins = [
            {
                "name": "static_enrich",
                "args": {"mapping": {"MFP-1": {"department": "Legal"}}},
            }
        ]
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["ordinary content"])
        meta_path = tmp_path / "clean.xml"
        meta_path.write_text("<meta><device_id>MFP-1</device_id></meta>")
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(pdf, meta_path, staging)

        assert ctx.audit_fields.get("department") == "Legal"
        row = pq.read_table(list(pipeline.index_root.glob("dt=*/*.parquet"))[0]).to_pylist()[0]
        assert __import__("json").loads(row["audit_fields"])["department"] == "Legal"

    def test_critical_emit_plugin_failure_preserves_staging_for_inspection(self, tmp_path, config):
        config.plugins = [
            {
                "name": "webhook",
                "critical": True,
                "args": {"url": "http://127.0.0.1:1/definitely-unreachable", "timeout": 1},
            }
        ]
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["ordinary content"])
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.claim(pdf, None, staging)
        pipeline.process(ctx)
        with pytest.raises(Exception):
            pipeline.commit(ctx)

        # The PDF, audit event, and index row are already durable — a
        # critical emit failure can't undo that — but staging must survive
        # for an operator to find, since rmtree never ran.
        assert ctx.staging_dir.exists()
        assert list(config.destination.archive.glob("dt=*/*.pdf"))

    def test_non_critical_emit_failure_does_not_block_commit(self, tmp_path, config):
        config.plugins = [
            {
                "name": "webhook",
                "critical": False,
                "args": {"url": "http://127.0.0.1:1/definitely-unreachable", "timeout": 1},
            }
        ]
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["ordinary content"])
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(pdf, None, staging)  # must not raise

        assert ctx.disposition == "archive"
        assert not ctx.staging_dir.exists()  # released normally


class TestContentIndexSplit:
    """The index (metadata) and content (raw full_text) stores are
    written separately and are independently addressable — this is the
    property purge relies on: deleting content never touches the index.
    """

    def test_index_row_never_contains_full_text(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["distinctive marker phrase here"])
        staging = config.destination.work_dir / "_processing"

        pipeline.run_job(pdf, None, staging)

        index_path = list(pipeline.index_root.glob("dt=*/*.parquet"))[0]
        row = pq.read_table(index_path).to_pylist()[0]
        assert "full_text" not in row
        assert "distinctive marker phrase" not in str(row)

    def test_content_row_holds_the_full_text(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["distinctive marker phrase here"])
        staging = config.destination.work_dir / "_processing"

        ctx = pipeline.run_job(pdf, None, staging)

        content_files = list(pipeline.content_root.glob("dt=*/*.parquet"))
        assert len(content_files) == 1
        assert content_files[0].stem == ctx.job_id
        row = pq.read_table(content_files[0]).to_pylist()[0]
        assert "distinctive marker phrase" in row["full_text"]

    def test_index_and_content_share_the_same_partition_date(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["content"])
        staging = config.destination.work_dir / "_processing"

        pipeline.run_job(pdf, None, staging)

        index_partitions = {p.name for p in pipeline.index_root.glob("dt=*")}
        content_partitions = {p.name for p in pipeline.content_root.glob("dt=*")}
        assert index_partitions == content_partitions


class TestContentPurge:
    """The capability this split exists for: deleting a job's raw text
    without deleting proof the job happened, and without breaking the
    audit chain. See dlpduck/schema.py and dlpduck/content.py.
    """

    def test_purge_removes_the_content_file(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["sensitive content"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)

        result = pipeline.purge_content(ctx.job_id, reason="wrong document scanned", actor="alice")

        assert result.content_removed is True
        assert result.document_removed is None  # soft purge — document untouched, not "removed"
        assert result.hard is False
        assert list(pipeline.content_root.glob("dt=*/*.parquet")) == []

    def test_purge_leaves_the_index_row_completely_untouched(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "sensitive.pdf", ["Card 4111 1111 1111 1111 on file"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)

        index_path = list(pipeline.index_root.glob("dt=*/*.parquet"))[0]
        row_before = pq.read_table(index_path).to_pylist()[0]

        pipeline.purge_content(ctx.job_id, reason="test", actor="alice")

        row_after = pq.read_table(index_path).to_pylist()[0]
        assert row_before == row_after
        assert row_after["disposition"] == "quarantine"  # proof the job happened survives

    def test_purge_leaves_the_archived_pdf_in_place(self, tmp_path, config):
        # Content-store purge is deliberately narrower than a full document
        # purge — it's the "wrong text got indexed" case, not
        # "delete this document everywhere".
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["content"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)

        pipeline.purge_content(ctx.job_id, reason="test", actor="alice")

        assert list(config.destination.archive.glob("dt=*/*.pdf"))

    def test_purge_appends_an_audit_event_without_breaking_the_chain(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["content"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)

        pipeline.purge_content(ctx.job_id, reason="wrong doc", actor="alice")

        ok, breaks = pipeline.audit.verify()
        assert ok is True
        assert breaks == []
        [log_file] = pipeline.audit.root.glob("dt=*/events.jsonl")
        events = log_file.read_text()
        assert '"event":"content.purged"' in events
        assert '"reason":"wrong doc"' in events
        assert '"actor":"alice"' in events

    def test_purging_a_nonexistent_job_is_recorded_but_not_an_error(self, tmp_path, config):
        pipeline = Pipeline(config)
        # Well-formed id, no such job — distinct from a malformed one,
        # which is rejected outright (see TestPurgeRejectsMalformedJobIds).
        result = pipeline.purge_content("0" * 32, reason="test", actor="alice")

        assert result.content_removed is False
        [log_file] = pipeline.audit.root.glob("dt=*/events.jsonl")
        assert '"content_removed":false' in log_file.read_text()
        assert '"mode":"soft"' in log_file.read_text()


class TestHardPurge:
    """--hard: also delete the archived PDF, a real erasure rather than
    just de-indexing. The index row and audit trail are unaffected either
    way — neither ever held the document or its text.
    """

    def test_hard_purge_removes_both_content_and_the_pdf(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "sensitive.pdf", ["Card 4111 1111 1111 1111 on file"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)
        assert ctx.disposition == "quarantine"

        result = pipeline.purge_content(ctx.job_id, reason="erasure request", actor="alice", hard=True)

        assert result.content_removed is True
        assert result.document_removed is True
        assert result.hard is True
        assert list(pipeline.content_root.glob("dt=*/*.parquet")) == []
        assert list(config.destination.quarantine.glob("dt=*/*.pdf")) == []

    def test_hard_purge_checks_whichever_root_the_disposition_actually_used(self, tmp_path, config):
        # An archived (not quarantined) document's PDF lives under
        # destination.archive — hard purge must find it there too, not
        # just in destination.quarantine.
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "clean.pdf", ["ordinary memo, nothing sensitive"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)
        assert ctx.disposition == "archive"

        result = pipeline.purge_content(ctx.job_id, reason="test", actor="alice", hard=True)

        assert result.document_removed is True
        assert list(config.destination.archive.glob("dt=*/*.pdf")) == []

    def test_soft_purge_by_default_leaves_the_pdf_alone(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "sensitive.pdf", ["Card 4111 1111 1111 1111 on file"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)

        result = pipeline.purge_content(ctx.job_id, reason="test", actor="alice")  # hard defaults False

        assert result.hard is False
        assert result.document_removed is None
        assert list(config.destination.quarantine.glob("dt=*/*.pdf"))  # still there

    def test_hard_purge_leaves_the_index_row_untouched(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "sensitive.pdf", ["Card 4111 1111 1111 1111 on file"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)

        index_path = list(pipeline.index_root.glob("dt=*/*.parquet"))[0]
        row_before = pq.read_table(index_path).to_pylist()[0]

        pipeline.purge_content(ctx.job_id, reason="test", actor="alice", hard=True)

        row_after = pq.read_table(index_path).to_pylist()[0]
        assert row_before == row_after

    def test_hard_purge_does_not_break_the_audit_chain_and_records_the_mode(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "sensitive.pdf", ["Card 4111 1111 1111 1111 on file"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)

        pipeline.purge_content(ctx.job_id, reason="erasure request", actor="alice", hard=True)

        ok, breaks = pipeline.audit.verify()
        assert ok is True
        assert breaks == []
        [log_file] = pipeline.audit.root.glob("dt=*/events.jsonl")
        events = log_file.read_text()
        assert '"mode":"hard"' in events
        assert '"document_removed":true' in events

    def test_hard_purge_of_an_already_soft_purged_job_still_removes_the_pdf(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "sensitive.pdf", ["Card 4111 1111 1111 1111 on file"])
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)

        soft = pipeline.purge_content(ctx.job_id, reason="first pass", actor="alice")
        assert soft.content_removed is True

        hard = pipeline.purge_content(ctx.job_id, reason="second pass", actor="alice", hard=True)
        assert hard.content_removed is False  # already gone from the first pass
        assert hard.document_removed is True  # but the PDF was still there to remove


class TestPurgeRejectsMalformedJobIds:
    """A job id is interpolated into a glob to find the files to delete,
    so its shape is a security boundary: "*" would otherwise purge every
    job in the store from a single call, and "../.." would walk out of it.
    """

    def test_wildcard_job_id_is_rejected_and_deletes_nothing(self, tmp_path, config):
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(
            _pdf(tmp_path / "doc.pdf", ["An ordinary memo."]), None, staging
        )
        before = list(pipeline.content_root.glob("dt=*/*.parquet"))
        assert before  # the job we just ingested

        with pytest.raises(InvalidJobId):
            pipeline.purge_content("*", reason="test", actor="mallory")

        assert list(pipeline.content_root.glob("dt=*/*.parquet")) == before
        assert ctx.job_id  # untouched

    def test_wildcard_hard_purge_does_not_delete_archived_pdfs(self, tmp_path, config):
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        pipeline.run_job(_pdf(tmp_path / "doc.pdf", ["An ordinary memo."]), None, staging)
        pdfs_before = list(config.destination.archive.glob("dt=*/*.pdf"))
        assert pdfs_before

        with pytest.raises(InvalidJobId):
            pipeline.purge_content("*", reason="test", actor="mallory", hard=True)

        assert list(config.destination.archive.glob("dt=*/*.pdf")) == pdfs_before

    @pytest.mark.parametrize(
        "job_id",
        ["*", "?" * 32, "../../etc/passwd", "", "ABCDEF" + "0" * 26, "0" * 31, "0" * 33],
    )
    def test_malformed_ids_are_rejected(self, job_id, config):
        pipeline = Pipeline(config)
        with pytest.raises(InvalidJobId):
            pipeline.purge_content(job_id, reason="test", actor="mallory")


class TestSymlinkedSourceIsRefused:
    def test_a_symlink_in_the_drop_folder_is_not_followed(self, tmp_path, config):
        """A drop folder is typically writable by something less trusted
        than the daemon; following a symlink would ingest whatever it
        points at into the searchable content store."""
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"

        secret = tmp_path / "secret.pdf"
        _pdf(secret, ["TOP SECRET not for ingestion"])
        link = config.source.path / "innocent.pdf"
        link.symlink_to(secret)

        with pytest.raises(UnsafeSourceFile):
            pipeline.claim(link, None, staging)

        assert secret.is_file()  # not moved out from under its owner


class TestPurgeRecordsIntentBeforeDeleting:
    """A purge is irreversible. If the only audit event is written after
    the deletion, a crash in between destroys data and leaves no record
    that anyone asked for it — the one outcome a DLP tool must not have.
    """

    def test_intent_is_recorded_before_the_deletion(self, tmp_path, config):
        import json

        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(_pdf(tmp_path / "doc.pdf", ["content"]), None, staging)

        pipeline.purge_content(ctx.job_id, reason="erasure request", actor="alice", hard=True)

        events = []
        for log in pipeline.audit.root.glob("dt=*/events.jsonl"):
            events += [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
        started = [e for e in events if e["event"] == "purge.started"]
        completed = [e for e in events if e["event"] == "content.purged"]

        assert started and completed
        assert started[0]["seq"] < completed[0]["seq"]  # intent first
        assert started[0]["reason"] == "erasure request"
        assert started[0]["actor"] == "alice"
        assert started[0]["mode"] == "hard"

    def test_a_crash_between_the_two_still_leaves_evidence(self, tmp_path, config):
        """Simulate dying immediately after the deletion: the started
        record must already be on disk."""
        import json

        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(_pdf(tmp_path / "doc.pdf", ["content"]), None, staging)

        real_append = pipeline.audit.append

        def _die_before_the_completion_record(event_type, **fields):
            if event_type == "content.purged":
                raise RuntimeError("process killed mid-purge")
            return real_append(event_type, **fields)

        pipeline.audit.append = _die_before_the_completion_record
        with pytest.raises(RuntimeError):
            pipeline.purge_content(ctx.job_id, reason="interrupted", actor="alice")

        events = []
        for log in pipeline.audit.root.glob("dt=*/events.jsonl"):
            events += [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
        started = [e for e in events if e["event"] == "purge.started"]
        assert started, "the deletion must never be invisible"
        assert not [e for e in events if e["event"] == "content.purged"]
        # ...and an operator can see the content really is gone.
        assert not list(pipeline.content_root.glob(f"dt=*/{ctx.job_id}.parquet"))


class TestContentTracing:
    """The end-to-end version of tests/test_tracing.py's unit tests: a real
    document through the real pipeline, checking what actually lands in
    the log records rather than trusting the helper function in isolation.
    """

    SECRET_LINE = "Card 4111 1111 1111 1111 on file"

    def _run(self, config, monkeypatch, caplog, *, debug: bool, trace_flag: bool):
        if trace_flag:
            monkeypatch.setenv("DLPDUCK_TRACE_CONTENT_OUTPUT", "true")
        else:
            monkeypatch.delenv("DLPDUCK_TRACE_CONTENT_OUTPUT", raising=False)
        level = logging.DEBUG if debug else logging.INFO
        caplog.set_level(level, logger="dlpduck")
        pipeline = Pipeline(config)
        pdf = _pdf(config.source.path / "card.pdf", [self.SECRET_LINE])
        pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")
        return "\n".join(r.getMessage() for r in caplog.records)

    def test_debug_alone_never_logs_document_text(self, config, monkeypatch, caplog):
        text = self._run(config, monkeypatch, caplog, debug=True, trace_flag=False)
        assert self.SECRET_LINE not in text
        assert "4111" not in text
        assert "extracted 1 page" in text  # the safe, structural DEBUG line is still there

    def test_flag_alone_never_logs_document_text(self, config, monkeypatch, caplog):
        text = self._run(config, monkeypatch, caplog, debug=False, trace_flag=True)
        assert self.SECRET_LINE not in text
        assert "4111" not in text

    def test_both_together_log_the_line_and_the_raw_match(self, config, monkeypatch, caplog):
        text = self._run(config, monkeypatch, caplog, debug=True, trace_flag=True)
        assert self.SECRET_LINE in text
        assert "4111 1111 1111 1111" in text  # the raw (unmasked) matched value
