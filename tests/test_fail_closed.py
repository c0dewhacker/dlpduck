"""Fail-closed is the property the whole design rests on: when DLPDuck
cannot be sure what a document contains, it must refuse to treat it as
clean. Every branch here is a way that certainty can be lost — a page that
wouldn't render, a rule that ran out of time, a limit exceeded, an enrich
plugin that was supposed to be authoritative and wasn't — and each one has
to end somewhere safe (failed/ or quarantine), never in the archive.
"""

import json
from pathlib import Path

import pymupdf
import pytest

from dlpduck.config import Config
from dlpduck.pipeline import Pipeline, content_job_id
from dlpduck.types import (
    DocumentText,
    DocumentTooLarge,
    JobContext,
    TextLine,
    UnsafeSourceFile,
)

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


def _config_dict(tmp_path, **overrides):
    src = tmp_path / "drops"
    src.mkdir(exist_ok=True)
    base = {
        "source": {"name": "t", "path": str(src), "metadata_format": "none"},
        "destination": {
            "archive": str(tmp_path / "archive"),
            "quarantine": str(tmp_path / "quarantine"),
            "work_dir": str(tmp_path / "work"),
        },
        "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = {**base[key], **value}
        else:
            base[key] = value
    return base


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
    return Config.model_validate(_config_dict(tmp_path))


def _pdf(path: Path, lines: list[str], pages: int = 1) -> Path:
    doc = pymupdf.open()
    for _ in range(pages):
        page = doc.new_page(width=595, height=842)
        y = 40
        for line in lines:
            page.insert_text((40, y), line)
            y += 20
    doc.save(path)
    return path


def _audit(pipeline) -> list[dict]:
    out = []
    for log in pipeline.audit.root.glob("dt=*/events.jsonl"):
        out += [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
    return out


def _assert_not_archived(config):
    assert not list(config.destination.archive.glob("dt=*/*.pdf"))


class TestLimitsAreEnforced:
    def test_too_many_pages_fails_the_job(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(_config_dict(tmp_path, limits={"max_pages": 1}))
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "long.pdf", ["content"], pages=3)

        ctx = pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")

        assert ctx.disposition == "failed"
        assert ctx.reason == "page_count_exceeds_limit"
        _assert_not_archived(config)
        assert any(e["event"] == "job.failed" for e in _audit(pipeline))

    def test_oversized_file_is_refused_at_claim(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(_config_dict(tmp_path, limits={"max_bytes": 500}))
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "big.pdf", ["x" * 200] * 40)
        assert pdf.stat().st_size > 500

        with pytest.raises(DocumentTooLarge):
            pipeline.claim(pdf, None, config.destination.work_dir / "_processing")

    def test_an_oversized_file_is_refused_without_being_read(self, tmp_path, monkeypatch):
        """The stat check and the bounded read are not redundant.

        Mutation testing showed removing the stat check changes nothing
        the suite could see — the bounded read still refuses — which is
        defence in depth working, but left the stat check's own purpose
        untested. It is what stops the daemon reading 200MB of a 500GB
        file someone dropped in a semi-trusted folder before deciding it
        was too big. Anyone tidying it away as "redundant" should have a
        test tell them otherwise.
        """
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(_config_dict(tmp_path, limits={"max_bytes": 500}))
        pipeline = Pipeline(config)
        pdf = _pdf(config.source.path / "big.pdf", ["x" * 200] * 40)
        assert pdf.stat().st_size > 500

        opened: list[str] = []
        real_open = open

        def spy(file, *args, **kwargs):
            opened.append(str(file))
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr("dlpduck.pipeline.open", spy, raising=False)

        with pytest.raises(DocumentTooLarge):
            pipeline.claim(pdf, None, config.destination.work_dir / "_processing")

        assert str(pdf) not in opened, "the file was read before being refused on size"

    def test_a_file_that_grows_after_the_stat_still_cannot_exceed_the_limit(
        self, tmp_path, monkeypatch
    ):
        """The limit is enforced against what is actually read, not against
        an earlier stat() that a still-writing producer can invalidate."""
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(_config_dict(tmp_path, limits={"max_bytes": 2000}))
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "grows.pdf", ["small"])

        real_stat = Path.stat

        class _UndersizedStat:
            """Reports a small size but otherwise behaves like the real
            stat — pathlib routes is_symlink() through here too."""

            def __init__(self, real):
                self._real = real
                self.st_size = 10

            def __getattr__(self, name):
                return getattr(self._real, name)

        def _lying_stat(self, *args, **kwargs):
            result = real_stat(self, *args, **kwargs)
            if self.name == "grows.pdf" and kwargs.get("follow_symlinks", True):
                # Pretend it was under the limit at check time, then let the
                # real (larger) file be what read() actually sees.
                return _UndersizedStat(result)
            return result

        pdf.write_bytes(pdf.read_bytes() + b"\x00" * 5000)  # now well over the limit
        monkeypatch.setattr(Path, "stat", _lying_stat)

        with pytest.raises(DocumentTooLarge):
            pipeline.claim(pdf, None, config.destination.work_dir / "_processing")


class TestClaimTimeRefusalsAreRoutedNotLost:
    """A document the system declines to assess still has to be visible
    as declined. Left in the drop folder it is silently unassessed, and
    re-attempted on every poll forever — a fail-open dressed as a log
    line.
    """

    def _pipeline(self, tmp_path, monkeypatch, **limits):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(_config_dict(tmp_path, limits=limits))
        return config, Pipeline(config)

    def _failed_dirs(self, config):
        root = config.destination.work_dir / "failed"
        return sorted(p for p in root.iterdir() if p.is_dir()) if root.is_dir() else []

    def test_an_oversized_file_leaves_the_drop_folder(self, tmp_path, monkeypatch):
        config, pipeline = self._pipeline(tmp_path, monkeypatch, max_bytes=500)
        pdf = _pdf(config.source.path / "big.pdf", ["x" * 200] * 40)

        with pytest.raises(DocumentTooLarge):
            pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")

        assert not pdf.exists(), "left in place, it would be retried every poll forever"
        [failed] = self._failed_dirs(config)
        assert (failed / "document.pdf").is_file()

    def test_the_refusal_is_audited_with_a_reason(self, tmp_path, monkeypatch):
        config, pipeline = self._pipeline(tmp_path, monkeypatch, max_bytes=500)
        pdf = _pdf(config.source.path / "big.pdf", ["x" * 200] * 40)

        with pytest.raises(DocumentTooLarge):
            pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")

        [event] = [e for e in _audit(pipeline) if e["event"] == "job.failed"]
        assert event["reason"] == "DocumentTooLarge"
        assert event["source_name"] == "big.pdf"

    def test_the_reason_is_written_beside_the_document(self, tmp_path, monkeypatch):
        config, pipeline = self._pipeline(tmp_path, monkeypatch, max_bytes=500)
        pdf = _pdf(config.source.path / "big.pdf", ["x" * 200] * 40)

        with pytest.raises(DocumentTooLarge):
            pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")

        [failed] = self._failed_dirs(config)
        meta = json.loads((failed / "metadata.json").read_text())
        assert meta["reason"] == "DocumentTooLarge"
        assert meta["source_name"] == "big.pdf"

    def test_a_symlink_is_relocated_without_ever_being_followed(self, tmp_path, monkeypatch):
        """The refusal must not undo itself: sizing or copying the target
        is the exact thing claim() declined to do."""
        config, pipeline = self._pipeline(tmp_path, monkeypatch)
        secret = tmp_path / "secret.txt"
        secret.write_text("a private file the drop folder should never reach")
        link = config.source.path / "planted.pdf"
        link.symlink_to(secret)

        with pytest.raises(UnsafeSourceFile):
            pipeline.run_job(link, None, config.destination.work_dir / "_processing")

        assert not link.exists() and not link.is_symlink()
        [failed] = self._failed_dirs(config)
        moved = failed / "document.pdf"
        assert moved.is_symlink(), "the link was relocated, not resolved"
        assert secret.read_text().startswith("a private file"), "the target is untouched"

    def test_the_same_file_rejected_twice_lands_in_one_place(self, tmp_path, monkeypatch):
        """The id is derived from name, size and mtime, so re-dropping the
        identical file (an rsync or `cp -p` that preserves mtime) reuses
        one directory rather than accumulating them.

        The bytes are captured once and rewritten, rather than
        regenerating the PDF each time: "the same file" has to be true by
        construction, not contingent on PyMuPDF emitting byte-identical
        output twice — which it does not reliably do, and which made an
        earlier version of this test flaky in the full suite.
        """
        import os

        config, pipeline = self._pipeline(tmp_path, monkeypatch, max_bytes=500)
        payload = _pdf(tmp_path / "source.pdf", ["x" * 200] * 40).read_bytes()

        for _ in range(2):
            pdf = config.source.path / "big.pdf"
            pdf.write_bytes(payload)
            os.utime(pdf, (1_700_000_000, 1_700_000_000))
            with pytest.raises(DocumentTooLarge):
                pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")

        assert len(self._failed_dirs(config)) == 1

    def test_a_different_file_under_the_same_name_gets_its_own_place(self, tmp_path):
        """The other half of that: two genuinely different documents that
        happen to share a filename must not be filed as one, or the second
        would silently overwrite the operator's evidence of the first."""
        import os

        monkeypatch = pytest.MonkeyPatch()
        config, pipeline = self._pipeline(tmp_path, monkeypatch, max_bytes=500)
        try:
            for lines in (["x" * 200] * 40, ["y" * 199] * 41):
                pdf = _pdf(config.source.path / "big.pdf", lines)
                os.utime(pdf, (1_700_000_000, 1_700_000_000))
                with pytest.raises(DocumentTooLarge):
                    pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")
        finally:
            monkeypatch.undo()

        assert len(self._failed_dirs(config)) == 2


class TestExtractionFailuresFailClosed:
    def test_an_extraction_crash_fails_the_job_rather_than_archiving_it(self, config, tmp_path):
        pipeline = Pipeline(config)

        def _boom(_pdf_bytes):
            raise RuntimeError("mupdf exploded")

        pipeline.extractor.extract = _boom
        pdf = _pdf(tmp_path / "doc.pdf", ["content"])

        ctx = pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")

        assert ctx.disposition == "failed"
        assert "extraction_error" in ctx.reason
        _assert_not_archived(config)

    def test_a_degraded_page_quarantines_even_with_no_hits(self, config, tmp_path):
        """A page that would not render makes the document's extraction
        claim untrustworthy — "no hits" from partial text is not the same
        as "clean"."""
        pipeline = Pipeline(config)

        def _degraded(_pdf_bytes):
            text = DocumentText(page_count=2)
            text.add_line(
                TextLine(
                    line_number=0, page_number=1, line_on_page=0, lines_on_page=1,
                    text="only the page that survived", source="native",
                )
            )
            text.degraded = True
            return text

        pipeline.extractor.extract = _degraded
        pdf = _pdf(tmp_path / "doc.pdf", ["content"])

        ctx = pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")

        assert ctx.hits == []  # nothing matched...
        assert ctx.disposition == "quarantine"  # ...and it is quarantined anyway
        assert ctx.reason == "degraded_extraction"
        _assert_not_archived(config)

    def test_degraded_can_be_opted_out_of_deliberately(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(
            _config_dict(tmp_path, dlp={"quarantine_on_degraded": False})
        )
        pipeline = Pipeline(config)

        def _degraded(_pdf_bytes):
            text = DocumentText(page_count=1)
            text.add_line(
                TextLine(
                    line_number=0, page_number=1, line_on_page=0, lines_on_page=1,
                    text="partial", source="native",
                )
            )
            text.degraded = True
            return text

        pipeline.extractor.extract = _degraded
        ctx = pipeline.run_job(
            _pdf(tmp_path / "doc.pdf", ["content"]),
            None,
            config.destination.work_dir / "_processing",
        )
        assert ctx.disposition == "archive"  # the operator asked for this


class TestRuleBudgetFailsTheJob:
    def test_a_rule_that_runs_out_of_time_fails_the_document(self, tmp_path, monkeypatch):
        # A rule that can't finish means the document was never fully
        # assessed — it must not be archived on the strength of a partial scan.
        # The extractor is stubbed rather than fed a pathological PDF:
        # PyMuPDF clips inserted text at the page edge (~91 chars), which is
        # far too short to make the pattern backtrack. What's under test here
        # is the pipeline's handling of the exception, not the engine's
        # timing — test_engine.py covers that end.
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(
            _config_dict(
                tmp_path,
                limits={"rule_budget_ms": 50},
                dlp={"rules": [{"id": "slow.rule", "name": "Catastrophic", "pattern": r"(a+)+$"}]},
            )
        )
        pipeline = Pipeline(config)

        def _pathological(_pdf_bytes):
            text = DocumentText(page_count=1)
            text.add_line(
                TextLine(
                    line_number=0, page_number=1, line_on_page=0, lines_on_page=1,
                    text="a" * 5000 + "b", source="native",
                )
            )
            return text

        pipeline.extractor.extract = _pathological
        pdf = _pdf(tmp_path / "slow.pdf", ["placeholder"])

        ctx = pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")

        assert ctx.disposition == "failed"
        assert "rule_budget_exceeded" in ctx.reason
        _assert_not_archived(config)
        failed = [e for e in _audit(pipeline) if e["event"] == "job.failed"]
        assert failed and failed[0]["rule_id"] == "slow.rule"


class TestCriticalPluginFailureFailsTheJob:
    def test_a_critical_enrich_plugin_that_raises_stops_the_job(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(
            _config_dict(
                tmp_path,
                plugins=[
                    {
                        "path": "tests.test_fail_closed.ExplodingEnrich",
                        "critical": True,
                        "args": {},
                    }
                ],
            )
        )
        pipeline = Pipeline(config)

        ctx = pipeline.run_job(
            _pdf(tmp_path / "doc.pdf", ["ordinary content"]),
            None,
            config.destination.work_dir / "_processing",
        )

        assert ctx.disposition == "failed"
        assert "enrich_plugin_failed" in ctx.reason
        _assert_not_archived(config)

    def test_a_noncritical_plugin_failure_is_audited_but_lets_the_job_through(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(
            _config_dict(
                tmp_path,
                plugins=[
                    {
                        "path": "tests.test_fail_closed.ExplodingEnrich",
                        "critical": False,
                        "args": {},
                    }
                ],
            )
        )
        pipeline = Pipeline(config)

        ctx = pipeline.run_job(
            _pdf(tmp_path / "doc.pdf", ["ordinary content"]),
            None,
            config.destination.work_dir / "_processing",
        )

        assert ctx.disposition == "archive"
        assert any(e["event"] == "plugin.failed" for e in _audit(pipeline))
        assert ctx.errors  # the failure is still on the record


class TestCrashRecoveryIntegrity:
    def test_a_staged_job_whose_content_does_not_match_its_id_is_left_alone(
        self, config, tmp_path
    ):
        """job_id is the content hash. If a staged directory's PDF doesn't
        hash to its name, something rewrote it between claim and resume —
        resume must not process it as if nothing happened.
        """
        pipeline = Pipeline(config)
        staging_root = config.destination.work_dir / "_processing"
        real_pdf = _pdf(tmp_path / "real.pdf", ["the original content"])
        swapped = _pdf(tmp_path / "swapped.pdf", ["something else entirely"])

        job_dir = staging_root / content_job_id(real_pdf.read_bytes())
        job_dir.mkdir(parents=True)
        (job_dir / "document.pdf").write_bytes(swapped.read_bytes())  # tampered

        resumed = pipeline.resume_staged(staging_root)

        assert resumed == []
        assert (job_dir / "document.pdf").is_file()  # kept for inspection
        _assert_not_archived(config)

    def test_a_genuinely_interrupted_job_is_resumed_and_completed(self, config, tmp_path):
        pipeline = Pipeline(config)
        staging_root = config.destination.work_dir / "_processing"
        pdf = _pdf(tmp_path / "interrupted.pdf", ["ordinary memo content"])

        job_dir = staging_root / content_job_id(pdf.read_bytes())
        job_dir.mkdir(parents=True)
        (job_dir / "document.pdf").write_bytes(pdf.read_bytes())

        resumed = pipeline.resume_staged(staging_root)

        assert len(resumed) == 1
        assert resumed[0].disposition == "archive"
        assert list(config.destination.archive.glob("dt=*/*.pdf"))


class ExplodingEnrich:
    """Module-level so the plugin loader can import it by dotted path."""

    phase = "enrich"
    name = "exploding"

    def __init__(self, name=None, critical=False, spool_root=None):
        self.critical = critical
        if name:
            self.name = name

    def run(self, ctx: JobContext) -> None:
        raise RuntimeError("directory lookup failed")


class TestCompanionMetadataIsBounded:
    """The PDF has a size limit; its companion arrives from the same
    semi-trusted drop folder and used to be read whole with no ceiling —
    a one-line PDF with a multi-gigabyte .xml beside it was enough to
    exhaust the daemon.
    """

    def test_an_oversized_companion_is_ignored_not_read(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(
            _config_dict(
                tmp_path,
                limits={"max_metadata_bytes": 500},
                source={
                    "name": "t", "path": str(tmp_path / "drops"), "metadata_format": "text",
                    "metadata_suffix": ".txt", "metadata_fields": ["device_id"],
                },
            )
        )
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "doc.pdf", ["ordinary content"])
        companion = tmp_path / "doc.txt"
        companion.write_text("device_id=MFP-1\n" + "padding=" + "A" * 5000 + "\n")

        ctx = pipeline.claim(pdf, companion, config.destination.work_dir / "_processing")

        assert ctx.metadata == {}  # the companion was skipped entirely
        rejected = [e for e in _audit(pipeline) if e["event"] == "metadata.rejected"]
        assert rejected and "max_metadata_bytes" in rejected[0]["error"]

    def test_a_normal_companion_is_still_read(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(
            _config_dict(
                tmp_path,
                source={
                    "name": "t", "path": str(tmp_path / "drops"), "metadata_format": "text",
                    "metadata_suffix": ".txt", "metadata_fields": ["device_id"],
                },
            )
        )
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "doc.pdf", ["ordinary content"])
        companion = tmp_path / "doc.txt"
        companion.write_text("device_id=MFP-3F-04\n")

        ctx = pipeline.claim(pdf, companion, config.destination.work_dir / "_processing")

        assert ctx.metadata == {"device_id": "MFP-3F-04"}

    def test_an_enormous_metadata_value_is_truncated_before_it_reaches_the_index(self):
        from dlpduck.metadata import MAX_VALUE_CHARS, allowlist

        kept = allowlist({"pdf_title": "A" * 100_000}, ["pdf_title"])

        assert len(kept["pdf_title"]) < MAX_VALUE_CHARS + 50
        assert kept["pdf_title"].endswith("[truncated]")


class TestHostileCompanionMetadata:
    """A companion file arrives from the same semi-trusted drop folder as
    the PDF. Whatever it does, the document itself must still be scanned —
    and the refusal must reach the audit trail, not just a log line."""

    def _config_with_xml_companion(self, tmp_path):
        return Config.model_validate(
            _config_dict(
                tmp_path,
                source={
                    "name": "t", "path": str(tmp_path / "drops"), "metadata_format": "xml",
                    "metadata_suffix": ".xml", "metadata_fields": ["device_id"],
                },
            )
        )

    def test_an_xml_entity_bomb_is_refused_and_audited(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = self._config_with_xml_companion(tmp_path)
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "doc.pdf", ["ordinary content"])
        companion = tmp_path / "doc.xml"
        companion.write_text(
            '<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY x "boom">]>\n'
            "<r><device_id>&x;</device_id></r>"
        )

        ctx = pipeline.claim(pdf, companion, config.destination.work_dir / "_processing")

        assert ctx.metadata == {}  # nothing from the hostile companion
        rejected = [e for e in _audit(pipeline) if e["event"] == "metadata.rejected"]
        assert rejected and "DOCTYPE" in rejected[0]["error"]

    def test_the_document_is_still_processed_normally(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = self._config_with_xml_companion(tmp_path)
        pipeline = Pipeline(config)
        pdf = _pdf(tmp_path / "doc.pdf", ["Card 4111 1111 1111 1111 on file"])
        companion = tmp_path / "doc.xml"
        companion.write_text("<<< not xml at all")

        ctx = pipeline.run_job(pdf, companion, config.destination.work_dir / "_processing")

        # A broken companion must not stop the DLP scan — that is the part
        # that matters.
        assert ctx.disposition == "quarantine"
        assert any(h.rule_id == "pan.generic" for h in ctx.hits)


class TestCrashRecoveryHandlesCompanions:
    """resume_staged re-reads whatever was staged alongside the PDF, so it
    needs the same bounds and the same tolerance as the claim path."""

    def _staged_job(self, tmp_path, config, companion_text: str, suffix=".txt"):
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        pdf = _pdf(tmp_path / "doc.pdf", ["ordinary content"])
        job_dir = staging / content_job_id(pdf.read_bytes())
        job_dir.mkdir(parents=True)
        (job_dir / "document.pdf").write_bytes(pdf.read_bytes())
        (job_dir / f"meta{suffix}").write_text(companion_text)
        return pipeline, staging

    def test_a_staged_companion_is_read_back(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(
            _config_dict(
                tmp_path,
                source={
                    "name": "t", "path": str(tmp_path / "drops"), "metadata_format": "text",
                    "metadata_suffix": ".txt", "metadata_fields": ["device_id"],
                },
            )
        )
        pipeline, staging = self._staged_job(tmp_path, config, "device_id=MFP-9\n")

        [ctx] = pipeline.resume_staged(staging)

        assert ctx.metadata == {"device_id": "MFP-9"}

    def test_an_oversized_staged_companion_is_ignored_not_read(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(
            _config_dict(
                tmp_path,
                limits={"max_metadata_bytes": 100},
                source={
                    "name": "t", "path": str(tmp_path / "drops"), "metadata_format": "text",
                    "metadata_suffix": ".txt", "metadata_fields": ["device_id"],
                },
            )
        )
        pipeline, staging = self._staged_job(
            tmp_path, config, "device_id=MFP-9\n" + "padding=" + "A" * 5000
        )

        [ctx] = pipeline.resume_staged(staging)

        assert ctx.metadata == {}
        assert ctx.disposition == "archive"  # the document still completed

    def test_an_unparseable_staged_companion_does_not_stop_recovery(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        config = Config.model_validate(
            _config_dict(
                tmp_path,
                source={
                    "name": "t", "path": str(tmp_path / "drops"), "metadata_format": "json",
                    "metadata_suffix": ".json", "metadata_fields": ["device_id"],
                },
            )
        )
        pipeline, staging = self._staged_job(tmp_path, config, "{not json", suffix=".json")

        [ctx] = pipeline.resume_staged(staging)

        assert ctx.disposition == "archive"
        assert ctx.metadata == {}
