"""Documents that are broken, hostile, or merely awkward.

A real corpus cannot be synthesised — a decade-old MFP emits things nobody
would think to write down. What can be pinned is the shape of the
guarantee: every one of these either produces a trustworthy reading or
lands somewhere safe. Nothing here may end up in the clean archive on the
strength of an extraction that did not happen.
"""

from pathlib import Path

import pytest

from dlpduck.config import Config
from dlpduck.extract import LineExtractor
from dlpduck.pipeline import Pipeline
from tests.pdf_factory import image_only_pdf, join_pdfs, make_pdf, rotate_pdf

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
    src = tmp_path / "drops"
    src.mkdir()
    return Config.model_validate(
        {
            "source": {"name": "t", "path": str(src), "metadata_format": "none"},
            "destination": {
                "archive": str(tmp_path / "archive"),
                "quarantine": str(tmp_path / "quarantine"),
                "work_dir": str(tmp_path / "work"),
            },
            "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
        }
    )


def _drop(config, name: str, data: bytes) -> Path:
    path = config.source.path / name
    path.write_bytes(data)
    return path


def _run(config, name: str, data: bytes):
    pipeline = Pipeline(config)
    return pipeline, pipeline.run_job(
        _drop(config, name, data), None, config.destination.work_dir / "_processing"
    )


def _ordinary_pdf(text: str = "an ordinary memo") -> bytes:
    return make_pdf([[text]])


def _image_only_pdf(fill: int | None = None, text: str | None = None) -> bytes:
    """A page with no text layer. `fill` paints featureless grey — a scan
    OCR cannot read; `text` rasterises real words."""
    return image_only_pdf([text] if text is not None else None, fill=200 if fill is None else fill)


class TestNothingUnreadableReachesTheCleanArchive:
    """The regression this module exists for: a document nobody could read
    used to be archived as clean, because zero extracted lines produce zero
    hits and zero hits read as 'nothing to see'."""

    def test_an_unreadable_scan_is_quarantined_not_archived(self, config):
        _, ctx = _run(config, "unreadable.pdf", _image_only_pdf(fill=200))

        assert ctx.text.lines == []
        assert ctx.disposition == "quarantine"
        assert ctx.reason == "no_text_extracted"
        assert not list(config.destination.archive.glob("dt=*/*.pdf"))

    def test_the_reason_distinguishes_it_from_a_page_that_errored(self, config):
        """'we read nothing' and 'a page threw' are different diagnoses and
        an operator triaging quarantine needs to tell them apart."""
        _, ctx = _run(config, "unreadable.pdf", _image_only_pdf(fill=255))
        assert ctx.reason == "no_text_extracted"

        _, other = _run(config, "garbage.pdf", b"GIF89a definitely not a pdf")
        assert other.reason.startswith("extraction_error:")
        assert other.disposition == "failed"

    def test_an_install_can_opt_out_deliberately(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        src = tmp_path / "drops"
        src.mkdir()
        config = Config.model_validate(
            {
                "source": {"name": "t", "path": str(src), "metadata_format": "none"},
                "destination": {
                    "archive": str(tmp_path / "archive"),
                    "quarantine": str(tmp_path / "quarantine"),
                    "work_dir": str(tmp_path / "work"),
                },
                "dlp": {
                    "quarantine_on_degraded": False,
                    "rules": [{"include": str(DEFAULT_RULES_PATH)}],
                },
            }
        )
        _, ctx = _run(config, "unreadable.pdf", _image_only_pdf(fill=200))

        assert ctx.disposition == "archive"  # the operator asked for this

    def test_a_readable_scan_is_still_judged_on_its_contents(self, config):
        """The guard must not swallow scans that OCR can read."""
        _, ctx = _run(config, "readable.pdf", _image_only_pdf(text="just a meeting note"))

        assert ctx.text.lines  # OCR found something
        assert ctx.disposition == "archive"
        assert ctx.reason is None


class TestStructurallyBrokenFilesLandSomewhereSafe:
    @pytest.mark.parametrize(
        "name,data",
        [
            ("empty.pdf", b""),
            ("header-only.pdf", b"%PDF-1.7\n"),
            ("not-a-pdf.pdf", b"GIF89a this is not a pdf at all"),
            ("truncated.pdf", _ordinary_pdf()[: len(_ordinary_pdf()) // 3]),
            ("nul-bytes.pdf", b"\x00" * 4096),
        ],
    )
    def test_a_broken_file_never_lands_in_the_archive(self, config, name, data):
        _, ctx = _run(config, name, data)

        assert ctx.disposition in {"failed", "quarantine"}, ctx.disposition
        assert not list(config.destination.archive.glob("dt=*/*.pdf"))

    def test_a_broken_file_is_recorded_rather_than_silently_dropped(self, config):
        import json

        pipeline, ctx = _run(config, "empty.pdf", b"")

        events = []
        for log in pipeline.audit.root.glob("dt=*/events.jsonl"):
            events += [json.loads(x) for x in log.read_text().splitlines() if x.strip()]
        assert any(e["event"] == "job.failed" for e in events)

    def test_trailing_junk_after_a_valid_document_is_harmless(self, config):
        """Not everything unusual is broken — a well-formed document with
        garbage appended still reads, and must not be quarantined for it."""
        _, ctx = _run(config, "junk-tail.pdf", _ordinary_pdf() + b"\n%%JUNK" * 200)

        assert ctx.disposition == "archive"
        assert ctx.text.lines


class TestRotatedPages:
    """A page fed sideways is ordinary MFP output. Native text is
    normalised by the parser; a scan is rasterised as displayed, so a
    correctly-marked rotation keeps its line structure."""

    @pytest.mark.parametrize("rotation", [0, 90, 180, 270])
    def test_native_text_survives_any_rotation(self, rotation):
        pdf = make_pdf(
            [["Card 4111 1111 1111 1111", "Second line of the page"]], font_size=18
        )
        text = LineExtractor().extract(rotate_pdf(pdf, rotation))

        assert [line.text for line in text.lines] == [
            "Card 4111 1111 1111 1111",
            "Second line of the page",
        ]

    @pytest.mark.parametrize("rotation", [0, 90, 180, 270])
    def test_a_rotated_document_is_still_judged(self, config, rotation):
        pdf = rotate_pdf(make_pdf([["Card 4111 1111 1111 1111"]], font_size=18), rotation)
        _, ctx = _run(config, f"rot{rotation}.pdf", pdf)

        assert ctx.disposition == "quarantine"
        assert any(h.rule_id == "pan.generic" for h in ctx.hits)


class TestMixedDocuments:
    def test_a_document_mixing_native_and_scanned_pages_reads_both(self, config):
        """Exercise mixed native and scanned page extraction end to end."""
        pdf = join_pdfs(
            make_pdf([["This page has a real text layer on it."]]),
            image_only_pdf(["Card 4111 1111 1111 1111"]),
        )
        _, ctx = _run(config, "mixed.pdf", pdf)

        sources = {line.source for line in ctx.text.lines}
        assert sources == {"native", "ocr"}, sources
        assert ctx.text.ocr_page_count == 1  # only the scanned page paid for OCR
        assert ctx.disposition == "quarantine"  # the card on page 2 was found
