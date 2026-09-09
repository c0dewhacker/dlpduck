"""The path the product exists for: a scanned document with no text layer,
read by OCR, judged by the rule engine, and routed accordingly.

Every other test builds PDFs that already carry a native text layer, which
means they exercise the extractor's fast path and stub out the slow one.
That leaves the headline claim — "we OCR scans and catch sensitive data in
them" — resting on unit tests of the pieces. These run the real RapidOCR
model over a real rasterised page, so they are slower than the rest of the
suite and deliberately few.
"""

from pathlib import Path

import pypdfium2 as pdfium
import pytest

from dlpduck.config import Config
from dlpduck.extract import LineExtractor
from dlpduck.pipeline import Pipeline
from tests.pdf_factory import image_only_pdf

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


def _scanned_pdf(path: Path, lines: list[str], dpi: int = 200) -> Path:
    """A PDF containing only an image of text — exactly what an MFP
    produces, and what every other test in the suite avoids."""
    path.write_bytes(image_only_pdf(lines, dpi=dpi))
    return path


@pytest.fixture(scope="module")
def extractor():
    return LineExtractor(dpi=150)


class TestScannedDocumentsAreRead:
    def test_a_page_with_no_text_layer_goes_through_ocr(self, tmp_path, extractor):
        pdf = _scanned_pdf(tmp_path / "scan.pdf", ["Card 4111 1111 1111 1111"])
        # Precondition: there really is nothing for the native path to find.
        with pdfium.PdfDocument(pdf) as document:
            page = document[0]
            text_page = page.get_textpage()
            try:
                assert not text_page.get_text_bounded().strip()
            finally:
                text_page.close()
                page.close()

        text = extractor.extract(pdf.read_bytes())

        assert text.ocr_page_count == 1
        assert text.degraded is False
        assert all(line.source == "ocr" for line in text.lines)

    def test_ocr_confidence_is_recorded(self, tmp_path, extractor):
        pdf = _scanned_pdf(tmp_path / "scan.pdf", ["Card 4111 1111 1111 1111"])
        text = extractor.extract(pdf.read_bytes())

        assert text.min_ocr_confidence is not None
        assert 0.0 < text.min_ocr_confidence <= 1.0

    def test_lines_keep_their_page_and_position(self, tmp_path, extractor):
        pdf = _scanned_pdf(
            tmp_path / "scan.pdf", ["First line here", "Card 4111 1111 1111 1111"]
        )
        text = extractor.extract(pdf.read_bytes())

        assert len(text.lines) >= 2
        assert [line.page_number for line in text.lines] == [1] * len(text.lines)
        assert [line.line_on_page for line in text.lines] == list(range(len(text.lines)))


class TestScannedSensitiveDataIsCaught:
    """The end-to-end claim: drop a scan containing a card number and the
    document is quarantined on the strength of OCR alone."""

    @pytest.fixture
    def config(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        src = tmp_path / "drops"
        src.mkdir()
        return Config.model_validate(
            {
                "source": {"name": "mfp", "path": str(src), "metadata_format": "none"},
                "destination": {
                    "archive": str(tmp_path / "archive"),
                    "quarantine": str(tmp_path / "quarantine"),
                    "work_dir": str(tmp_path / "work"),
                },
                "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
            }
        )

    def test_a_scanned_card_number_quarantines_the_document(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _scanned_pdf(tmp_path / "scan.pdf", ["Card 4111 1111 1111 1111"])

        ctx = pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")

        assert ctx.disposition == "quarantine"
        assert any(h.rule_id == "pan.generic" for h in ctx.hits)
        assert list(config.destination.quarantine.glob("dt=*/*.pdf"))

    def test_the_hit_from_a_scan_is_masked_like_any_other(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _scanned_pdf(tmp_path / "scan.pdf", ["Card 4111 1111 1111 1111"])

        ctx = pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")

        [hit] = [h for h in ctx.hits if h.rule_id == "pan.generic"]
        assert "•" in hit.masked_text
        assert "4111" not in hit.masked_text
        assert hit.match_hmac  # correlatable without the value

    def test_a_clean_scan_is_archived(self, tmp_path, config):
        pipeline = Pipeline(config)
        pdf = _scanned_pdf(tmp_path / "clean.pdf", ["Minutes of the monthly meeting"])

        ctx = pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")

        assert ctx.disposition == "archive"
        assert list(config.destination.archive.glob("dt=*/*.pdf"))

    def test_the_scanned_text_is_searchable_afterwards(self, tmp_path, config):
        """OCR output has to reach the content store, or a scan is
        invisible to search — which is most of what an archive is for."""
        from dlpduck.search import search

        pipeline = Pipeline(config)
        pdf = _scanned_pdf(tmp_path / "scan.pdf", ["Minutes of the monthly meeting"])
        pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")

        response = search(pipeline.content_root, pipeline.index_root, "monthly")

        assert len(response.results) == 1
