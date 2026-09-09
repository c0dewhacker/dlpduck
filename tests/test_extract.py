import pymupdf
import pytest

from dlpduck.extract import LineExtractor, _Box
from dlpduck.types import EncryptedDocument, PageTooLarge


@pytest.fixture(scope="module")
def extractor():
    # Loads real ONNX models — module-scoped so it happens once per file.
    return LineExtractor(dpi=150)


class TestRowClustering:
    """The v1 bug: sorting OCR boxes purely by top-left Y interleaves
    side-by-side boxes, so a form's label and its value land on different
    "lines" and no rule spanning the pair can ever match.
    """

    def test_side_by_side_boxes_join_into_one_row(self):
        boxes = [
            _Box(x0=20, cy=50, height=20, text="Account No.", score=0.99),
            _Box(x0=300, cy=51, height=20, text="12-34-56", score=0.99),
        ]
        rows = LineExtractor._cluster_rows(boxes)
        assert rows == ["Account No. 12-34-56"]

    def test_vertically_separated_boxes_stay_on_separate_rows(self):
        boxes = [
            _Box(x0=20, cy=50, height=20, text="First row", score=0.99),
            _Box(x0=20, cy=120, height=20, text="Second row", score=0.99),
        ]
        rows = LineExtractor._cluster_rows(boxes)
        assert rows == ["First row", "Second row"]

    def test_left_to_right_order_within_a_row_is_preserved_regardless_of_input_order(self):
        boxes = [
            _Box(x0=300, cy=50, height=20, text="second", score=0.99),
            _Box(x0=20, cy=51, height=20, text="first", score=0.99),
        ]
        rows = LineExtractor._cluster_rows(boxes)
        assert rows == ["first second"]

    def test_a_table_row_with_three_columns_stays_together(self):
        boxes = [
            _Box(x0=20, cy=50, height=18, text="Item", score=0.99),
            _Box(x0=200, cy=52, height=18, text="Qty", score=0.99),
            _Box(x0=350, cy=49, height=18, text="Price", score=0.99),
        ]
        rows = LineExtractor._cluster_rows(boxes)
        assert rows == ["Item Qty Price"]


class TestNativeVsOcrDecision:
    """v1's _has_native_text() decided for the WHOLE document from any one
    page holding >20 chars — a cover sheet with native text followed by
    scanned pages meant pages 2..N were silently unscanned. The decision
    must be per page.
    """

    def test_native_text_page_is_extracted_without_ocr(self, extractor):
        doc = pymupdf.open()
        page = doc.new_page(width=595, height=842)
        page.insert_text((40, 40), "This is plain native PDF text content.")
        pdf_bytes = doc.tobytes()

        result = extractor.extract(pdf_bytes)
        assert result.page_count == 1
        assert result.ocr_page_count == 0
        assert any("native PDF text" in ln.text for ln in result.lines)
        assert all(ln.source == "native" for ln in result.lines)

    def test_image_only_page_falls_back_to_ocr(self, extractor):
        doc = pymupdf.open()
        page = doc.new_page(width=400, height=200)
        page.insert_text((20, 60), "Rasterized Only", fontsize=20)
        pix = page.get_pixmap(dpi=150)
        img_doc = pymupdf.open()
        img_page = img_doc.new_page(width=pix.width, height=pix.height)
        img_page.insert_image(img_page.rect, pixmap=pix)
        pdf_bytes = img_doc.tobytes()

        result = extractor.extract(pdf_bytes)
        assert result.page_count == 1
        assert result.ocr_page_count == 1
        assert result.lines  # OCR found something
        assert all(ln.source == "ocr" for ln in result.lines)
        assert all(ln.confidence is not None for ln in result.lines)

    def test_mixed_document_extracts_both_pages_correctly(self, extractor):
        # This is the exact v1 bug scenario: native cover page + scanned
        # body page. Page 2 must NOT be silently dropped.
        doc = pymupdf.open()
        native_page = doc.new_page(width=595, height=842)
        native_page.insert_text((40, 40), "Native cover sheet with plenty of real text content.")

        raster_source = pymupdf.open()
        rp = raster_source.new_page(width=400, height=200)
        rp.insert_text((20, 60), "Scanned Body Page", fontsize=20)
        pix = rp.get_pixmap(dpi=150)
        img_page = doc.new_page(width=pix.width, height=pix.height)
        img_page.insert_image(img_page.rect, pixmap=pix)

        pdf_bytes = doc.tobytes()
        result = extractor.extract(pdf_bytes)

        assert result.page_count == 2
        assert result.ocr_page_count == 1  # only page 2, not both
        page1_lines = [ln for ln in result.lines if ln.page_number == 1]
        page2_lines = [ln for ln in result.lines if ln.page_number == 2]
        assert page1_lines and all(ln.source == "native" for ln in page1_lines)
        assert page2_lines and all(ln.source == "ocr" for ln in page2_lines)

    def test_line_numbers_are_document_global_and_page_relative_indices_reset(self, extractor):
        doc = pymupdf.open()
        for i in range(2):
            page = doc.new_page(width=595, height=842)
            page.insert_text((40, 40), f"Page {i} first native line of real text.")
            page.insert_text((40, 60), f"Page {i} second native line of real text.")
        result = extractor.extract(doc.tobytes())

        assert [ln.line_number for ln in result.lines] == [0, 1, 2, 3]
        assert [ln.line_on_page for ln in result.lines] == [0, 1, 0, 1]

    def test_encrypted_pdf_raises(self, extractor):
        doc = pymupdf.open()
        doc.new_page().insert_text((40, 40), "secret")
        doc.save("/tmp/dlpduck-test-encrypted.pdf", encryption=pymupdf.PDF_ENCRYPT_AES_256,
                  user_pw="hunter2", owner_pw="hunter2admin")
        pdf_bytes = open("/tmp/dlpduck-test-encrypted.pdf", "rb").read()

        with pytest.raises(EncryptedDocument):
            extractor.extract(pdf_bytes)


class TestOversizedPagesAreClamped:
    """A PDF declares its own page size, so a hostile or broken one can ask
    for a page metres across. Rasterising that at the configured dpi
    allocates a bitmap of hundreds of megapixels — a decompression bomb by
    another name. The dpi is scaled down for that page rather than the
    page being refused, so a genuinely large plan drawing still gets read.
    """

    def test_an_ordinary_page_uses_the_configured_dpi(self):
        extractor = LineExtractor(dpi=150)
        doc = pymupdf.open()
        page = doc.new_page(width=595, height=842)  # A4
        assert extractor._safe_dpi(page) == 150

    def test_a_large_page_is_scaled_down_rather_than_refused(self):
        """A genuinely big plan drawing still gets read, just coarsely."""
        extractor = LineExtractor(dpi=150)
        doc = pymupdf.open()
        # 50 inches square: 5,625MP at 150 dpi, but it fits at a lower one.
        page = doc.new_page(width=50 * 72, height=50 * 72)
        safe = extractor._safe_dpi(page)

        assert extractor.MIN_DPI <= safe < 150
        assert 50 * 50 * safe * safe <= extractor.MAX_RASTER_PIXELS

    def test_the_raster_never_exceeds_the_cap_at_any_page_size(self):
        """The regression that motivated PageTooLarge: clamping to a dpi
        floor and rasterising anyway defeated the cap entirely — a
        200-inch page was still 52MP, a 20,000-inch one half a trillion
        pixels."""
        extractor = LineExtractor(dpi=150)
        doc = pymupdf.open()
        for inches in (50, 100, 200, 500, 2000, 20000):
            page = doc.new_page(width=inches * 72, height=inches * 72)
            try:
                safe = extractor._safe_dpi(page)
            except PageTooLarge:
                continue  # refused, so nothing is allocated
            pixels = inches * inches * safe * safe
            assert pixels <= extractor.MAX_RASTER_PIXELS * 1.01, (inches, safe, pixels)

    def test_a_page_that_cannot_fit_even_at_the_floor_is_refused(self):
        extractor = LineExtractor(dpi=150)
        doc = pymupdf.open()
        page = doc.new_page(width=20000 * 72, height=20000 * 72)
        with pytest.raises(PageTooLarge):
            extractor._safe_dpi(page)

    def test_a_refused_page_degrades_the_document_rather_than_crashing(self):
        """extract() already treats a page it cannot read as degraded,
        which quarantines the document — fail closed, not fall over."""
        extractor = LineExtractor(dpi=150)
        doc = pymupdf.open()
        doc.new_page(width=20000 * 72, height=20000 * 72)  # no text layer -> OCR path
        buf = doc.tobytes()

        result = extractor.extract(buf)

        assert result.degraded is True
        assert result.lines == []

    def test_a_zero_sized_page_does_not_divide_by_zero(self):
        extractor = LineExtractor(dpi=150)
        doc = pymupdf.open()
        page = doc.new_page(width=1, height=1)
        assert extractor._safe_dpi(page) == 150


class TestRowClusteringEdges:
    """§5.2's row clustering is what makes a form's label and its value
    land on the same line, so a rule spanning the pair can match. The
    happy paths are covered above; these are the shapes real OCR output
    actually takes.
    """

    cluster = staticmethod(LineExtractor._cluster_rows)

    def test_no_boxes_yields_no_rows(self):
        assert self.cluster([]) == []

    def test_a_single_box_is_a_single_row(self):
        assert self.cluster([_Box(x0=10, cy=10, height=12, text="alone", score=1.0)]) == ["alone"]

    def test_boxes_arriving_bottom_to_top_are_still_ordered(self):
        boxes = [
            _Box(x0=0, cy=100, height=20, text="lower", score=1.0),
            _Box(x0=0, cy=20, height=20, text="upper", score=1.0),
        ]
        assert self.cluster(boxes) == ["upper", "lower"]

    def test_zero_height_boxes_fall_back_to_a_usable_tolerance(self):
        """Some engines report a degenerate bbox; the median-height
        tolerance must not become zero and split every word."""
        boxes = [
            _Box(x0=0, cy=10, height=0, text="a", score=1.0),
            _Box(x0=50, cy=10, height=0, text="b", score=1.0),
        ]
        assert self.cluster(boxes) == ["a b"]

    def test_drift_does_not_swallow_the_page_into_one_row(self):
        """Anchoring on the row's FIRST box, not its last, is what stops a
        long run of slightly-descending boxes merging into one line."""
        drifting = [
            _Box(x0=i * 40, cy=10 + i * 3, height=20, text=f"w{i}", score=1.0)
            for i in range(12)
        ]
        rows = self.cluster(drifting)
        assert len(rows) > 1, "drift accumulated into a single row"
        assert " ".join(rows).split() == [f"w{i}" for i in range(12)]  # nothing lost

    def test_a_tall_heading_beside_body_text_does_not_split_the_line(self):
        boxes = [
            _Box(x0=0, cy=50, height=40, text="TOTAL", score=1.0),
            _Box(x0=200, cy=52, height=14, text="£1,240.00", score=1.0),
        ]
        assert self.cluster(boxes) == ["TOTAL £1,240.00"]

    def test_rows_far_apart_never_merge_however_wide_the_page(self):
        boxes = [
            _Box(x0=0, cy=10, height=12, text="header", score=1.0),
            _Box(x0=900, cy=10, height=12, text="page 1", score=1.0),
            _Box(x0=0, cy=800, height=12, text="footer", score=1.0),
        ]
        assert self.cluster(boxes) == ["header page 1", "footer"]

    def test_every_box_appears_exactly_once(self):
        """Whatever the clustering decides, no text may be dropped or
        duplicated — a lost box is a rule that silently cannot match."""
        import random

        rng = random.Random(20260904)
        boxes = [
            _Box(
                x0=rng.uniform(0, 600),
                cy=rng.uniform(0, 800),
                height=rng.choice([10, 14, 20, 30]),
                text=f"t{i}",
                score=1.0,
            )
            for i in range(200)
        ]
        words = " ".join(self.cluster(boxes)).split()
        assert sorted(words) == sorted(f"t{i}" for i in range(200))

    def test_reading_order_is_top_to_bottom_then_left_to_right(self):
        boxes = [
            _Box(x0=300, cy=200, height=12, text="d", score=1.0),
            _Box(x0=10, cy=200, height=12, text="c", score=1.0),
            _Box(x0=300, cy=20, height=12, text="b", score=1.0),
            _Box(x0=10, cy=20, height=12, text="a", score=1.0),
        ]
        assert self.cluster(boxes) == ["a b", "c d"]
