"""Extract native PDF text or use RapidOCR, selected independently per page.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import pypdfium2 as pdfium
from pypdfium2 import raw as pdfium_c
from rapidocr_onnxruntime import RapidOCR

from dlpduck.pdfium import PDFIUM_LOCK, is_password_error, open_document
from dlpduck.types import DocumentText, EncryptedDocument, PageTooLarge, TextLine, TooManyPages

logger = logging.getLogger("dlpduck.extract")


@dataclass
class _Box:
    x0: float
    cy: float
    height: float
    text: str
    score: float | None  # OCR confidence; None for a native text run
    x1: float = 0.0
    top: float = 0.0
    bottom: float = 0.0


@dataclass(frozen=True)
class _Row:
    text: str
    source: str  # "native" | "ocr"
    confidence: float | None


@dataclass(frozen=True)
class _PageResult:
    rows: list[_Row]
    kind: str  # "native" | "ocr" | "mixed" | "blank"
    confidence: float | None  # mean OCR confidence over the page, if OCR ran


class LineExtractor:
    NATIVE_MIN_CHARS = 20  # per page; this used to be per document
    # A PDF declares its own page size, so a hostile (or just broken) one
    # can ask for a page metres across. Rasterising that at the configured
    # dpi would allocate a bitmap of hundreds of megapixels — a decompression
    # bomb by another name. Scale the dpi down for the offending page so a
    # genuinely large plan drawing still gets read, just coarsely — and
    # refuse the page outright if it cannot fit even at MIN_DPI, rather
    # than clamping to a floor and allocating the bitmap anyway.
    MAX_RASTER_PIXELS = 40_000_000  # ~40MP, about 120MB of RGB pixels
    MIN_DPI = 36  # below this OCR is worthless anyway — refuse instead

    # A page OCR reads nothing from is degraded — unless it is genuinely
    # blank. "Genuinely" is measured, not assumed: at most this fraction of
    # the rendered page may be dark. The default is deliberately tight —
    # about 200 pixels on an A4 page at 150 dpi, less ink than a nine-digit
    # identifier — so a page carrying a short value OCR failed to read still
    # fails closed; it exists for the blank backs of duplex scans, which
    # used to quarantine every such document as degraded. 0 restores the old
    # behaviour of treating every empty page as degraded.
    BLANK_MAX_INK = 0.0001
    _INK_LEVEL = 128  # a pixel darker than this (0-255) counts as ink

    def __init__(
        self,
        dpi: int = 150,
        *,
        isolate: bool = False,
        timeout: float = 120,
        max_pages: int | None = None,
        memory_mb: int | None = None,
        blank_max_ink: float | None = None,
    ):
        self.dpi = dpi
        if blank_max_ink is not None:
            self.BLANK_MAX_INK = blank_max_ink
        self.isolate = isolate
        self.timeout = timeout
        # Checked on open, before any page is rendered, and inside the
        # worker when isolated — counting pages means parsing the PDF,
        # which is exactly the work that must not happen in the daemon.
        self.max_pages = max_pages
        self.memory_mb = memory_mb
        # One page per worker process at the pipeline level — stop
        # ONNXRuntime grabbing every core inside every worker and fighting
        # the pool for them.
        self._ocr: RapidOCR | None = None

    def extract(self, pdf_bytes: bytes) -> DocumentText:
        if self.isolate:
            from dlpduck.extract_worker import extract_isolated

            return extract_isolated(
                pdf_bytes, self.dpi, self.NATIVE_MIN_CHARS, self.timeout,
                max_pages=self.max_pages, memory_mb=self.memory_mb,
                blank_max_ink=self.BLANK_MAX_INK,
            )
        return self._extract(pdf_bytes)

    def _extract(self, pdf_bytes: bytes) -> DocumentText:
        with PDFIUM_LOCK:
            try:
                document = open_document(pdf_bytes)
            except pdfium.PdfiumError as exc:
                if is_password_error(exc):
                    raise EncryptedDocument() from None
                raise

            with document:
                if self.max_pages is not None and len(document) > self.max_pages:
                    raise TooManyPages(len(document))
                out = DocumentText(page_count=len(document))
                n = 0
                for idx in range(len(document)):
                    page = document[idx]
                    try:
                        result = self._page_rows(page)
                    except Exception:
                        logger.debug("page %d failed to extract", idx + 1, exc_info=True)
                        out.degraded = True  # -> quarantine, never silently drop a page
                        out.failed_page_count += 1
                        continue
                    finally:
                        page.close()
                    rows = result.rows
                    if result.kind == "blank":
                        out.blank_page_count += 1
                    elif not rows:
                        out.degraded = True
                    if result.kind in ("ocr", "mixed", "blank"):
                        out.ocr_page_count += 1
                    logger.debug(
                        "page %d: %s, %d line(s)%s",
                        idx + 1, result.kind, len(rows),
                        f", confidence={result.confidence:.2f}"
                        if result.confidence is not None else "",
                    )
                    for on_page, row in enumerate(rows):
                        out.add_line(
                            TextLine(
                                line_number=n,
                                page_number=idx + 1,
                                line_on_page=on_page,
                                lines_on_page=len(rows),
                                text=row.text,
                                source=row.source,
                                confidence=row.confidence,
                            )
                        )
                        n += 1
                return out

    def _safe_dpi(self, page) -> int:
        """The configured dpi, reduced so this page fits MAX_RASTER_PIXELS.

        Raises PageTooLarge when it cannot fit even at MIN_DPI. Clamping to
        a floor and rasterising anyway would defeat the cap entirely: a
        200-inch page at the floor is still 52 megapixels, and a
        20,000-inch one is half a trillion — which is precisely the bomb
        the cap exists to stop. A page that cannot be rendered safely is a
        page that cannot be read, and extract() already treats that as
        degraded, which quarantines the document. Failing closed on a
        page nobody can OCR beats allocating a terabyte to prove it.
        """
        width, height = page.get_size()
        width_in = max(width, 1) / 72
        height_in = max(height, 1) / 72
        pixels = width_in * height_in * self.dpi * self.dpi
        if pixels <= self.MAX_RASTER_PIXELS:
            return self.dpi
        scale = (self.MAX_RASTER_PIXELS / pixels) ** 0.5
        reduced = int(self.dpi * scale)
        if reduced < self.MIN_DPI:
            raise PageTooLarge(
                f"page is {width_in:.0f}x{height_in:.0f}in — cannot be rasterised "
                f"under {self.MAX_RASTER_PIXELS} pixels without dropping below "
                f"{self.MIN_DPI} dpi"
            )
        return reduced

    def _page_rows(self, page) -> _PageResult:
        text_page = page.get_textpage()
        try:
            native = [
                line.strip() for line in text_page.get_text_bounded().splitlines() if line.strip()
            ]
            # Positioned native runs, for a page that also has images: those
            # rows have to be interleaved with what OCR finds in the images.
            native_boxes = self._native_boxes(page, text_page)
        finally:
            text_page.close()
        # PDFium reports bounded text bottom-to-top for quarter-turn pages.
        # Restore the content order used by unrotated and other rotated pages.
        rotation = page.get_rotation()
        if rotation == 90:
            native.reverse()
        has_images = any(page.get_objects(filter=[pdfium_c.FPDF_PAGEOBJ_IMAGE]))
        enough_native = sum(len(line) for line in native) >= self.NATIVE_MIN_CHARS
        if enough_native and not has_images:
            return _PageResult([_Row(t, "native", None) for t in native], "native", None)

        scale = self._safe_dpi(page) / 72
        bitmap = page.render(scale=scale)
        if self._ocr is None:
            self._ocr = RapidOCR(intra_op_num_threads=1, inter_op_num_threads=1)
        try:
            pixels = bitmap.to_numpy()
            result, _ = self._ocr(pixels)
            ink = self._ink_ratio(pixels) if not result else None
        finally:
            bitmap.close()

        ocr_boxes = [
            _Box(
                x0=min(p[0] for p in bbox) / scale,
                x1=max(p[0] for p in bbox) / scale,
                top=min(p[1] for p in bbox) / scale,
                bottom=max(p[1] for p in bbox) / scale,
                cy=sum(p[1] for p in bbox) / 4 / scale,
                height=(max(p[1] for p in bbox) - min(p[1] for p in bbox)) / scale,
                text=txt,
                score=score,
            )
            for bbox, txt, score in (result or [])
        ]
        conf = sum(b.score or 0.0 for b in ocr_boxes) / len(ocr_boxes) if ocr_boxes else None

        # A page with real native text AND images: keep the native text —
        # exact, where OCR of the same glyphs is an approximation — and
        # add only what OCR read from outside it, i.e. text that lives in
        # the images. This used to discard the native layer entirely and
        # rely on OCR for the whole page, so a logo on a letterhead was
        # enough to downgrade every line to an OCR guess.
        if enough_native and native_boxes and rotation == 0:
            extra = [b for b in ocr_boxes if not any(_overlaps(b, n) for n in native_boxes)]
            rows = self._cluster(native_boxes + extra)
            return _PageResult(rows, "mixed" if extra else "native", conf if extra else None)

        if not ocr_boxes:
            if ink is not None and self.BLANK_MAX_INK > 0 and ink <= self.BLANK_MAX_INK:
                return _PageResult([], "blank", None)
            return _PageResult([], "ocr", None)
        return _PageResult(
            [_Row(t, "ocr", conf) for t in self._cluster_rows(ocr_boxes)], "ocr", conf
        )

    @staticmethod
    def _native_boxes(page, text_page) -> list[_Box]:
        """Native text runs with their positions, in top-down page points
        (the same orientation as a rendered bitmap)."""
        height = page.get_size()[1]
        boxes = []
        for index in range(text_page.count_rects()):
            left, bottom, right, top = text_page.get_rect(index)
            text = text_page.get_text_bounded(left, bottom, right, top).strip()
            if not text:
                continue
            boxes.append(
                _Box(
                    x0=left, x1=right, top=height - top, bottom=height - bottom,
                    cy=height - (top + bottom) / 2, height=top - bottom, text=text, score=None,
                )
            )
        return boxes

    def _ink_ratio(self, pixels) -> float:
        gray = pixels.mean(axis=2) if pixels.ndim == 3 else pixels
        return float((gray < self._INK_LEVEL).mean())

    def _cluster(self, boxes: list[_Box]) -> list[_Row]:
        """Rows from a mix of native and OCR boxes. A row is native only if
        every part of it is; otherwise it is an OCR row carrying the mean
        confidence of its OCR parts."""
        rows = []
        for row in self._group(boxes):
            scores = [b.score for b in row if b.score is not None]
            text = " ".join(b.text for b in sorted(row, key=lambda b: b.x0)).strip()
            if scores:
                rows.append(_Row(text, "ocr", sum(scores) / len(scores)))
            else:
                rows.append(_Row(text, "native", None))
        return rows

    @staticmethod
    def _cluster_rows(boxes: list[_Box], tol_ratio: float = 0.5) -> list[str]:
        """Group boxes into visual rows, then order left-to-right within
        each row.

        A pure top-edge sort interleaves side-by-side boxes, so a form's
        label and its value land on different "lines" and no rule spanning
        the pair can ever match.
        """
        return [
            " ".join(b.text for b in sorted(row, key=lambda b: b.x0)).strip()
            for row in LineExtractor._group(boxes, tol_ratio)
        ]

    @staticmethod
    def _group(boxes: list[_Box], tol_ratio: float = 0.5) -> list[list[_Box]]:
        if not boxes:
            # The indexing below assumes a first box, and a caller that
            # doesn't know that shouldn't get an IndexError.
            return []

        heights = sorted(b.height for b in boxes if b.height > 0) or [12.0]
        # Positions are in page points (≈2 px at 150 dpi).
        tol = max(2.0, heights[len(heights) // 2] * tol_ratio)

        ordered = sorted(boxes, key=lambda b: b.cy)
        rows: list[list[_Box]] = []
        current = [ordered[0]]
        for b in ordered[1:]:
            # Anchor on the row's first box, not the last, to avoid drift
            # accumulating across a long row of nearly-aligned boxes.
            if b.cy - current[0].cy <= tol:
                current.append(b)
            else:
                rows.append(current)
                current = [b]
        rows.append(current)
        return rows


def _overlaps(a: _Box, b: _Box) -> bool:
    """Do two boxes cover substantially the same area? Used to drop OCR
    output that merely re-reads native text. Measured against the smaller
    of the two: an OCR box is padded well beyond the glyph extents PDFium
    reports for the same run, so "half of the OCR box" missed real
    re-reads and duplicated the line."""
    width = min(a.x1, b.x1) - max(a.x0, b.x0)
    height = min(a.bottom, b.bottom) - max(a.top, b.top)
    if width <= 0 or height <= 0:
        return False
    smaller = max(
        min((a.x1 - a.x0) * (a.bottom - a.top), (b.x1 - b.x0) * (b.bottom - b.top)), 1e-6
    )
    return width * height / smaller > 0.5
