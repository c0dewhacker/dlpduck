"""Extract native PDF text or use RapidOCR, selected independently per page.
"""

from __future__ import annotations

from dataclasses import dataclass

import pymupdf
from rapidocr_onnxruntime import RapidOCR

from dlpduck.types import DocumentText, EncryptedDocument, PageTooLarge, TextLine


@dataclass
class _Box:
    x0: float
    cy: float
    height: float
    text: str
    score: float


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

    def __init__(self, dpi: int = 150, *, isolate: bool = False, timeout: float = 120):
        self.dpi = dpi
        self.isolate = isolate
        self.timeout = timeout
        # One page per worker process at the pipeline level — stop
        # ONNXRuntime grabbing every core inside every worker and fighting
        # the pool for them.
        self._ocr: RapidOCR | None = None

    def extract(self, pdf_bytes: bytes) -> DocumentText:
        if self.isolate:
            from dlpduck.extract_worker import extract_isolated

            return extract_isolated(pdf_bytes, self.dpi, self.NATIVE_MIN_CHARS, self.timeout)
        return self._extract(pdf_bytes)

    def _extract(self, pdf_bytes: bytes) -> DocumentText:
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
        if doc.needs_pass:
            raise EncryptedDocument()

        out = DocumentText(page_count=len(doc))
        n = 0
        # pymupdf's Document is iterable at runtime; its stubs don't say so.
        for idx, page in enumerate(doc):  # type: ignore[arg-type, var-annotated]
            try:
                rows, source, conf = self._page_rows(page)
            except Exception:
                out.degraded = True  # -> quarantine, never silently drop a page
                out.failed_page_count += 1
                continue
            if not rows:
                out.degraded = True
            if source == "ocr":
                out.ocr_page_count += 1
            for on_page, text in enumerate(rows):
                out.add_line(
                    TextLine(
                        line_number=n,
                        page_number=idx + 1,
                        line_on_page=on_page,
                        lines_on_page=len(rows),
                        text=text,
                        source=source,
                        confidence=conf,
                    )
                )
                n += 1
        doc.close()
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
        rect = page.rect
        width_in = max(rect.width, 1) / 72
        height_in = max(rect.height, 1) / 72
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

    def _page_rows(self, page) -> tuple[list[str], str, float | None]:
        native = [t.strip() for t in page.get_text("text").splitlines() if t.strip()]
        if sum(len(t) for t in native) >= self.NATIVE_MIN_CHARS and not page.get_image_info():
            return native, "native", None

        pix = page.get_pixmap(dpi=self._safe_dpi(page))
        if self._ocr is None:
            self._ocr = RapidOCR(intra_op_num_threads=1, inter_op_num_threads=1)
        result, _ = self._ocr(pix.tobytes("png"))
        if not result:
            return [], "ocr", None

        boxes = [
            _Box(
                x0=bbox[0][0],
                cy=sum(p[1] for p in bbox) / 4,
                height=max(p[1] for p in bbox) - min(p[1] for p in bbox),
                text=txt,
                score=score,
            )
            for bbox, txt, score in result
        ]
        conf = sum(b.score for b in boxes) / len(boxes)
        return self._cluster_rows(boxes), "ocr", conf

    @staticmethod
    def _cluster_rows(boxes: list[_Box], tol_ratio: float = 0.5) -> list[str]:
        """Group boxes into visual rows, then order left-to-right within
        each row.

        A pure top-edge sort interleaves side-by-side boxes, so a form's
        label and its value land on different "lines" and no rule spanning
        the pair can ever match.
        """
        if not boxes:
            # Unreachable from _page_rows, which returns early on an empty
            # OCR result — but the indexing below assumes a first box, and
            # a caller that doesn't know that shouldn't get an IndexError.
            return []

        heights = sorted(b.height for b in boxes if b.height > 0) or [12.0]
        tol = max(4.0, heights[len(heights) // 2] * tol_ratio)

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

        return [
            " ".join(b.text for b in sorted(row, key=lambda b: b.x0)).strip()
            for row in rows
        ]
