from __future__ import annotations

import pymupdf
import pytest


@pytest.fixture
def hmac_key() -> bytes:
    return b"test-key-not-for-production"


def make_pdf(pages: list[list[str]], font_size: float = 11) -> bytes:
    """Build a simple native-text PDF: one list of lines per page, each
    line placed at an increasing y so PyMuPDF's own line extraction (not
    OCR) is exercised.
    """
    doc = pymupdf.open()
    for lines in pages:
        page = doc.new_page(width=595, height=842)
        y = 40
        for line in lines:
            page.insert_text((40, y), line, fontsize=font_size)
            y += 20
    return doc.tobytes()


@pytest.fixture
def pdf_factory():
    return make_pdf
