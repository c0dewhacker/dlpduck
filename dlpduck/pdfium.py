"""Shared PDFium operations and process-local serialization."""

from __future__ import annotations

import threading

import pypdfium2 as pdfium
from pypdfium2 import raw as pdfium_c

PDFIUM_LOCK = threading.RLock()


def open_document(pdf_bytes: bytes) -> pdfium.PdfDocument:
    """Open PDF bytes and preserve password failures for callers."""
    return pdfium.PdfDocument(pdf_bytes)


def is_password_error(error: pdfium.PdfiumError) -> bool:
    return error.err_code == pdfium_c.FPDF_ERR_PASSWORD

