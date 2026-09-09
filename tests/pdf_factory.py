"""Permissively licensed PDF fixtures used across the test suite."""

from __future__ import annotations

from collections.abc import Iterable
from io import BytesIO
from pathlib import Path

import pypdfium2 as pdfium
from PIL import Image
from pypdf import PdfReader, PdfWriter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

PAGE_SIZE = (595.0, 842.0)

_METADATA_KEYS = {
    "title": "/Title",
    "author": "/Author",
    "subject": "/Subject",
    "creator": "/Creator",
    "producer": "/Producer",
    "creationDate": "/CreationDate",
    "modDate": "/ModDate",
}


def make_pdf(
    pages: list[list[str]],
    font_size: float = 11,
    *,
    page_size: tuple[float, float] = PAGE_SIZE,
) -> bytes:
    """Create a native-text PDF with one list of lines per page."""
    output = BytesIO()
    pdf = canvas.Canvas(output, pagesize=page_size, pageCompression=1)
    pdf.setTitle("")
    pdf.setAuthor("")
    pdf.setSubject("")
    pdf.setCreator("")
    pdf._doc.info.producer = ""
    width, height = page_size
    for lines in pages:
        y = height - 40
        pdf.setFont("Helvetica", font_size)
        for line in lines:
            pdf.drawString(40, y, line)
            y -= 20
        pdf.showPage()
    pdf.save()
    return output.getvalue()


def write_pdf(
    path: Path,
    lines: list[str],
    *,
    font_size: float = 11,
    page_size: tuple[float, float] = PAGE_SIZE,
) -> Path:
    path.write_bytes(make_pdf([lines], font_size, page_size=page_size))
    return path


def blank_pdf(page_sizes: Iterable[tuple[float, float]]) -> bytes:
    writer = PdfWriter()
    writer.metadata = None
    for width, height in page_sizes:
        writer.add_blank_page(width=width, height=height)
    return _writer_bytes(writer)


def with_metadata(pdf_bytes: bytes, metadata: dict[str, str]) -> bytes:
    writer = _copy_pages(pdf_bytes)
    writer.metadata = None
    writer.add_metadata({_METADATA_KEYS.get(key, f"/{key}"): value for key, value in metadata.items()})
    return _writer_bytes(writer)


def without_metadata(pdf_bytes: bytes) -> bytes:
    writer = _copy_pages(pdf_bytes)
    writer.metadata = None
    return _writer_bytes(writer)


def encrypted_pdf(
    pdf_bytes: bytes,
    user_password: str = "hunter2",
    owner_password: str = "hunter2admin",
) -> bytes:
    writer = _copy_pages(pdf_bytes)
    writer.encrypt(user_password=user_password, owner_password=owner_password)
    return _writer_bytes(writer)


def rotate_pdf(pdf_bytes: bytes, rotation: int) -> bytes:
    writer = _copy_pages(pdf_bytes)
    for page in writer.pages:
        page.rotate(rotation)
    return _writer_bytes(writer)


def join_pdfs(*documents: bytes) -> bytes:
    writer = PdfWriter()
    writer.metadata = None
    for data in documents:
        reader = PdfReader(BytesIO(data))
        for page in reader.pages:
            writer.add_page(page)
    return _writer_bytes(writer)


def image_only_pdf(
    lines: list[str] | None = None,
    *,
    fill: int = 255,
    dpi: int = 200,
    page_size: tuple[float, float] = PAGE_SIZE,
) -> bytes:
    """Create a page containing a raster image and no text objects."""
    width_px = max(1, round(page_size[0] * dpi / 72))
    height_px = max(1, round(page_size[1] * dpi / 72))
    if lines:
        source = make_pdf([lines], 22, page_size=page_size)
        with pdfium.PdfDocument(source) as document:
            page = document[0]
            bitmap = page.render(scale=dpi / 72)
            try:
                image = bitmap.to_pil().copy()
            finally:
                bitmap.close()
                page.close()
    else:
        image = Image.new("RGB", (width_px, height_px), color=(fill, fill, fill))

    output = BytesIO()
    pdf = canvas.Canvas(output, pagesize=page_size, pageCompression=1)
    pdf.drawImage(ImageReader(image), 0, 0, width=page_size[0], height=page_size[1])
    pdf.showPage()
    pdf.save()
    return output.getvalue()


def _copy_pages(pdf_bytes: bytes) -> PdfWriter:
    reader = PdfReader(BytesIO(pdf_bytes))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    return writer


def _writer_bytes(writer: PdfWriter) -> bytes:
    output = BytesIO()
    writer.write(output)
    return output.getvalue()
