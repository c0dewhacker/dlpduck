"""Metadata the PDF itself carries — its Info dictionary (title, author,
creator, producer, creation/mod dates). Extracted unconditionally, so a
bare PDF with no companion XML/JSON dropped alongside it still has
*something* rather than an empty metadata dict.

A companion file's values always win on overlapping keys — see
Pipeline.claim(). And this is still subject to the same allowlist as
companion metadata: nothing here is kept unless
`source.metadata_fields` names it. A PDF's declared Title or Producer can
leak exactly as much as a filename can (a "Divorce filing — Jane Doe"
title saved from a word processor, say), so it gets no special exemption
from the opt-in rule.

Deliberately not built: parsing the dropped *filename* for structure. A
filename is whatever the sender happened to call the file, not something
the document itself asserts — a materially weaker signal than its own
declared metadata, and a potential source of quiet data leaks.
"""

from __future__ import annotations

import pymupdf

# PyMuPDF's Info-dictionary key -> our metadata field name.
_FIELDS = {
    "title": "pdf_title",
    "author": "pdf_author",
    "subject": "pdf_subject",
    "creator": "pdf_creator",
    "producer": "pdf_producer",
    "creationDate": "pdf_created_at",
    "modDate": "pdf_modified_at",
}


def extract_pdf_metadata(pdf_bytes: bytes) -> dict[str, str]:
    try:
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    except Exception:
        return {}  # unreadable here is not fatal — extraction proper will fail closed later
    raw = doc.metadata or {}
    return {out_key: raw[in_key] for in_key, out_key in _FIELDS.items() if raw.get(in_key)}
