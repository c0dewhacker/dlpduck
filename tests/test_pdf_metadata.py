"""Metadata is extracted from the PDF itself unconditionally, so a
bare PDF with no companion still yields something — but it's exactly as
subject to the allowlist as companion metadata is (tested at the pipeline
level in test_pipeline.py), and filename parsing is deliberately not
built.
"""

import pymupdf

from dlpduck.pdf_metadata import extract_pdf_metadata


def _pdf_bytes(metadata: dict) -> bytes:
    doc = pymupdf.open()
    doc.set_metadata(metadata)
    doc.new_page().insert_text((40, 40), "content")
    return doc.tobytes()


class TestExtractPdfMetadata:
    def test_extracts_populated_fields(self):
        pdf = _pdf_bytes({"title": "Q3 Report", "author": "jsmith", "creator": "Microsoft Word"})
        meta = extract_pdf_metadata(pdf)
        assert meta["pdf_title"] == "Q3 Report"
        assert meta["pdf_author"] == "jsmith"
        assert meta["pdf_creator"] == "Microsoft Word"

    def test_empty_fields_are_omitted_not_included_as_blanks(self):
        pdf = _pdf_bytes({"title": "Only Title"})
        meta = extract_pdf_metadata(pdf)
        assert meta == {"pdf_title": "Only Title"}
        assert "pdf_author" not in meta

    def test_pdf_with_no_metadata_at_all_yields_empty_dict(self):
        doc = pymupdf.open()
        doc.new_page().insert_text((40, 40), "content")
        meta = extract_pdf_metadata(doc.tobytes())
        assert meta == {}

    def test_unreadable_bytes_yield_empty_dict_not_an_exception(self):
        assert extract_pdf_metadata(b"not a pdf at all") == {}

    def test_filename_is_never_a_field(self):
        # Deliberately not built — a filename is whatever the sender
        # happened to call the file, not something the document asserts.
        pdf = _pdf_bytes({"title": "x"})
        meta = extract_pdf_metadata(pdf)
        assert "filename" not in meta
        assert "pdf_filename" not in meta

    def test_all_supported_fields_round_trip(self):
        pdf = _pdf_bytes(
            {
                "title": "T",
                "author": "A",
                "subject": "S",
                "creator": "C",
                "producer": "P",
            }
        )
        meta = extract_pdf_metadata(pdf)
        assert meta["pdf_title"] == "T"
        assert meta["pdf_author"] == "A"
        assert meta["pdf_subject"] == "S"
        assert meta["pdf_creator"] == "C"
        assert meta["pdf_producer"] == "P"
