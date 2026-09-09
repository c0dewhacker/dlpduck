"""Two Parquet stores, deliberately kept separate.

INDEX_SCHEMA (index/dt=.../<job_id>_<assessment_seq>.parquet) is permanent
metadata: it proves a document existed and was assessed, and every hit in
it is already masked (§6.4) — there is nothing in it that privacy or a
takedown request would ever require deleting. A job accumulates one row
per *assessment* (§8.4): the first at ingest, one more each time
reprocessing changes its verdict. Rows are never rewritten or deleted —
`latest_index_rows()` in dlpduck.reprocess picks the current one per job
via `assessment_seq`.

CONTENT_SCHEMA (content/dt=.../<job_id>.parquet, one file per job — not
versioned like the index, since search only ever wants the current text)
is the one place raw document text lives. Purging a job is exactly and
only deleting this one file: the index row stays as proof the job
happened, and the audit trail (which never held raw text) stays untouched
and append-only. See §8.1/§8.5 as originally written, and the
simplification recorded here: purge no longer needs to rewrite an index
row or redact an audit event for the common case, because the content
that must be deletable was never mixed into either.

CONTENT_SCHEMA carries both `full_text` (flat, for ILIKE search) and
`lines` (structured, for reprocessing). v1's `lines_json` was dropped for
duplicating full_text with no distinct purpose it actually served; `lines`
is added back here for a real one full_text can't provide — a
`line_scope: page` rule (our own default classification-banner rules)
needs page_number/line_on_page/lines_on_page to re-evaluate, which a
joined string has already destroyed. Reprocessing's "rules" mode (§8.4)
depends on this to re-run positional rules without re-opening the PDF.
"""

import pyarrow as pa

DLP_HIT_STRUCT = pa.struct(
    [
        ("rule_id", pa.string()),
        ("rule_name", pa.string()),
        ("severity", pa.string()),
        ("action", pa.string()),
        ("page_number", pa.int32()),
        ("line_number", pa.int32()),
        ("line_on_page", pa.int32()),
        ("start", pa.int32()),
        ("end", pa.int32()),
        ("masked_text", pa.string()),  # never the raw value
        ("match_hmac", pa.string()),
        ("validator", pa.string()),
    ]
)

INDEX_SCHEMA = pa.schema(
    [
        ("job_id", pa.string()),
        ("received_at", pa.timestamp("ms", tz="UTC")),  # fixed at ingest — dt= partition key
        ("assessed_at", pa.timestamp("ms", tz="UTC")),  # when THIS assessment was computed
        ("assessment_seq", pa.int32()),  # 1, 2, 3… per job_id
        ("ruleset_version", pa.string()),  # hash of the ruleset that produced this assessment
        ("supersedes_seq", pa.int32()),  # prior assessment_seq, null on the first
        ("release_pending", pa.bool_()),  # de-escalated logically, PDF not yet moved (§8.4)
        ("source_name", pa.string()),
        ("page_count", pa.int32()),
        ("ocr_page_count", pa.int32()),
        ("min_ocr_confidence", pa.float32()),
        ("degraded", pa.bool_()),
        ("disposition", pa.string()),  # archive | quarantine | failed
        ("reason", pa.string()),
        ("archive_path", pa.string()),
        ("pdf_sha256", pa.string()),
        ("flagged", pa.bool_()),
        ("highest_severity", pa.string()),
        ("hit_count", pa.int32()),
        ("rule_ids", pa.list_(pa.string())),  # cheap pre-filter
        ("hits", pa.list_(DLP_HIT_STRUCT)),  # masked_text/match_hmac only
        ("metadata", pa.string()),  # JSON, allowlisted keys only (§6.4)
        ("audit_fields", pa.string()),  # JSON
    ]
)

CONTENT_LINE_STRUCT = pa.struct(
    [
        ("line_number", pa.int32()),
        ("page_number", pa.int32()),
        ("line_on_page", pa.int32()),
        ("lines_on_page", pa.int32()),
        ("text", pa.string()),
        ("source", pa.string()),  # native | ocr
        ("confidence", pa.float32()),
    ]
)

CONTENT_SCHEMA = pa.schema(
    [
        ("job_id", pa.string()),
        ("full_text", pa.string()),  # flat text, for ILIKE search
        ("lines", pa.list_(CONTENT_LINE_STRUCT)),  # structured, for reprocessing
    ]
)
