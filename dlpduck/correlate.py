"""Value correlation: every document in which the same sensitive value was
found, without that value being stored anywhere.

Each hit carries `match_hmac`, a keyed digest of its normalised value (see
dlpduck.masking.correlate). Correlation is a lookup on those digests in the
permanent index — so it needs no content store, and still answers after a
document's text has been purged or aged out. That is the question an
investigator most often has once one hit is in front of them: "where else
has this card number / NI number / account turned up?"

Two ways in: from a hit already on screen (its digest), or from a value
the investigator types (digested here with the deployment's key, never
stored or logged). The second is a membership test on flagged values, so
callers gate it like full-text search.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from dlpduck.masking import correlate as digest_value
from dlpduck.search import LATEST_SQL, MAX_LIMIT, IndexFilters, SearchError, run_query

_DIGEST = re.compile(r"^[0-9a-f]{32}$")


@dataclass
class CorrelatedHit:
    job_id: str
    received_at: datetime
    disposition: str
    highest_severity: str | None
    archive_path: str
    release_pending: bool
    rule_id: str
    rule_name: str
    severity: str
    page_number: int
    line_number: int
    masked_text: str
    match_hmac: str


@dataclass
class CorrelationResponse:
    match_hmac: str
    hits: list[CorrelatedHit]
    truncated: bool
    documents: int  # distinct jobs among `hits`


def validate_digest(value: str) -> str:
    if not isinstance(value, str) or not _DIGEST.match(value):
        raise SearchError("not a correlation digest (expected 32 hex characters)")
    return value


def digest_for(value: str, key: bytes) -> str:
    """The digest a hit on `value` would carry. Normalised the same way
    as at scan time, so "4111-1111" and "4111 1111" are one value."""
    if not value or not value.strip():
        raise SearchError("enter a value to look up")
    if len(value) > 256:
        raise SearchError("values are limited to 256 characters")
    return digest_value(value, key)


def find(
    index_root: Path,
    match_hmac: str,
    *,
    start: date | None = None,
    end: date | None = None,
    filters: IndexFilters | None = None,
    limit: int = 200,
    offset: int = 0,
    timeout_seconds: float = 30.0,
) -> CorrelationResponse:
    """Every hit, in the current assessment of every job, whose value
    digests to `match_hmac` — newest first."""
    validate_digest(match_hmac)
    if not 0 < limit <= MAX_LIMIT:
        raise SearchError(f"limit must be between 1 and {MAX_LIMIT}")
    if offset < 0:
        raise SearchError("offset must be nonnegative")
    if start and end and start > end:
        raise SearchError("Start date must be on or before end date")
    index_root = Path(index_root)
    if not any(index_root.glob("dt=*/*.parquet")):
        return CorrelationResponse(match_hmac, [], False, 0)

    where, params = (filters or IndexFilters()).sql("i")
    # A cheap pre-filter before unnesting: list_contains over the digests
    # column would need one, so the struct list is checked directly.
    where.append("list_contains(list_transform(i.hits, h -> h.match_hmac), ?)")
    params.append(match_hmac)
    if start is not None:
        where.append("i.dt >= ?")
        params.append(start)
    if end is not None:
        where.append("i.dt <= ?")
        params.append(end)

    # `where` holds fixed fragments with `?` placeholders only.
    sql = f"""
        WITH latest AS ({LATEST_SQL}),
        matched AS (
            SELECT i.job_id, i.received_at, i.disposition, i.highest_severity,
                   i.archive_path, i.release_pending, unnest(i.hits) AS h
            FROM latest AS i
            WHERE {" AND ".join(where)}
        )
        SELECT job_id, received_at, disposition, highest_severity, archive_path,
               release_pending, h.rule_id, h.rule_name, h.severity, h.page_number,
               h.line_number, h.masked_text, h.match_hmac
        FROM matched
        WHERE h.match_hmac = ?
        ORDER BY received_at DESC, job_id, h.line_number
        LIMIT ? OFFSET ?
    """
    rows = run_query(
        sql,
        [str(index_root / "dt=*" / "*.parquet"), *params, match_hmac, limit + 1, offset],
        timeout_seconds,
    )
    hits = [
        CorrelatedHit(
            job_id=r[0], received_at=r[1], disposition=r[2], highest_severity=r[3],
            archive_path=r[4], release_pending=bool(r[5]), rule_id=r[6], rule_name=r[7],
            severity=r[8], page_number=r[9], line_number=r[10], masked_text=r[11],
            match_hmac=r[12],
        )
        for r in rows[:limit]
    ]
    return CorrelationResponse(
        match_hmac=match_hmac,
        hits=hits,
        truncated=len(rows) > limit,
        documents=len({h.job_id for h in hits}),
    )
