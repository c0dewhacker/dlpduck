"""Join raw document text with permanent assessment metadata by job ID.

The separate Parquet stores let operators purge content while retaining
the audit history.

Because it's an inner join, a job whose content has been purged
(dlpduck.content.purge_content) simply has no row in the content store and
so can never match a search — "make it not searchable" falls straight out
of the join, with no extra logic required. Its index row is untouched and
still answers "did this job exist, what did we decide" through other
means (dlpduck index, the audit trail).

The date range is optional — "when did this arrive?" is usually exactly
what an investigator doesn't know, and search exists to answer it. Given,
a range prunes the content store's dt= partitions before DuckDB reads a
byte of the large full_text column; omitted, the query scans the whole
content store, bounded by a wall-clock timeout and a row limit instead of
being refused outright.

Every value is bound (job_id, severity, dates); the only thing built from
the raw query string is a server-side regexp_extract pattern made of an
escaped literal, so there is no SQL injection and no user-supplied regex
to backtrack on.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import duckdb

from dlpduck.types import Severity

SEVERITIES = {s.value for s in Severity}
MAX_QUERY_CHARS = 128
MAX_LIMIT = 1000


class SearchError(ValueError):
    pass


class QueryTimeout(Exception):
    pass


@dataclass
class SearchResult:
    job_id: str
    received_at: datetime
    page_count: int
    disposition: str
    highest_severity: str | None
    hit_count: int
    archive_path: str
    snippet: str
    # Set by the console when the viewer may not see this document's raw
    # text (see app._is_contained). The library itself never withholds —
    # the CLI runs as an OS user with no role to check.
    snippet_withheld: bool = False


@dataclass
class SearchResponse:
    results: list[SearchResult] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    truncated: bool = False  # hit the row limit — there may be more
    unbounded: bool = False  # no date range was given


def audit_terms(query: str, mode: str, key: bytes) -> dict[str, str]:
    """How a search query is recorded in the audit trail.

    "plain" keeps the query, so "who searched for what" is answerable.
    "hashed" keeps only a keyed digest — same HMAC key as match
    correlation, so repeated searches for a term still line up without
    the term itself entering a store that has no purge path.
    """
    if mode == "hashed":
        return {"terms_hmac": hmac.new(key, query.encode("utf-8"), hashlib.sha256).hexdigest()[:32]}
    return {"query": query}


def _snippet_pattern(q: str) -> str:
    # The user never supplies regex syntax — this is an escaped literal
    # wrapped in a fixed, server-authored pattern.
    return f"(?i).{{0,60}}{re.escape(q)}.{{0,60}}"


def search(
    content_root: Path,
    index_root: Path,
    q: str,
    start: date | None = None,
    end: date | None = None,
    severity: str | None = None,
    limit: int = 100,
    timeout_seconds: float = 30.0,
    offset: int = 0,
) -> SearchResponse:
    if offset < 0:
        raise SearchError("offset must be nonnegative")
    if start and end and start > end:
        raise SearchError("Start date must be on or before end date")
    if not q:
        raise SearchError("query must not be empty")
    if len(q) > MAX_QUERY_CHARS:
        raise SearchError(f"search terms are limited to {MAX_QUERY_CHARS} characters")
    if severity is not None and severity not in SEVERITIES:
        raise SearchError(f"unknown severity {severity!r} — must be one of {sorted(SEVERITIES)}")
    if not 0 < limit <= MAX_LIMIT:
        raise SearchError(f"limit must be between 1 and {MAX_LIMIT}")

    content_root = Path(content_root)
    index_root = Path(index_root)
    # Nothing purged from the content store can ever match — check the
    # store that's actually searched, not the (permanent) index. Both
    # sides feed the join, so an empty index (nothing ingested yet) is
    # the same "nothing to find" case.
    if not any(content_root.glob("dt=*/*.parquet")) or not any(
        index_root.glob("dt=*/*.parquet")
    ):
        return SearchResponse(unbounded=start is None and end is None)

    # ILIKE gives `%` and `_` meaning. The query is a literal search term,
    # not a pattern language the user opted into — without escaping,
    # searching for "100%" silently means "100 followed by anything", and
    # a query of just "%" matches every document in the store.
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    where = ["c.full_text ILIKE ? ESCAPE '\\'"]
    params: list[Any] = [f"%{escaped}%"]
    if start is not None:
        where.append("c.dt >= ?")
        params.append(start)
    if end is not None:
        where.append("c.dt <= ?")
        params.append(end)
    if severity is not None:
        where.append("i.highest_severity = ?")
        params.append(severity)

    # The only interpolation below is `where`, joined from the fixed
    # literals built above ("c.dt >= ?" etc). Every VALUE — query, dates,
    # severity, limit, and both parquet globs — is a bound parameter.
    sql = f"""
        WITH latest AS (
            -- A job accumulates one index row per assessment;
            -- search must only ever see the current one, or a reprocessed
            -- job would show stale or duplicate results.
            SELECT * FROM read_parquet(?, hive_partitioning = true, union_by_name = true)
            QUALIFY row_number() OVER (PARTITION BY job_id ORDER BY assessment_seq DESC) = 1
        )
        SELECT i.job_id, i.received_at, i.page_count, i.disposition, i.highest_severity,
               i.hit_count, i.archive_path,
               regexp_extract(c.full_text, ?, 0) AS snippet
        FROM read_parquet(?, hive_partitioning = true, union_by_name = true) AS c
        JOIN latest AS i USING (job_id)
        WHERE {" AND ".join(where)}
        ORDER BY i.received_at DESC, i.job_id
        LIMIT ? OFFSET ?
    """
    content_glob = str(content_root / "dt=*" / "*.parquet")
    index_glob = str(index_root / "dt=*" / "*.parquet")
    # Bound in the exact order their `?` placeholders appear in the SQL
    # text above: the WITH clause's read_parquet, then the snippet
    # pattern, then the content-side read_parquet, then the WHERE clause.
    # Ask for one more than the limit so truncation is a length check, not
    # a second COUNT(*) query.
    all_params = [index_glob, _snippet_pattern(q), content_glob, *params, limit + 1, offset]

    con = duckdb.connect()
    # received_at was written as raw UTC; DuckDB defaults to converting
    # TIMESTAMPTZ to the local system zone on read, which would both
    # misorder/mislabel results near local midnight and disagree with the
    # UTC dates dt= partitions and the audit trail use everywhere else.
    con.execute("SET TimeZone='UTC'")
    # DuckDB has no built-in statement_timeout in this version — interrupt
    # the connection from a watchdog thread instead, the same "bound with
    # a clock rather than refuse the query" guard.
    timer = threading.Timer(timeout_seconds, con.interrupt)
    timer.daemon = True
    timer.start()
    started = time.monotonic()
    try:
        rows = con.execute(sql, all_params).fetchall()
    except duckdb.InterruptException as exc:
        raise QueryTimeout(
            f"search exceeded its {timeout_seconds}s budget — narrow the date range or query"
        ) from exc
    finally:
        timer.cancel()
        con.close()
    elapsed = time.monotonic() - started

    truncated = len(rows) > limit
    rows = rows[:limit]
    results = [
        SearchResult(
            job_id=r[0],
            received_at=r[1],
            page_count=r[2],
            disposition=r[3],
            highest_severity=r[4],
            hit_count=r[5],
            archive_path=r[6],
            snippet=r[7] or "",
        )
        for r in rows
    ]
    return SearchResponse(
        results=results,
        elapsed_seconds=elapsed,
        truncated=truncated,
        unbounded=start is None and end is None,
    )
