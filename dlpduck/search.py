"""Join raw document text with permanent assessment metadata by job ID.

The separate Parquet stores let operators purge content while retaining
the audit history.

Because it's an inner join, a job whose content has been purged
(dlpduck.content.purge_content) simply has no row in the content store and
so can never match a search — "make it not searchable" falls straight out
of the join, with no extra logic required. Its index row is untouched and
still answers "did this job exist, what did we decide" through other
means (the jobs list, value correlation in dlpduck.correlate, the audit
trail).

The date range is optional — "when did this arrive?" is usually exactly
what an investigator doesn't know, and search exists to answer it. Given,
a range prunes the content store's dt= partitions before DuckDB reads a
byte of the large full_text column; omitted, the query scans the whole
content store, bounded by a wall-clock timeout and a row limit instead of
being refused outright.

Query syntax (see `parse_query`) is deliberately small: words that must
all appear, "quoted phrases", and -exclusions. Every term is matched
case-insensitively, and a phrase matches across any run of whitespace —
including the line break OCR put in the middle of it. Users never supply
regex syntax: each term becomes an escaped literal inside a fixed,
server-authored RE2 pattern (linear time, no backtracking), and every
value — patterns, dates, filters, globs — is a bound parameter.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import duckdb

from dlpduck.tracing import content_trace_enabled
from dlpduck.types import Severity

logger = logging.getLogger("dlpduck.search")
SEVERITIES = {s.value for s in Severity}
DISPOSITIONS = {"archive", "quarantine"}
MAX_QUERY_CHARS = 256
MAX_TERMS = 10
MAX_LIMIT = 1000


class SearchError(ValueError):
    pass


class QueryTimeout(Exception):
    pass


@dataclass(frozen=True)
class Query:
    """A parsed search: every `include` term must appear, no `exclude`
    term may. A term is a tuple of words matched as a phrase."""

    include: tuple[tuple[str, ...], ...]
    exclude: tuple[tuple[str, ...], ...] = ()


_TOKEN = re.compile(r'(-?)(?:"([^"]*)"?|(\S+))')


def parse_query(q: str) -> Query:
    """`invoice "account number" -draft` → must contain "invoice" and the
    phrase "account number", must not contain "draft".

    An unmatched quote runs to the end of the query rather than being an
    error; an empty phrase is ignored. A query of only exclusions is
    refused — it would match nearly everything.
    """
    if not q or not q.strip():
        raise SearchError("query must not be empty")
    if len(q) > MAX_QUERY_CHARS:
        raise SearchError(f"search terms are limited to {MAX_QUERY_CHARS} characters")
    include: list[tuple[str, ...]] = []
    exclude: list[tuple[str, ...]] = []
    for negated, phrase, word in _TOKEN.findall(q):
        words = tuple((phrase if phrase else word).split())
        if not words:
            continue
        (exclude if negated else include).append(words)
    if not include:
        raise SearchError("give at least one term to search for, not only exclusions")
    if len(include) + len(exclude) > MAX_TERMS:
        raise SearchError(f"at most {MAX_TERMS} terms per search")
    return Query(tuple(include), tuple(exclude))


def _term_pattern(words: tuple[str, ...]) -> str:
    # Escaped literals only, joined by "any whitespace": a phrase OCR wrapped
    # onto the next line still matches.
    return r"\s+".join(re.escape(w) for w in words)


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
    release_pending: bool = False
    source_name: str | None = None
    rule_ids: list[str] = field(default_factory=list)
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


@dataclass(frozen=True)
class IndexFilters:
    """Filters on the current assessment, shared by search, the jobs list
    and correlation so the three cannot disagree about what "HIGH" or
    "rule X" means. Every value is validated here and bound later."""

    severity: str | None = None  # exactly this highest severity
    min_severity: str | None = None  # this highest severity or worse
    rule_id: str | None = None  # at least one hit from this rule
    disposition: str | None = None
    source_name: str | None = None
    flagged: bool | None = None  # True: has hits; False: has none
    release_pending: bool = False

    def __post_init__(self) -> None:
        for name in ("severity", "min_severity"):
            value = getattr(self, name)
            if value is not None and value not in SEVERITIES:
                raise SearchError(
                    f"unknown severity {value!r} — must be one of {sorted(SEVERITIES)}"
                )
        if self.disposition is not None and self.disposition not in DISPOSITIONS:
            raise SearchError(f"disposition must be one of {sorted(DISPOSITIONS)}")
        for name in ("rule_id", "source_name"):
            value = getattr(self, name)
            if value is not None and (not value or len(value) > 128):
                raise SearchError(f"{name} must be 1-128 characters")

    def sql(self, alias: str) -> tuple[list[str], list[Any]]:
        """WHERE fragments (fixed text, `?` placeholders only) and their
        bound values, against the current-assessment relation `alias`."""
        where: list[str] = []
        params: list[Any] = []
        if self.severity is not None:
            where.append(f"{alias}.highest_severity = ?")
            params.append(self.severity)
        if self.min_severity is not None:
            worse = [s.value for s in Severity if s.rank >= Severity(self.min_severity).rank]
            where.append(f"{alias}.highest_severity IN ({','.join('?' for _ in worse)})")
            params.extend(worse)
        if self.rule_id is not None:
            where.append(f"list_contains({alias}.rule_ids, ?)")
            params.append(self.rule_id)
        if self.disposition is not None:
            where.append(f"{alias}.disposition = ?")
            params.append(self.disposition)
        if self.source_name is not None:
            where.append(f"{alias}.source_name = ?")
            params.append(self.source_name)
        if self.flagged is True:
            where.append(f"{alias}.hit_count > 0")
        elif self.flagged is False:
            where.append(f"{alias}.hit_count = 0")
        if self.release_pending:
            where.append(f"{alias}.release_pending = true")
        return where, params


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


def run_query(sql: str, params: list[Any], timeout_seconds: float) -> list[tuple]:
    """Run one read-only DuckDB query with a wall-clock budget.

    DuckDB has no statement_timeout in this version, so a watchdog thread
    interrupts the connection instead — "bound with a clock rather than
    refuse the query". Timestamps are read in UTC: they were written as UTC
    and are what chose each dt= partition, and DuckDB's default of the
    host's local zone would misorder and mislabel rows near midnight.
    """
    con = duckdb.connect()
    con.execute("SET TimeZone='UTC'")
    timer = threading.Timer(timeout_seconds, con.interrupt)
    timer.daemon = True
    timer.start()
    try:
        return con.execute(sql, params).fetchall()
    except duckdb.InterruptException as exc:
        raise QueryTimeout(
            f"query exceeded its {timeout_seconds}s budget — narrow the date range or query"
        ) from exc
    finally:
        timer.cancel()
        con.close()


# The current assessment per job — a job accumulates one index row per
# assessment, and every reader must only ever see the newest.
LATEST_SQL = """
    SELECT * FROM read_parquet(?, hive_partitioning = true, union_by_name = true)
    QUALIFY row_number() OVER (PARTITION BY job_id ORDER BY assessment_seq DESC) = 1
"""


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
    *,
    filters: IndexFilters | None = None,
) -> SearchResponse:
    if offset < 0:
        raise SearchError("offset must be nonnegative")
    if start and end and start > end:
        raise SearchError("Start date must be on or before end date")
    query = parse_query(q)
    if not 0 < limit <= MAX_LIMIT:
        raise SearchError(f"limit must be between 1 and {MAX_LIMIT}")
    filters = filters or IndexFilters()
    if severity is not None:
        filters = IndexFilters(**{**filters.__dict__, "severity": severity})

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

    where: list[str] = []
    params: list[Any] = []
    for words in query.include:
        where.append("regexp_matches(c.full_text, ?)")
        params.append("(?i)" + _term_pattern(words))
    for words in query.exclude:
        where.append("NOT regexp_matches(c.full_text, ?)")
        params.append("(?i)" + _term_pattern(words))
    if start is not None:
        where.append("c.dt >= ?")
        params.append(start)
    if end is not None:
        where.append("c.dt <= ?")
        params.append(end)
    index_where, index_params = filters.sql("i")
    where += index_where
    params += index_params

    # The snippet is centred on the first term. (?s) lets it run across the
    # line breaks a wrapped phrase may contain; they are flattened below.
    snippet = "(?is).{0,60}" + _term_pattern(query.include[0]) + ".{0,60}"

    # The only interpolation below is `where`, joined from the fixed
    # fragments built above. Every VALUE is a bound parameter, bound in the
    # order the placeholders appear: the index glob, the snippet pattern,
    # the content glob, the WHERE clause, then LIMIT and OFFSET. One more
    # row than the limit is asked for, so truncation is a length check.
    sql = f"""
        WITH latest AS ({LATEST_SQL})
        SELECT i.job_id, i.received_at, i.page_count, i.disposition, i.highest_severity,
               i.hit_count, i.archive_path, regexp_extract(c.full_text, ?, 0) AS snippet,
               i.release_pending, i.source_name, i.rule_ids
        FROM read_parquet(?, hive_partitioning = true, union_by_name = true) AS c
        JOIN latest AS i USING (job_id)
        WHERE {" AND ".join(where)}
        ORDER BY i.received_at DESC, i.job_id
        LIMIT ? OFFSET ?
    """
    all_params = [
        str(index_root / "dt=*" / "*.parquet"),
        snippet,
        str(content_root / "dt=*" / "*.parquet"),
        *params,
        limit + 1,
        offset,
    ]

    started = time.monotonic()
    rows = run_query(sql, all_params, timeout_seconds)
    elapsed = time.monotonic() - started

    truncated = len(rows) > limit
    results = [
        SearchResult(
            job_id=r[0],
            received_at=r[1],
            page_count=r[2],
            disposition=r[3],
            highest_severity=r[4],
            hit_count=r[5],
            archive_path=r[6],
            snippet=" ".join((r[7] or "").split()),
            release_pending=bool(r[8]),
            source_name=r[9],
            rule_ids=list(r[10] or []),
        )
        for r in rows[:limit]
    ]
    logger.debug(
        "search: %d result(s) in %.3fs (truncated=%s) for query=%s",
        len(results), elapsed, truncated,
        repr(q) if content_trace_enabled() else f"<{len(q)} char(s), redacted>",
    )
    return SearchResponse(
        results=results,
        elapsed_seconds=elapsed,
        truncated=truncated,
        unbounded=start is None and end is None,
    )
