"""§10.6/§8.5: v1 interpolated the query and severity straight into SQL —
injection in both, plus an unvalidated user-supplied regex as a ReDoS
vector — and always scanned every Parquet file on every query. This tests
those fixes, plus the content/index split: search joins the content store
(raw full_text) against the metadata index by job_id, so a job whose
content has been purged simply falls out of the join and stops matching,
while its index row (and the audit trail) are untouched.
"""

from datetime import UTC, date, datetime
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

import dlpduck.search as search_module
from dlpduck.content import purge_content
from dlpduck.schema import CONTENT_SCHEMA, INDEX_SCHEMA
from dlpduck.search import MAX_QUERY_CHARS, QueryTimeout, SearchError, search

# Job ids are content-derived 32-hex digests in reality, and the store
# helpers now validate that shape before globbing for a file — so the
# fixtures use real-shaped ids with readable names bound to them.
JOB1 = "1" * 32
JOB2 = "2" * 32
JOB3 = "3" * 32
ABSENT = "0" * 32


def _index_row(job_id, dt, disposition="archive", severity=None, hit_count=0):
    return {
        "job_id": job_id,
        "received_at": datetime(dt.year, dt.month, dt.day, 12, 0, tzinfo=UTC),
        "source_name": "test",
        "page_count": 1,
        "ocr_page_count": 0,
        "min_ocr_confidence": None,
        "degraded": False,
        "disposition": disposition,
        "reason": None,
        "archive_path": f"/archive/{job_id}.pdf",
        "pdf_sha256": "x",
        "flagged": hit_count > 0,
        "highest_severity": severity,
        "hit_count": hit_count,
        "rule_ids": [],
        "hits": [],
        "metadata": "{}",
        "audit_fields": "{}",
    }


def _write_store(root: Path, schema: pa.Schema, rows_by_date: dict[date, list[dict]]) -> None:
    for dt, day_rows in rows_by_date.items():
        partition = root / f"dt={dt.isoformat()}"
        partition.mkdir(parents=True, exist_ok=True)
        for row in day_rows:
            table = pa.Table.from_pylist([row], schema=schema)
            pq.write_table(table, partition / f"{row['job_id']}.parquet")


def _seed(
    tmp_path: Path,
    docs: list[tuple[str, str, date]],
    kwargs_per_job: dict[str, dict] | None = None,
) -> tuple[Path, Path]:
    """docs = [(job_id, full_text, received_date), ...]. Writes matching
    rows to both stores, mirroring what Pipeline.commit() does.
    """
    content_root = tmp_path / "content"
    index_root = tmp_path / "index"

    content_by_date: dict[date, list[dict]] = {}
    index_by_date: dict[date, list[dict]] = {}
    for job_id, text, dt in docs:
        content_by_date.setdefault(dt, []).append({"job_id": job_id, "full_text": text})
        extra = (kwargs_per_job or {}).get(job_id, {})
        index_by_date.setdefault(dt, []).append(_index_row(job_id, dt, **extra))

    _write_store(content_root, CONTENT_SCHEMA, content_by_date)
    _write_store(index_root, INDEX_SCHEMA, index_by_date)
    return content_root, index_root


@pytest.fixture
def stores(tmp_path):
    return _seed(
        tmp_path,
        [
            (JOB1, "This memo discusses the quarterly roadmap in detail.", date(2026, 1, 10)),
            (
                JOB2,
                "Card number 4111 1111 1111 1111 was found on this page.",
                date(2026, 1, 15),
            ),
            (
                JOB3,
                "OFFICIAL-SENSITIVE roadmap discussion continues here.",
                date(2026, 2, 1),
            ),
        ],
        kwargs_per_job={
            JOB2: {"disposition": "quarantine", "severity": "HIGH", "hit_count": 1},
            JOB3: {"disposition": "quarantine", "severity": "CRITICAL", "hit_count": 2},
        },
    )


class TestBasicSearch:
    def test_finds_matching_documents(self, stores):
        content_root, index_root = stores
        response = search(content_root, index_root, "roadmap")
        job_ids = {r.job_id for r in response.results}
        assert job_ids == {JOB1, JOB3}

    def test_case_insensitive(self, stores):
        content_root, index_root = stores
        response = search(content_root, index_root, "ROADMAP")
        assert len(response.results) == 2

    def test_no_match_returns_empty_not_an_error(self, stores):
        content_root, index_root = stores
        response = search(content_root, index_root, "nonexistent_term_xyz")
        assert response.results == []

    def test_snippet_is_extracted_around_the_match(self, stores):
        content_root, index_root = stores
        response = search(content_root, index_root, "quarterly")
        assert len(response.results) == 1
        assert "quarterly" in response.results[0].snippet.lower()

    def test_result_carries_index_metadata_not_just_content(self, stores):
        content_root, index_root = stores
        response = search(content_root, index_root, "4111")
        assert len(response.results) == 1
        r = response.results[0]
        assert r.disposition == "quarantine"
        assert r.highest_severity == "HIGH"
        assert r.hit_count == 1
        assert r.archive_path == f"/archive/{JOB2}.pdf"

    def test_empty_stores_return_empty_without_erroring(self, tmp_path):
        response = search(tmp_path / "content", tmp_path / "index", "anything")
        assert response.results == []


class TestContentPurgeExcludesFromSearch:
    """The whole point of the split: purging content is exactly deleting
    its file, and search must simply stop finding it — no extra
    "is this purged" logic needed anywhere.
    """

    def test_purged_job_no_longer_matches(self, stores):
        content_root, index_root = stores
        assert purge_content(content_root, JOB3) is True

        response = search(content_root, index_root, "roadmap")
        assert {r.job_id for r in response.results} == {JOB1}

    def test_purging_content_does_not_touch_the_index_store(self, stores, tmp_path):
        content_root, index_root = stores
        purge_content(content_root, JOB3)

        # The index row for job3 must still be readable directly — purge
        # never rewrites or deletes anything under index/.
        con = duckdb.connect()
        rows = con.execute(
            f"SELECT job_id, disposition, highest_severity FROM "
            f"read_parquet('{index_root}/dt=*/*.parquet', hive_partitioning=true) "
            f"WHERE job_id = '{JOB3}'"
        ).fetchall()
        con.close()
        assert rows == [(JOB3, "quarantine", "CRITICAL")]

    def test_purging_an_already_purged_job_is_a_harmless_noop(self, stores):
        content_root, index_root = stores
        assert purge_content(content_root, JOB3) is True
        assert purge_content(content_root, JOB3) is False  # already gone

    def test_purging_a_job_that_never_had_content_is_a_harmless_noop(self, stores):
        content_root, index_root = stores
        assert purge_content(content_root, ABSENT) is False


class TestDateRangeIsOptional:
    def test_no_range_searches_everything_and_is_marked_unbounded(self, stores):
        content_root, index_root = stores
        response = search(content_root, index_root, "roadmap")
        assert response.unbounded is True
        assert len(response.results) == 2

    def test_range_given_is_marked_bounded_and_prunes(self, stores):
        content_root, index_root = stores
        response = search(
            content_root, index_root, "roadmap", start=date(2026, 1, 1), end=date(2026, 1, 31)
        )
        assert response.unbounded is False
        assert [r.job_id for r in response.results] == [JOB1]

    def test_range_excludes_documents_outside_it(self, stores):
        content_root, index_root = stores
        response = search(
            content_root, index_root, "roadmap", start=date(2026, 2, 1), end=date(2026, 2, 28)
        )
        assert [r.job_id for r in response.results] == [JOB3]


class TestSeverityFilter:
    def test_filters_by_exact_severity(self, stores):
        content_root, index_root = stores
        response = search(content_root, index_root, "roadmap", severity="CRITICAL")
        assert [r.job_id for r in response.results] == [JOB3]

    def test_unknown_severity_is_rejected_not_silently_ignored(self, stores):
        content_root, index_root = stores
        with pytest.raises(SearchError, match="unknown severity"):
            search(content_root, index_root, "roadmap", severity="SUPER_CRITICAL")


class TestInjectionResistance:
    """The exact v1 bug: query and severity were interpolated directly
    into the SQL string and into a regex, respectively.
    """

    def test_sql_metacharacters_in_query_are_inert(self, stores):
        content_root, index_root = stores
        response = search(content_root, index_root, "'; DROP TABLE anything; --")
        assert response.results == []  # no match, no error, no injected SQL

    def test_percent_and_underscore_are_treated_literally(self, stores):
        content_root, index_root = stores
        response = search(content_root, index_root, "100%_roadmap")
        assert response.results == []

    def test_severity_is_validated_against_an_enum_not_interpolated(self, stores):
        content_root, index_root = stores
        malicious = "HIGH' OR '1'='1"
        with pytest.raises(SearchError):
            search(content_root, index_root, "roadmap", severity=malicious)

    def test_query_used_as_a_regex_source_is_escaped(self, stores):
        content_root, index_root = stores
        response = search(content_root, index_root, "roadmap.*")  # literal, not present
        assert response.results == []


class TestLimitsAndValidation:
    def test_empty_query_rejected(self, stores):
        content_root, index_root = stores
        with pytest.raises(SearchError, match="empty"):
            search(content_root, index_root, "")

    def test_overlong_query_rejected(self, stores):
        content_root, index_root = stores
        with pytest.raises(SearchError, match=str(MAX_QUERY_CHARS)):
            search(content_root, index_root, "x" * (MAX_QUERY_CHARS + 1))

    def test_limit_bounds_result_count_and_flags_truncation(self, tmp_path):
        docs = [(f"job{i}", "shared marker text", date(2026, 1, 1)) for i in range(5)]
        content_root, index_root = _seed(tmp_path, docs)

        response = search(content_root, index_root, "shared", limit=2)
        assert len(response.results) == 2
        assert response.truncated is True

    def test_not_truncated_when_results_fit_under_the_limit(self, stores):
        content_root, index_root = stores
        response = search(content_root, index_root, "roadmap", limit=100)
        assert response.truncated is False

    def test_invalid_limit_rejected(self, stores):
        content_root, index_root = stores
        with pytest.raises(SearchError):
            search(content_root, index_root, "roadmap", limit=0)
        with pytest.raises(SearchError):
            search(content_root, index_root, "roadmap", limit=10_000)


class TestTimeoutGuard:
    def test_duckdb_interrupt_is_surfaced_as_querytimeout_not_a_raw_duckdb_exception(
        self, stores, monkeypatch
    ):
        # A real timing race (tiny fixture vs. a near-zero timeout) is
        # inherently flaky — the query can finish before the watchdog timer
        # even fires. Test the exception-mapping deterministically instead:
        # stub the connection so execute() raises exactly what DuckDB raises
        # when a watchdog thread calls con.interrupt() mid-query, and
        # confirm search() maps that to QueryTimeout rather than leaking it.
        content_root, index_root = stores

        class _StubConnection:
            def execute(self, sql, *a, **kw):
                # Let session setup (e.g. "SET TimeZone=...") through —
                # only the actual search query should look interrupted.
                if sql.strip().upper().startswith("SET "):
                    return self
                raise duckdb.InterruptException("interrupted")

            def interrupt(self):
                pass

            def close(self):
                pass

        monkeypatch.setattr(search_module.duckdb, "connect", lambda: _StubConnection())

        with pytest.raises(QueryTimeout, match="exceeded its"):
            search(content_root, index_root, "roadmap", timeout_seconds=5.0)

    def test_timeout_only_fires_after_the_configured_delay(self, stores):
        # A generous timeout must not spuriously interrupt a fast query —
        # this is the flip side of the guard: it bounds slow queries
        # without punishing fast ones.
        content_root, index_root = stores
        response = search(content_root, index_root, "roadmap", timeout_seconds=30.0)
        assert response.results  # completed normally, no exception


class TestMultipleAssessmentsPerJob:
    """§8.4: reprocessing appends a new index row rather than rewriting
    the old one, so a job can have several assessment rows on disk at
    once. Search must resolve to only the current one — this exercises
    that against a REAL pipeline + reprocessor, not synthetic fixture
    rows, since getting the QUALIFY window function wrong here would
    silently show stale severity/disposition or duplicate a result.
    """

    def _pdf(self, path, lines):
        import pymupdf

        doc = pymupdf.open()
        page = doc.new_page(width=595, height=842)
        y = 40
        for line in lines:
            page.insert_text((40, y), line)
            y += 20
        doc.save(path)
        return path

    def test_search_reflects_the_post_reprocess_severity_not_the_original(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        from dlpduck.config import Config
        from dlpduck.pipeline import Pipeline
        from dlpduck.reprocess import Reprocessor

        src = tmp_path / "drops"
        src.mkdir()

        def cfg(rules):
            return Config.model_validate(
                {
                    "source": {"name": "t", "path": str(src), "metadata_format": "none"},
                    "destination": {
                        "archive": str(tmp_path / "archive"),
                        "quarantine": str(tmp_path / "quarantine"),
                        "work_dir": str(tmp_path / "work"),
                    },
                    "dlp": {"rules": rules},
                }
            )

        narrow = cfg([{"id": "never_matches", "name": "x", "pattern": "ZZZ_NEVER_ZZZ"}])
        pipeline = Pipeline(narrow)
        pdf = self._pdf(tmp_path / "doc.pdf", ["Reference ACCT-482910 in this memo"])
        staging = narrow.destination.work_dir / "_processing"
        ctx = pipeline.run_job(pdf, None, staging)
        assert ctx.disposition == "archive"

        content_root = narrow.destination.work_dir / "content"
        index_root = narrow.destination.work_dir / "index"

        before = search(content_root, index_root, "ACCT-482910")
        assert before.results[0].disposition == "archive"
        assert before.results[0].highest_severity is None

        wide = cfg(
            [
                {
                    "id": "acct",
                    "name": "Account number",
                    "pattern": r"ACCT-\d{6}",
                    "severity": "CRITICAL",
                    "action": "quarantine",
                }
            ]
        )
        Reprocessor(Pipeline(wide)).commit()

        after = search(content_root, index_root, "ACCT-482910")

        # Exactly one result — not two, even though two index files now
        # exist on disk for this job_id — and it reflects the NEW verdict.
        assert len(after.results) == 1
        assert after.results[0].job_id == ctx.job_id
        assert after.results[0].disposition == "quarantine"
        assert after.results[0].highest_severity == "CRITICAL"

        # Confirm the old assessment file is genuinely still there,
        # untouched — the point is that search skips it, not that it's gone.
        assert len(list(index_root.glob(f"dt=*/{ctx.job_id}_*.parquet"))) == 2


class TestLikeWildcardsAreLiteral:
    """The query is a search term, not a pattern language: ILIKE's own
    metacharacters must not leak through it."""

    def test_percent_does_not_become_a_wildcard(self, tmp_path):
        content_root, index_root = _seed(
            tmp_path,
            [
                (JOB1, "Completion was 100% on schedule.", date(2026, 1, 10)),
                (JOB2, "Nothing related here at all.", date(2026, 1, 11)),
            ],
        )
        # "100%" must match only the document containing that literal.
        response = search(content_root, index_root, "100%")
        assert [r.job_id for r in response.results] == [JOB1]

    def test_a_bare_percent_matches_nothing_rather_than_everything(self, tmp_path):
        content_root, index_root = _seed(
            tmp_path,
            [
                (JOB1, "no percent signs in this text", date(2026, 1, 10)),
                (JOB2, "nor in this one", date(2026, 1, 11)),
            ],
        )
        response = search(content_root, index_root, "%")
        assert response.results == []

    def test_underscore_is_literal_too(self, tmp_path):
        content_root, index_root = _seed(
            tmp_path,
            [
                (JOB1, "the file was named report_final today", date(2026, 1, 10)),
                (JOB2, "the file was named reportXfinal today", date(2026, 1, 11)),
            ],
        )
        response = search(content_root, index_root, "report_final")
        assert [r.job_id for r in response.results] == [JOB1]


class TestSearchTermAuditing:
    """The audit trail is hash-chained and has no purge path, so anything
    written there is permanent. A DLP investigation routinely means
    searching for the sensitive value itself, which is why how a query is
    recorded is a deployment decision rather than a fixed one.
    """

    KEY = b"test-key-not-for-production"

    def test_plain_mode_keeps_the_query(self):
        from dlpduck.search import audit_terms

        fields = audit_terms("acme corp invoice", "plain", self.KEY)
        assert fields == {"query": "acme corp invoice"}

    def test_hashed_never_carries_the_term(self):
        from dlpduck.search import audit_terms

        fields = audit_terms("123-45-6789", "hashed", self.KEY)
        assert "123-45-6789" not in str(fields)
        assert "query" not in fields
        assert len(fields["terms_hmac"]) == 32

    def test_hashed_still_correlates_repeated_searches(self):
        from dlpduck.search import audit_terms

        first = audit_terms("123-45-6789", "hashed", self.KEY)
        again = audit_terms("123-45-6789", "hashed", self.KEY)
        other = audit_terms("something else", "hashed", self.KEY)

        assert first == again  # "this term was searched twice" survives
        assert first != other

    def test_the_digest_is_keyed_so_it_cannot_be_brute_forced_offline(self):
        from dlpduck.search import audit_terms

        mine = audit_terms("123-45-6789", "hashed", self.KEY)
        theirs = audit_terms("123-45-6789", "hashed", b"a-different-deployment-key")
        assert mine != theirs
