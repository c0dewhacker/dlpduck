"""Behaviour that only goes wrong once there is a lot of data.

The audit trail is the store that grows without bound — retention is
opt-in, so a deployment that never configures it keeps every event
forever. The console reads it on the /audit page and on every job detail
page, which makes "how does this read behave at a year of traffic" a
correctness question rather than a performance footnote: reading a year
into memory to render 500 rows is how a console stops being usable.

These build a synthetic corpus rather than measure wall-clock thresholds,
so they assert on work done (rows read, memory held) instead of timings
that would be flaky on a loaded machine.
"""

import json
import tracemalloc
from datetime import date

import pytest

from dlpduck.audit import AuditLog

DAYS = 120
PER_DAY = 200


@pytest.fixture(scope="module")
def big_log(tmp_path_factory):
    root = tmp_path_factory.mktemp("audit-scale")
    seq = 0
    for d in range(DAYS):
        partition = root / f"dt=2026-{(d // 30) + 1:02d}-{(d % 30) + 1:02d}"
        partition.mkdir(parents=True, exist_ok=True)
        with open(partition / "events.jsonl", "a") as f:
            for i in range(PER_DAY):
                seq += 1
                f.write(
                    json.dumps(
                        {
                            "seq": seq,
                            "ts": "2026-01-01T00:00:00Z",
                            "event": "job.completed",
                            "job_id": f"{i:032x}",
                            "hits": [],
                        }
                    )
                    + "\n"
                )
    return AuditLog(root, integrity="none"), seq


class TestTheAuditBrowserStaysBounded:
    def test_a_page_does_not_load_the_whole_history_into_memory(self, big_log):
        """The /audit page asks for 500 rows. It used to read every event
        in range, sort, and throw the rest away — 127MB for one page on a
        year of modest traffic, growing forever."""
        log, total = big_log
        assert total == DAYS * PER_DAY  # the corpus really is large

        tracemalloc.start()
        try:
            events = log.events(limit=500)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

        assert len(events) == 500
        # Generous, but far below the ~50MB+ that holding the corpus costs.
        assert peak < 10_000_000, f"held {peak / 1e6:.0f}MB to render 500 rows"

    def test_it_still_returns_the_newest_events(self, big_log):
        log, total = big_log
        events = log.events(limit=500)

        assert [e["seq"] for e in events] == list(range(total, total - 500, -1))

    def test_a_smaller_limit_reads_even_less(self, big_log):
        log, total = big_log
        events = log.events(limit=10)

        assert [e["seq"] for e in events] == list(range(total, total - 10, -1))

    def test_asking_for_more_than_exists_is_not_an_error(self, tmp_path):
        log = AuditLog(tmp_path, integrity="none")
        for _ in range(5):
            log.append("job.completed", job_id="a" * 32)

        assert len(log.events(limit=500)) == 5

    def test_a_date_filter_still_bounds_the_result(self, big_log):
        log, _ = big_log
        events = log.events(start=date(2026, 1, 1), end=date(2026, 1, 2), limit=10_000)

        assert len(events) == 2 * PER_DAY
        assert all(e["seq"] <= 2 * PER_DAY for e in events)

    def test_the_early_stop_does_not_skip_a_partition_boundary(self, big_log):
        """A limit that lands mid-partition must still come back with a
        contiguous newest-first run, not a gap where the read stopped."""
        log, total = big_log
        events = log.events(limit=PER_DAY + 50)

        seqs = [e["seq"] for e in events]
        assert seqs == list(range(total, total - (PER_DAY + 50), -1))


class TestAJobTimelineStaysCheap:
    def test_one_job_is_found_without_decoding_every_record(self, big_log):
        """events_for_job has to look in every partition — a purge lands
        years after ingest — but it should not JSON-decode 24,000 records
        to find the handful that mention one job."""
        log, _ = big_log
        tracemalloc.start()
        try:
            events = log.events_for_job(f"{5:032x}")
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

        assert len(events) == DAYS  # one per day, as seeded
        assert peak < 10_000_000, f"held {peak / 1e6:.0f}MB for one job's timeline"

    def test_the_timeline_is_oldest_first_and_complete(self, big_log):
        log, _ = big_log
        events = log.events_for_job(f"{7:032x}")

        seqs = [e["seq"] for e in events]
        assert seqs == sorted(seqs)
        assert len(seqs) == DAYS

    def test_a_job_with_no_events_returns_nothing(self, big_log):
        log, _ = big_log
        assert log.events_for_job("f" * 32) == []

    def test_a_job_id_appearing_only_as_a_substring_does_not_match(self, tmp_path):
        """The pre-filter is a substring test, so the parse still has to be
        what decides — otherwise a longer id containing a shorter one would
        pull in the wrong events."""
        log = AuditLog(tmp_path, integrity="none")
        partition = tmp_path / "dt=2026-01-01"
        partition.mkdir()
        (partition / "events.jsonl").write_text(
            json.dumps({"seq": 1, "event": "job.completed", "job_id": "a" * 32}) + "\n"
            + json.dumps({"seq": 2, "event": "job.completed", "job_id": "b" * 32,
                          "note": "mentions " + "a" * 32}) + "\n"
        )

        events = log.events_for_job("a" * 32)

        assert [e["seq"] for e in events] == [1]


# --- the index side -------------------------------------------------------

from datetime import UTC, datetime, timedelta  # noqa: E402

import pyarrow as pa  # noqa: E402
import pyarrow.parquet as pq  # noqa: E402

from dlpduck.reprocess import index_stats, latest_index_rows  # noqa: E402
from dlpduck.schema import INDEX_SCHEMA  # noqa: E402

INDEX_DAYS = 40
JOBS_PER_DAY = 250


@pytest.fixture(scope="module")
def big_index(tmp_path_factory):
    root = tmp_path_factory.mktemp("index-scale") / "index"
    base = datetime(2026, 1, 1, 12, tzinfo=UTC)
    n = 0
    for d in range(INDEX_DAYS):
        day = base + timedelta(days=d)
        partition = root / f"dt={day.date().isoformat()}"
        partition.mkdir(parents=True, exist_ok=True)
        rows = [
            {
                "job_id": f"{n + i:032x}", "received_at": day, "assessed_at": day,
                "assessment_seq": 1, "ruleset_version": "v1", "supersedes_seq": None,
                "release_pending": i % 50 == 0, "source_name": "t", "page_count": 1,
                "ocr_page_count": 0, "min_ocr_confidence": None, "degraded": False,
                "disposition": "quarantine" if i % 10 == 0 else "archive", "reason": None,
                "archive_path": "/a/x.pdf", "pdf_sha256": "x", "flagged": False,
                "highest_severity": None, "hit_count": 0, "rule_ids": [], "hits": [],
                "metadata": "{}", "audit_fields": "{}",
            }
            for i in range(JOBS_PER_DAY)
        ]
        n += JOBS_PER_DAY
        pq.write_table(pa.Table.from_pylist(rows, schema=INDEX_SCHEMA), partition / "b.parquet")
    return root, n, base


class TestTheJobListIsBounded:
    def test_a_page_holds_a_page_not_the_whole_index(self, big_index):
        root, total, _ = big_index
        tracemalloc.start()
        try:
            rows = latest_index_rows(root, limit=501, newest_first=True)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

        assert len(rows) == 501
        assert total > 501  # there really is more behind it
        assert peak < 10_000_000, f"held {peak / 1e6:.0f}MB for one page"

    def test_the_page_really_is_the_newest_jobs(self, big_index):
        root, _, base = big_index
        rows = latest_index_rows(root, limit=5, newest_first=True)

        newest_day = base + timedelta(days=INDEX_DAYS - 1)
        assert all(r["received_at"].date() == newest_day.date() for r in rows)

    def test_without_a_limit_the_behaviour_is_unchanged(self, big_index):
        root, total, _ = big_index
        assert len(latest_index_rows(root)) == total

    def test_a_date_filter_composes_with_the_limit(self, big_index):
        root, _, base = big_index
        day = (base + timedelta(days=2)).date()
        rows = latest_index_rows(root, start=day, end=day, limit=10, newest_first=True)

        assert len(rows) == 10
        assert all(r["received_at"].date() == day for r in rows)


class TestOverviewCountersAreComputedInSql:
    def test_counting_does_not_load_every_row(self, big_index):
        root, _, base = big_index
        tracemalloc.start()
        try:
            stats = index_stats(root, base.date())
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

        assert stats["total"] == INDEX_DAYS * JOBS_PER_DAY
        assert peak < 5_000_000, f"held {peak / 1e6:.0f}MB to count five integers"

    def test_the_counters_agree_with_a_full_scan(self, big_index):
        """The whole point of moving this into SQL is that it stays
        correct — so check it against the naive computation it replaced."""
        root, _, base = big_index
        stats = index_stats(root, base.date())
        rows = latest_index_rows(root)

        assert stats["total"] == len(rows)
        assert stats["quarantined"] == sum(1 for r in rows if r["disposition"] == "quarantine")
        assert stats["release_pending"] == sum(1 for r in rows if r["release_pending"])
        assert stats["today"] == sum(1 for r in rows if r["received_at"].date() == base.date())

    def test_an_empty_index_counts_zero_rather_than_failing(self, tmp_path):
        assert index_stats(tmp_path / "nothing", date(2026, 1, 1))["total"] == 0
