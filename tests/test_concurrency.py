"""Properties that only appear when more than one writer is running.

Coverage cannot see these: the code paths execute fine single-threaded and
still lose data in production. The index write guard was added by reasoning
about a race and verified sequentially; this is that reasoning actually put
under contention, alongside the audit log's claimed in-process thread
safety and the crash-recovery sweep racing the daemon that is still
running.
"""

import multiprocessing
import shutil
import threading
from datetime import date
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq
import pymupdf
import pytest

from dlpduck.audit import AuditLog
from dlpduck.config import Config
from dlpduck.index import (
    AssessmentExists,
    compact_partition,
    index_row,
    plan_compaction,
    write_row,
)
from dlpduck.pipeline import Pipeline
from dlpduck.reprocess import latest_index_rows

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
    src = tmp_path / "drops"
    src.mkdir()
    return Config.model_validate(
        {
            "source": {"name": "t", "path": str(src), "metadata_format": "none"},
            "destination": {
                "archive": str(tmp_path / "archive"),
                "quarantine": str(tmp_path / "quarantine"),
                "work_dir": str(tmp_path / "work"),
            },
            "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
        }
    )


def _pdf(path: Path, lines: list[str]) -> Path:
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    y = 40
    for line in lines:
        page.insert_text((40, y), line)
        y += 20
    doc.save(path)
    return path


class TestAuditLogUnderConcurrentAppends:
    """AuditLog documents itself as thread-safe within a process. The
    chain makes that testable: any interleaving of the read-modify-write
    on _prev_hash would show up as a broken link or a duplicate seq."""

    def test_the_chain_survives_many_threads_appending_at_once(self, tmp_path):
        log = AuditLog(tmp_path)
        threads, per_thread = 12, 40
        errors: list[Exception] = []

        def hammer(n: int) -> None:
            try:
                for i in range(per_thread):
                    log.append("job.completed", job_id=f"{n:032x}", n=i)
            except Exception as exc:  # pragma: no cover - failure path under test
                errors.append(exc)

        workers = [threading.Thread(target=hammer, args=(n,)) for n in range(threads)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()

        assert not errors
        ok, breaks = log.verify()
        assert ok, [b.detail for b in breaks]

    def test_every_append_gets_a_distinct_contiguous_sequence(self, tmp_path):
        log = AuditLog(tmp_path)
        threads, per_thread = 12, 40

        def hammer(n: int) -> None:
            for i in range(per_thread):
                log.append("job.completed", job_id=f"{n:032x}", n=i)

        workers = [threading.Thread(target=hammer, args=(n,)) for n in range(threads)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()

        seqs = sorted(e["seq"] for e in log.events(limit=10**6))
        assert seqs == list(range(1, threads * per_thread + 1))


class TestAssessmentWritesUnderContention:
    """The append-only history's sequence number is chosen by reading the
    current highest and adding one, so every concurrent writer picks the
    same one. Exactly one may win; the rest must be refused rather than
    overwriting an assessment the audit trail already recorded.
    """

    def _ingested(self, tmp_path, config):
        pipeline = Pipeline(config)
        ctx = pipeline.run_job(
            _pdf(tmp_path / "doc.pdf", ["ordinary content"]),
            None,
            config.destination.work_dir / "_processing",
        )
        row = latest_index_rows(pipeline.index_root, job_ids=[ctx.job_id])[0]
        return pipeline, ctx.job_id, row

    def test_exactly_one_writer_wins_the_same_sequence_number(self, tmp_path, config):
        pipeline, job_id, row = self._ingested(tmp_path, config)
        racers = 12
        start = threading.Barrier(racers)
        won: list[int] = []
        lost: list[int] = []

        def race(n: int) -> None:
            mine = dict(row)
            mine["reason"] = f"writer-{n}"
            start.wait()  # release them together
            try:
                write_row(
                    pipeline.index_root, mine, dt=row["received_at"].date(),
                    job_id=job_id, assessment_seq=2, exclusive=True,
                )
                won.append(n)
            except AssessmentExists:
                lost.append(n)

        workers = [threading.Thread(target=race, args=(n,)) for n in range(racers)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()

        assert len(won) == 1, f"{len(won)} writers believed they won"
        assert len(lost) == racers - 1

    def test_the_winners_assessment_is_what_survives_on_disk(self, tmp_path, config):
        pipeline, job_id, row = self._ingested(tmp_path, config)
        racers = 12
        start = threading.Barrier(racers)
        won: list[int] = []

        def race(n: int) -> None:
            mine = dict(row)
            mine["reason"] = f"writer-{n}"
            start.wait()
            try:
                write_row(
                    pipeline.index_root, mine, dt=row["received_at"].date(),
                    job_id=job_id, assessment_seq=2, exclusive=True,
                )
                won.append(n)
            except AssessmentExists:
                pass

        workers = [threading.Thread(target=race, args=(n,)) for n in range(racers)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()

        files = sorted(pipeline.index_root.glob(f"dt=*/{job_id}_0002.parquet"))
        assert len(files) == 1  # no torn or duplicate assessment
        stored = pq.read_table(files[0]).to_pylist()[0]
        assert stored["reason"] == f"writer-{won[0]}"


class TestConcurrentIngestOfTheSameDocument:
    """job_id is content-derived, so the same document arriving twice is
    the same job. Two workers claiming it at once must not corrupt the
    archive or produce two conflicting index rows."""

    def test_the_same_pdf_ingested_twice_concurrently_stays_one_job(self, tmp_path, config):
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        source = _pdf(tmp_path / "twin.pdf", ["the very same content"])
        drops = config.source.path
        first, second = drops / "a.pdf", drops / "b.pdf"
        first.write_bytes(source.read_bytes())
        second.write_bytes(source.read_bytes())

        start = threading.Barrier(2)
        errors: list[Exception] = []

        def ingest(path: Path) -> None:
            start.wait()
            try:
                pipeline.run_job(path, None, staging)
            except Exception as exc:
                errors.append(exc)

        workers = [threading.Thread(target=ingest, args=(p,)) for p in (first, second)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()

        # Whatever the interleaving, the archive holds one document and the
        # index describes one job — not two halves of a race.
        archived = list(config.destination.archive.glob("dt=*/*.pdf"))
        assert len(archived) == 1, [p.name for p in archived]
        assert len({r["job_id"] for r in latest_index_rows(pipeline.index_root)} ) == 1


class TestACrashMidWriteCannotBreakTheWholeStore:
    """Both Parquet stores are read through a `dt=*/*.parquet` glob, so a
    single file without a footer fails every query over it. A `kill -9` or
    a full disk while committing one job would otherwise take down the
    jobs list, search and reprocess for *every* job — until an operator
    worked out which file to delete.
    """

    def _store_reads_cleanly(self, root: Path) -> int:
        if not list(root.glob("dt=*/*.parquet")):
            return 0  # an empty store reads fine; DuckDB just won't glob it
        con = duckdb.connect()
        try:
            glob = str(root / "dt=*" / "*.parquet")
            return con.execute(
                f"SELECT count(*) FROM read_parquet('{glob}', "  # noqa: S608
                "hive_partitioning=true, union_by_name=true)"
            ).fetchone()[0]
        finally:
            con.close()

    def test_an_interrupted_content_write_leaves_no_file_at_all(self, config, tmp_path, monkeypatch):
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        pipeline.run_job(_pdf(tmp_path / "first.pdf", ["An ordinary memo."]), None, staging)
        content_root = config.destination.work_dir / "content"
        assert self._store_reads_cleanly(content_root) == 1

        real_write = pq.write_table

        def die_midway(table, where, **kwargs):
            real_write(table, where, **kwargs)  # a real, complete temp file
            raise OSError(28, "No space left on device")  # ...then the disk fills

        monkeypatch.setattr(pq, "write_table", die_midway)
        with pytest.raises(OSError):
            pipeline.run_job(_pdf(tmp_path / "second.pdf", ["Another memo."]), None, staging)
        monkeypatch.setattr(pq, "write_table", real_write)

        assert not list(content_root.glob("dt=*/*.tmp"))
        assert self._store_reads_cleanly(content_root) == 1, "the store still reads"

    def test_a_truncated_temp_file_never_becomes_a_real_one(self, config, tmp_path, monkeypatch):
        """The sharper case: the library wrote *something*, just not all
        of it. Renaming that into place is what breaks the store."""
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        content_root = config.destination.work_dir / "content"

        real_write = pq.write_table

        def truncate_midway(table, where, **kwargs):
            real_write(table, where, **kwargs)
            data = Path(where).read_bytes()
            Path(where).write_bytes(data[: len(data) // 2])  # footer gone
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(pq, "write_table", truncate_midway)
        with pytest.raises(OSError):
            pipeline.run_job(_pdf(tmp_path / "doc.pdf", ["A memo."]), None, staging)
        monkeypatch.setattr(pq, "write_table", real_write)

        assert self._store_reads_cleanly(content_root) == 0
        assert not list(content_root.glob("dt=*/*.parquet"))

    def test_the_index_race_guard_survives_the_change(self, config, tmp_path):
        """Exclusivity now comes from os.link rather than an O_EXCL open;
        two writers racing for one assessment number must still leave one
        refusal, not one silent overwrite."""
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(_pdf(tmp_path / "doc.pdf", ["A memo."]), None, staging)
        index_root = config.destination.work_dir / "index"
        row = index_row(ctx, "somewhere.pdf", assessment_seq=2)

        write_row(
            index_root, row, dt=ctx.received_at.date(), job_id=ctx.job_id,
            assessment_seq=2, exclusive=True,
        )
        with pytest.raises(AssessmentExists):
            write_row(
                index_root, row, dt=ctx.received_at.date(), job_id=ctx.job_id,
                assessment_seq=2, exclusive=True,
            )

    def test_a_refused_exclusive_write_leaves_no_debris(self, config, tmp_path):
        """os.link leaves the temp file behind on success and on failure;
        neither may end up in the store's glob."""
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ctx = pipeline.run_job(_pdf(tmp_path / "doc.pdf", ["A memo."]), None, staging)
        index_root = config.destination.work_dir / "index"
        row = index_row(ctx, "somewhere.pdf", assessment_seq=2)

        kwargs = dict(
            dt=ctx.received_at.date(), job_id=ctx.job_id, assessment_seq=2, exclusive=True
        )
        write_row(index_root, row, **kwargs)
        with pytest.raises(AssessmentExists):
            write_row(index_root, row, **kwargs)

        assert not list(index_root.glob("dt=*/*.tmp"))
        assert self._store_reads_cleanly(index_root) == 2


def _audit_writer(root: str, tag: str, count: int) -> None:
    """Module-level so it can be pickled for a real subprocess."""
    from dlpduck.audit import AuditLog

    log = AuditLog(Path(root))
    for i in range(count):
        log.append("job.completed", job_id=f"{tag}{i:028d}")


class TestTheAuditLogSurvivesTheDocumentedDeployment:
    """`dlpduck run` and `dlpduck console run` are two processes over one
    work_dir — the quick start says so — and the console appends on every
    search, PDF view, purge and login. "One writer" was an assumption the
    documented setup broke on the first search anyone ran: the console
    cached the chain head at startup, so its first event chained from a
    stale hash and reused a sequence number.

    A false tampering alarm is worse than none. It teaches an operator
    that verify-audit failing means nothing.
    """

    def test_two_writers_in_one_process_still_chain(self, tmp_path):
        """The cheap version of the bug: two AuditLog instances, which is
        exactly what two processes look like (the thread lock is
        per-instance)."""
        root = tmp_path / "audit"
        daemon = AuditLog(root)
        console = AuditLog(root)

        daemon.append("job.completed", job_id="a" * 32)
        console.append("ui.search", actor="ivy", query="acme")
        daemon.append("job.completed", job_id="b" * 32)

        result = AuditLog(root).verify()
        assert result.ok, [b.detail for b in result.breaks]
        assert sorted(e["seq"] for e in AuditLog(root).events(limit=50)) == [1, 2, 3]

    def test_concurrent_processes_lose_nothing_and_reuse_no_sequence(self, tmp_path):
        root = tmp_path / "audit"
        per_process, writers = 25, 4
        procs = [
            multiprocessing.Process(
                target=_audit_writer, args=(str(root), chr(97 + k), per_process)
            )
            for k in range(writers)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=120)

        assert all(p.exitcode == 0 for p in procs), [p.exitcode for p in procs]
        events = AuditLog(root).events(limit=10_000)
        seqs = sorted(e["seq"] for e in events)
        assert len(events) == per_process * writers, "an append was lost"
        assert seqs == list(range(1, len(seqs) + 1)), "a sequence number was reused or skipped"
        assert AuditLog(root).verify().ok

    def test_a_reader_is_never_blocked_by_a_writer(self, tmp_path):
        """verify() and events() take no lock — an operator reading the
        trail must not be able to stall ingestion, and vice versa."""
        root = tmp_path / "audit"
        log = AuditLog(root)
        log.append("job.completed", job_id="a" * 32)

        with log._appending():  # a writer holding the lock
            assert AuditLog(root).events(limit=10)
            assert AuditLog(root).verify().ok


class TestCompactionKeepsTheGuarantees:
    """Compaction merges a day's assessment files into one, which frees
    every historical `<job>_<seq>.parquet` name. Those names ARE the
    exclusive-write guard, so this is the place to prove nothing that
    depended on them broke.
    """

    def _ingest(self, tmp_path, config, n=3):
        pipeline = Pipeline(config)
        staging = config.destination.work_dir / "_processing"
        ids = []
        for i in range(n):
            pdf = _pdf(tmp_path / f"doc{i}.pdf", [f"ordinary memo number {i}"])
            ids.append(pipeline.run_job(pdf, None, staging).job_id)
        return pipeline, ids

    def _age_partition(self, pipeline):
        """Compaction skips today, so move the partition into the past."""
        [partition] = list(pipeline.index_root.glob("dt=*"))
        old = pipeline.index_root / "dt=2020-01-01"
        shutil.move(str(partition), str(old))
        return old

    def test_every_row_survives(self, tmp_path, config):
        pipeline, ids = self._ingest(tmp_path, config, n=5)
        self._age_partition(pipeline)
        before = {r["job_id"] for r in latest_index_rows(pipeline.index_root)}

        for plan in plan_compaction(pipeline.index_root):
            compact_partition(plan)

        after = {r["job_id"] for r in latest_index_rows(pipeline.index_root)}
        assert after == before
        assert len(list(pipeline.index_root.glob("dt=*/*.parquet"))) == 1

    def test_todays_partition_is_left_alone(self, tmp_path, config):
        """It is still being appended to, and compacting underneath a live
        writer would race the guard that stops two writers clobbering one
        assessment."""
        pipeline, _ = self._ingest(tmp_path, config, n=3)
        assert plan_compaction(pipeline.index_root) == []

    def test_the_assessment_history_is_preserved(self, tmp_path, config):
        """Several assessments of one job must still read back in order —
        the history is the record, not just the latest verdict."""
        pipeline, ids = self._ingest(tmp_path, config, n=1)
        job_id = ids[0]
        row = latest_index_rows(pipeline.index_root, job_ids=[job_id])[0]
        for seq in (2, 3):
            extra = dict(row)
            extra["assessment_seq"] = seq
            extra["reason"] = f"seq-{seq}"
            write_row(
                pipeline.index_root, extra, dt=row["received_at"].date(),
                job_id=job_id, assessment_seq=seq, exclusive=True,
            )
        self._age_partition(pipeline)

        for plan in plan_compaction(pipeline.index_root):
            compact_partition(plan)

        [current] = latest_index_rows(pipeline.index_root, job_ids=[job_id])
        assert current["assessment_seq"] == 3
        assert current["reason"] == "seq-3"

    def test_an_interrupted_compaction_costs_space_and_nothing_else(self, tmp_path, config):
        """The merged file is made visible BEFORE the originals go, so a
        crash leaves every row present twice — which every reader already
        collapses. The other order would have a window with no rows."""
        pipeline, ids = self._ingest(tmp_path, config, n=4)
        partition = self._age_partition(pipeline)
        expected = {r["job_id"] for r in latest_index_rows(pipeline.index_root)}
        [plan] = plan_compaction(pipeline.index_root)

        # Merge, but die before removing any original.
        merged = partition / f"compacted-{partition.name.removeprefix('dt=')}.parquet"
        table = pa.concat_tables(
            [pq.read_table(f) for f in plan.files], promote_options="permissive"
        )
        pq.write_table(table, merged, compression="snappy")

        assert len(list(partition.glob("*.parquet"))) == len(plan.files) + 1
        rows = latest_index_rows(pipeline.index_root)
        assert {r["job_id"] for r in rows} == expected
        assert len(rows) == len(expected), "a duplicated row became a duplicated job"

    def test_rerunning_compaction_is_a_no_op(self, tmp_path, config):
        pipeline, _ = self._ingest(tmp_path, config, n=3)
        self._age_partition(pipeline)
        for plan in plan_compaction(pipeline.index_root):
            compact_partition(plan)

        assert plan_compaction(pipeline.index_root) == []

    def test_the_race_guard_still_refuses_a_duplicate_next_assessment(
        self, tmp_path, config
    ):
        """The guard exists for two writers choosing the same *next*
        sequence number. Compaction frees historical names, so this proves
        the case it actually protects is untouched: both writers still
        collide on the same new filename."""
        pipeline, ids = self._ingest(tmp_path, config, n=1)
        job_id = ids[0]
        row = latest_index_rows(pipeline.index_root, job_ids=[job_id])[0]
        partition = self._age_partition(pipeline)
        for plan in plan_compaction(pipeline.index_root):
            compact_partition(plan)

        dt = date.fromisoformat(partition.name.removeprefix("dt="))
        kwargs = dict(dt=dt, job_id=job_id, assessment_seq=2, exclusive=True)
        write_row(pipeline.index_root, dict(row), **kwargs)
        with pytest.raises(AssessmentExists):
            write_row(pipeline.index_root, dict(row), **kwargs)
