"""Retention is opt-in per store (no window configured = kept
forever), a directory delete keyed on the dt= partition name, and the
audit store specifically needs a checkpoint before deletion so an
authorized trim doesn't look like tampering to verify().
"""

from datetime import date, timedelta
from pathlib import Path

import pytest

from dlpduck.audit import AuditLog
from dlpduck.config import Config
from dlpduck.retention import (
    RetentionPlan,
    apply_retention,
    eligible_failures,
    eligible_partitions,
    plan_retention,
)

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


def _config(tmp_path: Path, retention: dict | None = None) -> Config:
    src = tmp_path / "drops"
    src.mkdir(exist_ok=True)
    data = {
        "source": {"name": "t", "path": str(src), "metadata_format": "none"},
        "destination": {
            "archive": str(tmp_path / "archive"),
            "quarantine": str(tmp_path / "quarantine"),
            "work_dir": str(tmp_path / "work"),
        },
        "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
    }
    if retention:
        data["retention"] = retention
    return Config.model_validate(data)


def _touch_partition(root: Path, dt: date, filename: str = "x.parquet") -> Path:
    partition = root / f"dt={dt.isoformat()}"
    partition.mkdir(parents=True, exist_ok=True)
    (partition / filename).write_bytes(b"x")
    return partition


class TestEligiblePartitions:
    def test_partitions_older_than_cutoff_are_eligible(self, tmp_path):
        old = _touch_partition(tmp_path, date(2020, 1, 1))
        _touch_partition(tmp_path, date.today())

        eligible = eligible_partitions(tmp_path, cutoff=date.today() - timedelta(days=30))

        assert eligible == [old]

    def test_nonexistent_root_returns_empty(self, tmp_path):
        assert eligible_partitions(tmp_path / "does_not_exist", cutoff=date.today()) == []

    def test_malformed_partition_names_are_ignored_not_errored(self, tmp_path):
        (tmp_path / "dt=not-a-date").mkdir()
        (tmp_path / "not-a-partition-at-all").mkdir()
        eligible = eligible_partitions(tmp_path, cutoff=date(2099, 1, 1))
        assert eligible == []

    def test_exactly_at_cutoff_is_not_eligible(self, tmp_path):
        cutoff = date(2026, 1, 1)
        _touch_partition(tmp_path, cutoff)
        assert eligible_partitions(tmp_path, cutoff=cutoff) == []


class TestPlanRetention:
    def test_no_config_means_nothing_is_planned(self, tmp_path):
        config = _config(tmp_path)  # no retention section at all
        plans = plan_retention(config)
        assert all(p.cutoff is None and p.eligible == [] for p in plans)

    def test_documents_days_covers_archive_quarantine_and_content_together(self, tmp_path):
        config = _config(tmp_path, {"documents_days": 30})
        old = date.today() - timedelta(days=40)
        _touch_partition(config.destination.archive, old)
        _touch_partition(config.destination.quarantine, old)
        _touch_partition(config.destination.work_dir / "content", old)
        failed = config.destination.work_dir / "failed" / ("a" * 32)
        failed.mkdir(parents=True)
        (failed / "metadata.json").write_text(
            '{"received_at":"' + old.isoformat() + 'T00:00:00+00:00"}'
        )

        plans = plan_retention(config)
        by_store = {p.store: p for p in plans}

        assert len(by_store["archive"].eligible) == 1
        assert len(by_store["quarantine"].eligible) == 1
        assert len(by_store["content"].eligible) == 1
        assert by_store["failed"].eligible == [failed]
        assert by_store["index"].eligible == []  # not configured
        assert by_store["audit"].eligible == []  # not configured

    def test_malformed_failed_job_is_retained_for_inspection(self, tmp_path):
        root = tmp_path / "failed"
        malformed = root / ("b" * 32)
        malformed.mkdir(parents=True)
        (malformed / "metadata.json").write_text("not json")

        assert eligible_failures(root, date(2099, 1, 1)) == []

    def test_index_and_audit_have_independent_windows(self, tmp_path):
        config = _config(tmp_path, {"index_days": 10, "audit_days": 100})
        config.audit.path = tmp_path / "separate-audit"
        near_old = date.today() - timedelta(days=20)  # past index window, not audit's
        _touch_partition(config.destination.work_dir / "index", near_old)
        _touch_partition(config.audit_dir, near_old)

        plans = plan_retention(config)
        by_store = {p.store: p for p in plans}

        assert len(by_store["index"].eligible) == 1
        assert by_store["audit"].root == config.audit_dir
        assert by_store["audit"].eligible == []  # 20 days < 100-day window

    def test_recent_partitions_are_never_eligible(self, tmp_path):
        config = _config(tmp_path, {"documents_days": 30})
        _touch_partition(config.destination.archive, date.today())

        plans = plan_retention(config)
        assert next(p for p in plans if p.store == "archive").eligible == []


class TestApplyRetention:
    def test_apply_deletes_eligible_partitions(self, tmp_path):
        config = _config(tmp_path, {"documents_days": 30})
        old = _touch_partition(config.destination.archive, date.today() - timedelta(days=40))
        new = _touch_partition(config.destination.archive, date.today())

        plans = plan_retention(config)
        audit = AuditLog(config.destination.work_dir / "audit")
        removed = apply_retention(plans, audit)

        assert removed == 1
        assert not old.exists()
        assert new.exists()

    def test_apply_is_a_noop_when_nothing_is_eligible(self, tmp_path):
        config = _config(tmp_path, {"documents_days": 30})
        _touch_partition(config.destination.archive, date.today())

        plans = plan_retention(config)
        audit = AuditLog(config.destination.work_dir / "audit")
        removed = apply_retention(plans, audit)

        assert removed == 0

    def test_dry_run_plan_alone_deletes_nothing(self, tmp_path):
        config = _config(tmp_path, {"documents_days": 30})
        old = _touch_partition(config.destination.archive, date.today() - timedelta(days=40))

        plan_retention(config)  # planning alone must have no side effects

        assert old.exists()

    def test_audit_partitions_are_checkpointed_before_deletion(self, tmp_path):
        config = _config(tmp_path, {"audit_days": 30})
        audit = AuditLog(config.destination.work_dir / "audit", integrity="chained")
        for i in range(3):
            audit.append("job.completed", job_id=f"old{i}")

        [old_partition] = list((config.destination.work_dir / "audit").glob("dt=*"))
        # Backdate it past the retention window without touching the
        # events themselves — same technique as test_audit.py.
        old_dir = old_partition.parent / "dt=2020-01-01"
        old_partition.rename(old_dir)

        plans = plan_retention(config)
        assert len(next(p for p in plans if p.store == "audit").eligible) == 1

        removed = apply_retention(plans, audit)
        assert removed == 1
        assert not old_dir.exists()

        # A fresh AuditLog picks up the checkpoint and keeps chaining.
        audit2 = AuditLog(config.destination.work_dir / "audit", integrity="chained")
        audit2.append("job.completed", job_id="new1")
        ok, breaks = audit2.verify()
        assert ok is True
        assert breaks == []


class TestRetentionRecordsIntentBeforeDeleting:
    """Retention deletes in bulk, so an interrupted sweep is the widest
    unrecorded-deletion window in the system."""

    def _events(self, audit):
        import json

        out = []
        for log in audit.root.glob("dt=*/events.jsonl"):
            out += [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
        return out

    def test_started_is_recorded_before_applied(self, tmp_path):
        audit = AuditLog(tmp_path / "audit")
        root = tmp_path / "content"
        old = root / "dt=2020-01-01"
        old.mkdir(parents=True)
        (old / "x.parquet").write_bytes(b"x")
        plans = [RetentionPlan(store="content", root=root, cutoff=date(2026, 1, 1), eligible=[old])]

        apply_retention(plans, audit)

        events = self._events(audit)
        started = [e for e in events if e["event"] == "retention.started"]
        applied = [e for e in events if e["event"] == "retention.applied"]
        assert started and applied
        assert started[0]["seq"] < applied[0]["seq"]
        assert started[0]["partitions"] == ["dt=2020-01-01"]
        assert not old.exists()

    def test_an_interrupted_sweep_still_says_it_began(self, tmp_path, monkeypatch):
        audit = AuditLog(tmp_path / "audit")
        root = tmp_path / "content"
        old = root / "dt=2020-01-01"
        old.mkdir(parents=True)
        (old / "x.parquet").write_bytes(b"x")
        plans = [RetentionPlan(store="content", root=root, cutoff=date(2026, 1, 1), eligible=[old])]

        def _die(*_args, **_kwargs):
            raise RuntimeError("killed mid-sweep")

        monkeypatch.setattr("dlpduck.retention.shutil.rmtree", _die)
        with pytest.raises(RuntimeError):
            apply_retention(plans, audit)

        events = self._events(audit)
        assert [e for e in events if e["event"] == "retention.started"]
        assert not [e for e in events if e["event"] == "retention.applied"]
