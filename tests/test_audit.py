import json
import os
import shutil
from datetime import UTC, date, datetime

import pytest

from dlpduck.audit import AuditLog


class TestChainedIntegrity:
    def test_events_chain_together(self, tmp_path):
        log = AuditLog(tmp_path, integrity="chained")
        e1 = log.append("job.completed", job_id="a")
        e2 = log.append("job.completed", job_id="b")
        assert e1["prev"] is None
        assert e2["prev"] == e1["hash"]
        assert e1["seq"] == 1
        assert e2["seq"] == 2

    def test_verify_passes_on_an_untouched_log(self, tmp_path):
        log = AuditLog(tmp_path, integrity="chained")
        for i in range(5):
            log.append("job.completed", job_id=str(i))
        ok, breaks = log.verify()
        assert ok is True
        assert breaks == []

    def test_verify_catches_a_rewritten_field(self, tmp_path):
        log = AuditLog(tmp_path, integrity="chained")
        log.append("job.completed", job_id="a", disposition="quarantine")
        log.append("job.completed", job_id="b")

        # Tamper: quietly change the first event's disposition, matching
        # its original hash's *position* but not its content.
        files = sorted(tmp_path.glob("dt=*/events.jsonl"))
        lines = files[0].read_text().splitlines()
        event = json.loads(lines[0])
        event["disposition"] = "archive"
        lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
        files[0].write_text("\n".join(lines) + "\n")

        ok, breaks = log.verify()
        assert ok is False
        assert len(breaks) >= 1

    def test_verify_catches_a_deleted_event(self, tmp_path):
        log = AuditLog(tmp_path, integrity="chained")
        log.append("job.completed", job_id="a")
        log.append("job.completed", job_id="b")
        log.append("job.completed", job_id="c")

        files = sorted(tmp_path.glob("dt=*/events.jsonl"))
        lines = files[0].read_text().splitlines()
        del lines[1]  # remove the middle event — b's hash no longer chains
        files[0].write_text("\n".join(lines) + "\n")

        ok, breaks = log.verify()
        assert ok is False

    def test_resuming_after_restart_continues_the_chain(self, tmp_path):
        log1 = AuditLog(tmp_path, integrity="chained")
        e1 = log1.append("job.completed", job_id="a")

        # Simulate a process restart: a fresh AuditLog over the same root
        # must resume from the last written hash, not start a new chain.
        log2 = AuditLog(tmp_path, integrity="chained")
        e2 = log2.append("job.completed", job_id="b")

        assert e2["prev"] == e1["hash"]
        assert e2["seq"] == 2
        ok, breaks = log2.verify()
        assert ok is True

    def test_events_never_carry_a_raw_matched_value(self, tmp_path):
        # This is a structural guard, not a content check: the AuditLog
        # itself has no field for cleartext, so a hit passed in must
        # already have been masked upstream — this test asserts
        # append() doesn't add anything beyond what's given.
        log = AuditLog(tmp_path, integrity="chained")
        event = log.append("job.completed", job_id="a", masked_text="••••1234")
        assert event["masked_text"] == "••••1234"


class TestTrimCheckpoint:
    """Retention deletes whole old dt= partitions. Naively doing
    that leaves the earliest surviving event's `prev` pointing at a hash
    nothing on disk can reproduce — verify() must not report that as
    tampering when a checkpoint explains it.
    """

    def _split_into_old_and_new_partitions(self, tmp_path):
        """Build one real 4-event chain via AuditLog, then physically
        split it into two dt= directories — 2 events in "old", 2 in
        "new" — to simulate what's left after retention removes the old
        one. The events themselves are untouched, so their prev/hash
        fields are exactly as a real multi-day chain would have them.
        """
        log = AuditLog(tmp_path, integrity="chained")
        for i in range(4):
            log.append("job.completed", job_id=f"job{i}")

        [today_dir] = list(tmp_path.glob("dt=*"))
        lines = (today_dir / "events.jsonl").read_text().splitlines()

        # Both dates must sort before "today" (where a real append lands)
        # so partition file ordering matches how real dt= directories are
        # only ever created moving forward in time.
        old_dir = tmp_path / "dt=2020-01-01"
        new_dir = tmp_path / "dt=2020-06-01"
        old_dir.mkdir()
        new_dir.mkdir()
        (old_dir / "events.jsonl").write_text("\n".join(lines[:2]) + "\n")
        (new_dir / "events.jsonl").write_text("\n".join(lines[2:]) + "\n")

        import shutil

        shutil.rmtree(today_dir)
        return old_dir, new_dir

    def test_verify_fails_without_a_checkpoint_after_a_naive_delete(self, tmp_path):
        # Establishes the problem this exists to fix: deleting the old
        # partition with no checkpoint makes an authorized trim look
        # exactly like tampering.
        old_dir, new_dir = self._split_into_old_and_new_partitions(tmp_path)
        shutil.rmtree(old_dir)

        log = AuditLog(tmp_path, integrity="chained")
        ok, breaks = log.verify()
        assert ok is False

    def test_checkpoint_then_delete_leaves_verify_passing(self, tmp_path):
        old_dir, new_dir = self._split_into_old_and_new_partitions(tmp_path)
        log = AuditLog(tmp_path, integrity="chained")

        checkpoint = log.write_trim_checkpoint([old_dir])
        assert checkpoint is not None
        shutil.rmtree(old_dir)

        ok, breaks = log.verify()
        assert ok is True
        assert breaks == []

    def test_checkpoint_records_the_last_event_of_the_partition_being_removed(self, tmp_path):
        old_dir, new_dir = self._split_into_old_and_new_partitions(tmp_path)
        log = AuditLog(tmp_path, integrity="chained")

        checkpoint = log.write_trim_checkpoint([old_dir])

        last_old_event = json.loads((old_dir / "events.jsonl").read_text().splitlines()[-1])
        assert checkpoint["hash"] == last_old_event["hash"]
        assert checkpoint["seq"] == last_old_event["seq"]

    def test_new_appends_still_chain_correctly_after_a_trim(self, tmp_path):
        old_dir, new_dir = self._split_into_old_and_new_partitions(tmp_path)
        log = AuditLog(tmp_path, integrity="chained")
        log.write_trim_checkpoint([old_dir])
        shutil.rmtree(old_dir)

        # Resume in a fresh instance, as a new CLI invocation would.
        log2 = AuditLog(tmp_path, integrity="chained")
        log2.append("job.completed", job_id="job4")

        ok, breaks = log2.verify()
        assert ok is True
        assert breaks == []

    def test_resume_falls_back_to_checkpoint_when_every_partition_is_gone(self, tmp_path):
        old_dir, new_dir = self._split_into_old_and_new_partitions(tmp_path)
        log = AuditLog(tmp_path, integrity="chained")
        log.write_trim_checkpoint([old_dir, new_dir])  # everything trimmed
        shutil.rmtree(old_dir)
        shutil.rmtree(new_dir)

        log2 = AuditLog(tmp_path, integrity="chained")
        event = log2.append("job.completed", job_id="job5")

        # Chains from the checkpoint, not from scratch (seq restarting at
        # 1 / prev=None would silently discard the fact that 4 events
        # already happened).
        assert event["seq"] == 5
        assert event["prev"] is not None

    def test_checkpoint_never_moves_backwards(self, tmp_path):
        old_dir, new_dir = self._split_into_old_and_new_partitions(tmp_path)
        log = AuditLog(tmp_path, integrity="chained")

        first = log.write_trim_checkpoint([old_dir, new_dir])
        second = log.write_trim_checkpoint([old_dir])  # smaller, later trim attempt

        assert second == first  # unchanged — never regresses to an earlier point

    def test_noop_when_integrity_is_none(self, tmp_path):
        log = AuditLog(tmp_path, integrity="none")
        log.append("job.completed", job_id="a")
        [partition] = tmp_path.glob("dt=*")

        assert log.write_trim_checkpoint([partition]) is None

    def test_noop_with_an_empty_partition_list(self, tmp_path):
        log = AuditLog(tmp_path, integrity="chained")
        log.append("job.completed", job_id="a")

        assert log.write_trim_checkpoint([]) is None


    def test_an_unreadable_checkpoint_does_not_stop_the_process_starting(self, tmp_path):
        """_resume runs in the constructor, so raising here would take
        the daemon and every CLI command down over one bad sidecar."""
        log = AuditLog(tmp_path, integrity="chained")
        log.append("job.completed", job_id="a")
        (tmp_path / ".chain_checkpoint.json").write_text("{truncated")

        reopened = AuditLog(tmp_path, integrity="chained")

        assert reopened.append("job.completed", job_id="b")["seq"] == 2

    def test_a_checkpoint_that_is_not_a_checkpoint_is_ignored(self, tmp_path):
        log = AuditLog(tmp_path, integrity="chained")
        log.append("job.completed", job_id="a")
        (tmp_path / ".chain_checkpoint.json").write_text('["not", "a", "checkpoint"]')

        assert AuditLog(tmp_path, integrity="chained").verify().ok

    def test_the_checkpoint_write_is_atomic(self, tmp_path, monkeypatch):
        """Retention deletes the accounted-for partitions the moment this
        returns, so a half-written checkpoint is unrecoverable: the events
        are gone and nothing left on disk explains their absence."""
        old_dir, new_dir = self._split_into_old_and_new_partitions(tmp_path)
        log = AuditLog(tmp_path, integrity="chained")
        log.write_trim_checkpoint([old_dir])
        before = (tmp_path / ".chain_checkpoint.json").read_text()

        def die(src, dst):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(os, "replace", die)
        with pytest.raises(OSError):
            log.write_trim_checkpoint([old_dir, new_dir])

        assert (tmp_path / ".chain_checkpoint.json").read_text() == before
        assert not list(tmp_path.glob("*.tmp"))


class TestIntegrityFlag:
    def test_none_produces_plain_events_without_chain_fields(self, tmp_path):
        log = AuditLog(tmp_path, integrity="none")
        event = log.append("job.completed", job_id="a")
        assert "prev" not in event
        assert "hash" not in event

    def test_none_verify_is_a_trivial_pass(self, tmp_path):
        log = AuditLog(tmp_path, integrity="none")
        log.append("job.completed", job_id="a")
        ok, breaks = log.verify()
        assert ok is True
        assert breaks == []

    def test_invalid_integrity_value_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            AuditLog(tmp_path, integrity="sometimes")


class TestEventsBrowser:
    def test_events_returns_everything_newest_first_by_default(self, tmp_path):
        log = AuditLog(tmp_path, integrity="chained")
        for i in range(3):
            log.append("job.completed", job_id=f"job{i}")

        events = log.events()

        assert [e["job_id"] for e in events] == ["job2", "job1", "job0"]

    def test_events_respects_the_limit(self, tmp_path):
        log = AuditLog(tmp_path, integrity="chained")
        for i in range(5):
            log.append("job.completed", job_id=f"job{i}")

        events = log.events(limit=2)

        assert len(events) == 2
        assert events[0]["job_id"] == "job4"  # still newest first

    def test_date_range_excludes_partitions_outside_it(self, tmp_path):
        log = AuditLog(tmp_path, integrity="chained")
        log.append("job.completed", job_id="today")

        old_dir = tmp_path / "dt=2020-01-01"
        old_dir.mkdir()
        (old_dir / "events.jsonl").write_text(
            '{"seq":1,"ts":"x","event":"job.completed","job_id":"old"}\n'
        )

        # UTC, not date.today(): partitions are named from
        # datetime.now(UTC).date(), so east of UTC the local date can
        # already be tomorrow and this filter would exclude the partition
        # the event was just written to. That is a real difference the
        # console's date filters inherit, not a test detail.
        events = log.events(start=datetime.now(UTC).date())
        assert [e["job_id"] for e in events] == ["today"]

        events_all = log.events(start=date(2019, 1, 1))
        assert {e["job_id"] for e in events_all} == {"today", "old"}

    def test_empty_log_returns_empty(self, tmp_path):
        log = AuditLog(tmp_path, integrity="chained")
        assert log.events() == []


class TestFsyncDurability:
    def test_append_is_immediately_visible_on_disk(self, tmp_path):
        log = AuditLog(tmp_path, integrity="chained")
        log.append("job.completed", job_id="a")
        files = list(tmp_path.glob("dt=*/events.jsonl"))
        assert len(files) == 1
        assert json.loads(files[0].read_text().splitlines()[0])["job_id"] == "a"


class TestACorruptRecordDoesNotTakeDownTheTrail:
    """A truncated final line is the ordinary shape of a crash or a full
    disk — the exact moment the audit trail matters most. One unreadable
    byte used to make the whole trail unreadable: the /audit screen, every
    job page rendering a timeline, verify-audit, and the daemon's own
    startup all raised JSONDecodeError.
    """

    def _log_with_a_truncated_tail(self, tmp_path):
        log = AuditLog(tmp_path)
        for i in range(3):
            log.append("job.completed", job_id="a" * 32, n=i)
        [events_file] = tmp_path.glob("dt=*/events.jsonl")
        events_file.write_text(events_file.read_text() + '{"seq":4,"event":"job.comple')
        return log, events_file

    def test_the_daemon_can_still_start(self, tmp_path):
        self._log_with_a_truncated_tail(tmp_path)
        resumed = AuditLog(tmp_path)  # this used to raise
        assert resumed._seq == 3  # resumes from the last record that parses

    def test_a_new_event_continues_the_chain_after_the_bad_line(self, tmp_path):
        self._log_with_a_truncated_tail(tmp_path)
        resumed = AuditLog(tmp_path)
        event = resumed.append("job.completed", job_id="b" * 32)
        assert event["seq"] == 4
        assert event["prev"] is not None

    def test_the_readable_history_is_still_readable(self, tmp_path):
        log, _ = self._log_with_a_truncated_tail(tmp_path)
        assert len(log.events()) == 3
        assert len(log.events_for_job("a" * 32)) == 3

    def test_verify_reports_the_hole_rather_than_crashing_or_passing(self, tmp_path):
        log, events_file = self._log_with_a_truncated_tail(tmp_path)
        ok, breaks = log.verify()
        assert ok is False, "an unreadable record must never verify clean"
        assert any("not readable JSON" in b.detail for b in breaks)
        assert breaks[0].line_no == 4

    def test_a_corrupt_line_in_the_middle_does_not_hide_later_records(self, tmp_path):
        log = AuditLog(tmp_path)
        log.append("job.completed", job_id="a" * 32)
        [events_file] = tmp_path.glob("dt=*/events.jsonl")
        good = events_file.read_text().splitlines()
        log.append("job.completed", job_id="c" * 32)
        after = events_file.read_text().splitlines()[1:]
        events_file.write_text("\n".join([good[0], "{not json at all", *after]) + "\n")

        assert len(log.events()) == 2  # both real records still surface
        ok, breaks = log.verify()
        assert ok is False
        assert any(b.line_no == 2 for b in breaks)


class TestPartitionDatesAreUTC:
    """Everything in DLPDuck partitions on UTC — dt= directories, the
    index, the content store. The console's date filters therefore mean
    UTC days, which is worth pinning: a machine east of UTC has a local
    "today" that is already tomorrow for several hours, and a filter that
    silently quietly dropped the newest partition would look like data
    loss rather than a timezone.
    """

    def test_a_partition_is_named_for_the_utc_date_not_the_local_one(self, tmp_path):
        log = AuditLog(tmp_path)
        log.append("job.completed", job_id="a" * 32)

        [partition] = list(tmp_path.glob("dt=*"))
        assert partition.name == f"dt={datetime.now(UTC).date().isoformat()}"

    def test_filtering_from_the_utc_today_includes_what_was_just_written(self, tmp_path):
        log = AuditLog(tmp_path)
        log.append("job.completed", job_id="a" * 32)

        events = log.events(start=datetime.now(UTC).date())

        assert len(events) == 1

    def test_a_filter_is_inclusive_at_both_ends(self, tmp_path):
        log = AuditLog(tmp_path)
        for day in ("2026-03-01", "2026-03-02", "2026-03-03"):
            partition = tmp_path / f"dt={day}"
            partition.mkdir()
            (partition / "events.jsonl").write_text(
                f'{{"seq":1,"ts":"x","event":"job.completed","job_id":"{day}"}}\n'
            )

        events = log.events(start=date(2026, 3, 1), end=date(2026, 3, 3))
        assert {e["job_id"] for e in events} == {"2026-03-01", "2026-03-02", "2026-03-03"}

        middle = log.events(start=date(2026, 3, 2), end=date(2026, 3, 2))
        assert {e["job_id"] for e in middle} == {"2026-03-02"}


class TestRedaction:
    """Append-only logs and erasure requests eventually collide.
    Something sensitive does land in the trail — a search term, a filename
    inside a parse error — and the only options used to be keep it forever
    or drop a whole partition.
    """

    def _log_with_a_secret(self, tmp_path):
        log = AuditLog(tmp_path)
        log.append("job.completed", job_id="a" * 32, disposition="archive")
        log.append("ui.search", actor="ivy", query="123-45-6789", results=0)
        log.append("job.completed", job_id="b" * 32, disposition="archive")
        return log

    def _raw(self, tmp_path) -> str:
        return "".join(f.read_text() for f in tmp_path.glob("dt=*/events.jsonl"))

    def test_the_value_really_leaves_the_disk(self, tmp_path):
        log = self._log_with_a_secret(tmp_path)
        assert "123-45-6789" in self._raw(tmp_path)

        log.redact(2, ["query"], reason="erasure request 41", actor="admin")

        assert "123-45-6789" not in self._raw(tmp_path)

    def test_the_chain_still_verifies_around_it(self, tmp_path):
        log = self._log_with_a_secret(tmp_path)
        log.redact(2, ["query"], reason="erasure request 41", actor="admin")

        result = log.verify()

        assert result.ok
        assert [r.seq for r in result.redactions] == [2]
        assert result.redactions[0].fields == ["query"]

    def test_the_removal_is_itself_recorded_and_chained(self, tmp_path):
        log = self._log_with_a_secret(tmp_path)
        log.redact(2, ["query"], reason="erasure request 41", actor="admin")

        recorded = [e for e in log.events(limit=100) if e["event"] == "audit.redacted"]
        assert len(recorded) == 1
        assert recorded[0]["redacted_seq"] == 2
        assert recorded[0]["reason"] == "erasure request 41"
        assert recorded[0]["actor"] == "admin"
        assert recorded[0]["prev"] is not None  # part of the chain, not a note

    def test_other_events_are_untouched(self, tmp_path):
        log = self._log_with_a_secret(tmp_path)
        log.redact(2, ["query"], reason="r", actor="admin")

        events = {e["seq"]: e for e in log.events(limit=100)}
        assert events[1]["disposition"] == "archive"
        assert events[3]["disposition"] == "archive"
        assert events[2]["actor"] == "ivy"  # only the named field went

    def test_marking_an_event_redacted_without_a_record_is_a_break(self, tmp_path):
        """The abuse path this design has to answer for: blanking content
        and calling it a redaction must not verify clean."""
        self._log_with_a_secret(tmp_path)
        [path] = tmp_path.glob("dt=*/events.jsonl")
        lines = path.read_text().splitlines()
        forged = json.loads(lines[0])
        forged["disposition"] = "quarantine"
        forged["redacted"] = {"fields": ["disposition"]}
        lines[0] = json.dumps(forged, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n")

        result = AuditLog(tmp_path).verify()

        assert result.ok is False
        assert any("no audit.redacted event records" in b.detail for b in result.breaks)

    def test_chain_scaffolding_cannot_be_redacted(self, tmp_path):
        log = self._log_with_a_secret(tmp_path)
        for field in ("seq", "ts", "hash", "prev"):
            with pytest.raises(KeyError):
                log.redact(2, [field], reason="r", actor="admin")

    def test_redacting_a_field_the_event_does_not_have_is_refused(self, tmp_path):
        log = self._log_with_a_secret(tmp_path)
        with pytest.raises(KeyError):
            log.redact(2, ["no_such_field"], reason="r", actor="admin")

    def test_an_unknown_sequence_number_is_refused(self, tmp_path):
        log = self._log_with_a_secret(tmp_path)
        with pytest.raises(KeyError):
            log.redact(999, ["query"], reason="r", actor="admin")

    def test_redacting_nothing_is_refused(self, tmp_path):
        log = self._log_with_a_secret(tmp_path)
        with pytest.raises(ValueError):
            log.redact(2, [], reason="r", actor="admin")

    def test_a_second_redaction_accumulates_rather_than_replaces(self, tmp_path):
        log = self._log_with_a_secret(tmp_path)
        log.redact(2, ["query"], reason="first", actor="admin")
        log.redact(2, ["actor"], reason="second", actor="admin")

        result = log.verify()
        assert result.ok
        assert result.redactions[0].fields == ["actor", "query"]

    def test_appending_still_works_afterwards(self, tmp_path):
        log = self._log_with_a_secret(tmp_path)
        log.redact(2, ["query"], reason="r", actor="admin")

        log.append("job.completed", job_id="c" * 32, disposition="archive")

        assert log.verify().ok

    def test_a_reopened_log_still_verifies(self, tmp_path):
        log = self._log_with_a_secret(tmp_path)
        log.redact(2, ["query"], reason="r", actor="admin")

        reopened = AuditLog(tmp_path)
        reopened.append("job.completed", job_id="d" * 32)

        assert reopened.verify().ok

    def test_verify_result_still_unpacks_as_a_pair(self, tmp_path):
        """Existing callers do `ok, breaks = verify()`; that must keep
        working while new code reads .redactions."""
        log = self._log_with_a_secret(tmp_path)
        ok, breaks = log.verify()
        assert ok is True and breaks == []

    def test_widening_a_real_redaction_by_hand_is_a_break(self, tmp_path):
        """One authorised removal must not license blanking the rest of
        that event. Without the field-level check, the seq alone would
        read as "explained" and this would verify clean."""
        log = self._log_with_a_secret(tmp_path)
        log.redact(2, ["query"], reason="erasure request 41", actor="admin")

        [path] = tmp_path.glob("dt=*/events.jsonl")
        lines = path.read_text().splitlines()
        for i, raw in enumerate(lines):
            event = json.loads(raw)
            if event.get("seq") != 2:
                continue
            event["actor"] = "[redacted]"
            event["redacted"] = {"fields": ["actor", "query"]}
            lines[i] = json.dumps(event, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n")

        result = AuditLog(tmp_path).verify()

        assert result.ok is False
        assert any("actor" in b.detail and "no audit.redacted" in b.detail for b in result.breaks)

    def test_the_accountability_record_cannot_be_hollowed_out(self, tmp_path):
        """Redacting which event was emptied, or which fields, would turn
        one authorised redaction into cover for any number of others."""
        log = self._log_with_a_secret(tmp_path)
        log.redact(2, ["query"], reason="r", actor="admin")
        [record] = [e for e in log.events(limit=100) if e["event"] == "audit.redacted"]

        for field in ("redacted_seq", "fields"):
            with pytest.raises(KeyError):
                log.redact(record["seq"], [field], reason="r2", actor="admin")

        # reason and actor stay redactable — that is a recorded loss of
        # accountability, not a way to hide one.
        log.redact(record["seq"], ["reason"], reason="r3", actor="admin")
        assert log.verify().ok

    def test_a_partly_unredactable_request_removes_nothing(self, tmp_path):
        """Being told "done" while one named field is still on disk is
        the worst possible outcome of an erasure request."""
        log = self._log_with_a_secret(tmp_path)

        with pytest.raises(KeyError):
            log.redact(2, ["query", "hash"], reason="r", actor="admin")

        assert "123-45-6789" in self._raw(tmp_path)
        assert log.verify().ok
        assert log.verify().redactions == []

    def test_naming_an_absent_field_removes_nothing(self, tmp_path):
        log = self._log_with_a_secret(tmp_path)

        with pytest.raises(KeyError):
            log.redact(2, ["query", "no_such_field"], reason="r", actor="admin")

        assert "123-45-6789" in self._raw(tmp_path)

    def test_the_rewrite_never_leaves_a_truncated_partition(self, tmp_path, monkeypatch):
        """The one operation in this system that rewrites rather than
        appends. A crash partway through an in-place write would destroy
        every already-durable event in the partition."""
        log = self._log_with_a_secret(tmp_path)
        [path] = tmp_path.glob("dt=*/events.jsonl")
        before = path.read_text()

        real_replace = os.replace

        def die_before_replace(src, dst):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(os, "replace", die_before_replace)
        with pytest.raises(OSError):
            log.redact(2, ["query"], reason="r", actor="admin")
        monkeypatch.setattr(os, "replace", real_replace)

        assert path.read_text() == before, "the partition survived intact"
        assert AuditLog(tmp_path).verify().ok
        assert not list(tmp_path.glob("dt=*/*.tmp")), "no temp file left behind"

    def test_the_rewrite_keeps_the_partition_file_mode(self, tmp_path):
        log = self._log_with_a_secret(tmp_path)
        [path] = tmp_path.glob("dt=*/events.jsonl")
        path.chmod(0o640)

        log.redact(2, ["query"], reason="r", actor="admin")

        assert path.stat().st_mode & 0o777 == 0o640
