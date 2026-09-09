"""Re-evaluate already-committed jobs against the CURRENT ruleset, without
re-running OCR, appending a new assessment rather than overwriting the
old one.

Reprocessing is append-only, for the same reason the content/index split
exists: "this document was assessed as clean on 3 September under
ruleset 8f2a1c" is an evidential claim, and silently replacing it with a
different answer six weeks later is exactly the tampering the audit chain
exists to detect. A reassessment is a new row; nothing is ever rewritten.

Escalation (a document that now matches a quarantine rule) is applied
automatically on commit — fail closed, same as everywhere else in this
system. De-escalation is never automatic: the new assessment is written
(so the logical verdict is on record), but the PDF is not physically
moved and `release_pending` is set — an unattended batch that quietly
un-quarantines documents because a rule was loosened is operationally
indistinguishable from an attacker weakening that rule. `Reprocessor.release`
is the separate, explicitly human action that actually moves the file —
it takes a reason and an actor, records both, and does nothing else: it
does not re-run rules, so it can't change what the release_pending
assessment already decided, only carry it out.

Two modes. "rules" (the default) reads the content store's structured
`lines` — never the PDF — and runs at index-scan speed; because it never
re-extracts, a document whose ORIGINAL extraction was degraded stays
fail-closed regardless of what the new ruleset finds, and page_count /
ocr_page_count / degraded carry forward from the prior assessment
unchanged. "extract" re-opens the archived PDF and genuinely re-runs
LineExtractor — for an OCR model upgrade, or recovering a job whose
original extraction was degraded — and is correspondingly slower; a
successful extract-mode reassessment also overwrites the content store
with the fresh text (the content store holds only the current text, not
a history) and writes real, re-derived
page_count / ocr_page_count / min_ocr_confidence / degraded rather than
carrying the old ones forward.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal

import duckdb

from dlpduck.content import read_document_text, write_content_row
from dlpduck.disposition import decide
from dlpduck.durability import move_durably, write_atomically
from dlpduck.engine import DLPEngine
from dlpduck.index import AssessmentExists, write_row
from dlpduck.operations import serialized
from dlpduck.types import DLPHit, DocumentText, JobContext, TextLine

Direction = Literal["escalate", "deescalate", "changed", "unchanged", "content_unavailable"]
Mode = Literal["rules", "extract"]
MODES: tuple[Mode, ...] = ("rules", "extract")


def parse_mode(value: str) -> Mode:
    """Narrow a caller-supplied string to a Mode, or say why not.

    Both entry points validate this already — click with a Choice, the
    console route with an explicit check — but neither could express that
    to a type checker, so the Literal was decorative. One place to do it
    means a third caller cannot quietly skip it."""
    if value not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {value!r}")
    return value  # type: ignore[return-value]  # narrowed by the check above


_INDEX_COLUMNS = [
    "job_id",
    "received_at",
    "assessed_at",
    "assessment_seq",
    "ruleset_version",
    "supersedes_seq",
    "release_pending",
    "source_name",
    "page_count",
    "ocr_page_count",
    "min_ocr_confidence",
    "degraded",
    "disposition",
    "reason",
    "archive_path",
    "pdf_sha256",
    "flagged",
    "highest_severity",
    "hit_count",
    "rule_ids",
    "hits",
    "metadata",
    "audit_fields",
]


def index_stats(index_root: Path, today: date) -> dict:
    """The Overview's counters, computed in the query engine.

    The console used to load every current row into Python and count them
    there — which meant the landing page got slower and heavier with every
    document ever ingested, to render five integers.
    """
    index_root = Path(index_root)
    empty = {"total": 0, "today": 0, "quarantined": 0, "release_pending": 0}
    if not any(index_root.glob("dt=*/*.parquet")):
        return empty

    glob = str(index_root / "dt=*" / "*.parquet")
    sql = """
        WITH current AS (
            SELECT disposition, release_pending, received_at
            FROM read_parquet(?, hive_partitioning = true, union_by_name = true)
            QUALIFY row_number() OVER (PARTITION BY job_id ORDER BY assessment_seq DESC) = 1
        )
        SELECT
            count(*),
            count(*) FILTER (WHERE received_at::DATE = ?),
            count(*) FILTER (WHERE disposition = 'quarantine'),
            count(*) FILTER (WHERE release_pending)
        FROM current
    """
    con = duckdb.connect()
    try:
        con.execute("SET TimeZone='UTC'")  # same reason as latest_index_rows
        counted = con.execute(sql, [glob, today]).fetchone()
        if counted is None:  # an ungrouped aggregate always returns a row
            return empty
        total, today_count, quarantined, pending = counted
    finally:
        con.close()
    return {
        "total": total,
        "today": today_count,
        "quarantined": quarantined,
        "release_pending": pending,
    }


def latest_index_rows(
    index_root: Path,
    job_ids: list[str] | None = None,
    start: date | None = None,
    end: date | None = None,
    limit: int | None = None,
    newest_first: bool = False,
    disposition: str | None = None,
    release_pending: bool = False,
    offset: int = 0,
) -> list[dict]:
    """The current assessment per job — the highest assessment_seq for
    each job_id. With no is_current flag to synchronize, this remains
    correct by construction.

    `limit` bounds the result in the query rather than after it. The
    console's job list has no natural bound otherwise: it read every row
    ever ingested and rendered all of them into one HTML table, which is
    48MB and two seconds at 30,000 jobs and grows from there. Ask for the
    newest N and say so, the same way search reports a truncated result.
    """
    index_root = Path(index_root)
    if not any(index_root.glob("dt=*/*.parquet")):
        return []

    where = []
    params: list = []
    if start is not None:
        where.append("dt >= ?")
        params.append(start)
    if end is not None:
        where.append("dt <= ?")
        params.append(end)
    if job_ids:
        where.append(f"job_id IN ({','.join('?' for _ in job_ids)})")
        params.extend(job_ids)
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""

    glob = str(index_root / "dt=*" / "*.parquet")
    # _INDEX_COLUMNS is a module-level constant and `where_sql` contains
    # only "?" placeholders; job ids, dates and the parquet glob are all
    # bound parameters.
    #
    # union_by_name lets a file written by an older release — one missing a
    # column a later version added — still be read, with the newer column
    # coming back NULL instead of the whole query failing. Without it the
    # first schema addition makes every historical row unreadable, and the
    # index is the one store that is meant to be permanent.
    outer_filters = []
    if disposition:
        outer_filters.append("disposition = ?")
        params.append(disposition)
    if release_pending:
        outer_filters.append("release_pending = true")
    outer_sql = "WHERE " + " AND ".join(outer_filters) if outer_filters else ""
    sql = f"""
        WITH current AS (
        SELECT {", ".join(_INDEX_COLUMNS)}
        FROM read_parquet(?, hive_partitioning = true, union_by_name = true)
        {where_sql}
        QUALIFY row_number() OVER (PARTITION BY job_id ORDER BY assessment_seq DESC) = 1
        ) SELECT * FROM current {outer_sql}
        ORDER BY received_at {"DESC" if newest_first else "ASC"}, job_id
        {"LIMIT ?" if limit is not None else ""}
        OFFSET ?
    """
    con = duckdb.connect()
    try:
        # DuckDB defaults its session TimeZone to the LOCAL system zone and
        # silently converts TIMESTAMPTZ columns on read. received_at was
        # written as raw UTC (datetime.now(timezone.utc)) and its .date()
        # is what chose the dt= partition — reading it back local-shifted
        # would compute a different date near local midnight and put a
        # reassessment in the wrong partition. Pin UTC so round-tripping a
        # timestamp through DuckDB always agrees with how it was written.
        con.execute("SET TimeZone='UTC'")
        bound = [glob, *params] + ([limit] if limit is not None else []) + [offset]
        rows = con.execute(sql, bound).fetchall()
    finally:
        con.close()
    return [dict(zip(_INDEX_COLUMNS, r, strict=True)) for r in rows]


@dataclass
class ReassessmentOutcome:
    job_id: str
    direction: Direction
    old_disposition: str | None
    new_disposition: str | None
    old_severity: str | None
    new_severity: str | None
    old_hit_count: int
    new_hit_count: int


@dataclass
class ReprocessSummary:
    ruleset_version: str
    scope_size: int = 0
    outcomes: list[ReassessmentOutcome] = field(default_factory=list)
    written: int = 0  # assessments actually committed (0 for preview)
    # extract mode only: verdict was "unchanged" but content had to be
    # (and was) re-extracted anyway — e.g. recovering previously-purged
    # content. Not counted in `written`, since no new assessment row exists.
    content_refreshed: int = 0

    def count(self, direction: Direction) -> int:
        return sum(1 for o in self.outcomes if o.direction == direction)

    @property
    def unchanged(self) -> int:
        return self.count("unchanged")


@dataclass
class ReleaseResult:
    job_id: str
    released: bool
    reason_denied: str | None = None  # set when released is False


_ESCALATING = {"quarantine"}


class Reprocessor:
    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.index_root = pipeline.index_root
        self.content_root = pipeline.content_root
        self.destination = pipeline.config.destination
        self.audit = pipeline.audit
        self.engine: DLPEngine = pipeline.engine
        self.ruleset_version = pipeline.ruleset_version
        self._recover_transitions()

    def _scope_rows(
        self, job_ids: list[str] | None, start: date | None, end: date | None
    ) -> list[dict]:
        return latest_index_rows(self.index_root, job_ids=job_ids, start=start, end=end)

    def _evaluate(
        self, row: dict, mode: Mode = "rules"
    ) -> tuple[ReassessmentOutcome, list[DLPHit] | None, str | None, DocumentText | None]:
        """Returns (outcome, new_hits, new_disposition, text) — the last
        three are None exactly when direction is "content_unavailable",
        and `text` is otherwise only populated in "extract" mode (the
        caller uses it to refresh the content store; "rules" mode has
        nothing new to write there).
        """
        job_id = row["job_id"]

        if mode == "extract":
            pdf_path = Path(row["archive_path"])
            if not pdf_path.is_file():
                return self._unavailable(row), None, None, None
            try:
                text = self.pipeline.extractor.extract(pdf_path.read_bytes())
            except Exception:  # EncryptedDocument included — either way, nothing to reassess
                return self._unavailable(row), None, None, None
        else:
            text = read_document_text(self.content_root, job_id)
            if text is None:
                return self._unavailable(row), None, None, None

        new_hits = self.engine.scan(text)
        # A degraded extraction stays fail-closed under reprocessing too.
        # "rules" mode never re-examines extraction quality — it can't,
        # it doesn't touch the PDF — so it must not be able to launder a
        # degraded document into a clean one just by having fewer rules
        # match this time; it carries the ORIGINAL degraded flag forward.
        # "extract" mode genuinely re-derives it, for real, from the fresh
        # OCR pass — the whole point of paying for re-extraction.
        if mode == "rules":
            text.degraded = row["degraded"]
            text.page_count = row["page_count"]
            text.ocr_page_count = row["ocr_page_count"]
            # The permanent schema predates failed_page_count. Preserve the
            # distinction from the recorded reason without making every old
            # Parquet-only deployment unreadable through a missing column.
            text.failed_page_count = 1 if row["reason"] == "degraded_extraction" else 0
        new_disposition, _ = decide(text, new_hits, self.pipeline.config.dlp.quarantine_on_degraded)
        new_severity = max((h.severity for h in new_hits), key=lambda s: s.rank).value if new_hits else None

        old_disposition = row["disposition"]
        if old_disposition == new_disposition:
            same_hits = (
                row["hits"]
                == [{**asdict(h), "severity": h.severity.value} for h in new_hits]
                and row["ruleset_version"] == self.ruleset_version
                and (mode != "extract" or (
                    row["page_count"] == text.page_count
                    and row["ocr_page_count"] == text.ocr_page_count
                    and row["degraded"] == text.degraded
                ))
            )
            direction: Direction = "unchanged" if same_hits else "changed"
        elif old_disposition != "quarantine" and new_disposition == "quarantine":
            direction = "escalate"
        elif old_disposition == "quarantine" and new_disposition != "quarantine":
            direction = "deescalate"
        else:
            direction = "changed"

        outcome = ReassessmentOutcome(
            job_id=job_id,
            direction=direction,
            old_disposition=old_disposition,
            new_disposition=new_disposition,
            old_severity=row["highest_severity"],
            new_severity=new_severity,
            old_hit_count=row["hit_count"],
            new_hit_count=len(new_hits),
        )
        return outcome, new_hits, new_disposition, (text if mode == "extract" else None)

    def _unavailable(self, row: dict) -> ReassessmentOutcome:
        return ReassessmentOutcome(
            job_id=row["job_id"],
            direction="content_unavailable",
            old_disposition=row["disposition"],
            new_disposition=None,
            old_severity=row["highest_severity"],
            new_severity=None,
            old_hit_count=row["hit_count"],
            new_hit_count=0,
        )

    def preview(
        self,
        job_ids: list[str] | None = None,
        start: date | None = None,
        end: date | None = None,
        mode: Mode = "rules",
    ) -> ReprocessSummary:
        """Report what reprocessing would change. Writes nothing at all —
        the default mode, and the one people should actually live in
        (the rule-tuning workflow). "extract" mode previews are slower
        (real OCR per document) but check exactly what a commit would do,
        including cases only a fresh extraction could catch."""
        rows = self._scope_rows(job_ids, start, end)
        summary = ReprocessSummary(ruleset_version=self.ruleset_version, scope_size=len(rows))
        for row in rows:
            outcome, _, _, _ = self._evaluate(row, mode)
            summary.outcomes.append(outcome)
        return summary

    @serialized
    def commit(
        self,
        job_ids: list[str] | None = None,
        start: date | None = None,
        end: date | None = None,
        mode: Mode = "rules",
    ) -> ReprocessSummary:
        """Append a new assessment for every job whose verdict actually
        changes. Escalations move the PDF into quarantine immediately;
        de-escalations are recorded with release_pending=True and leave
        the PDF exactly where it is. In "extract" mode, a changed job's
        content-store entry is also refreshed with the newly extracted text.
        """
        self._recover_transitions()
        rows = self._scope_rows(job_ids, start, end)
        summary = ReprocessSummary(ruleset_version=self.ruleset_version, scope_size=len(rows))

        self.audit.append(
            "reprocess.started",
            ruleset_version=self.ruleset_version,
            scope_size=len(rows),
            mode=mode,
        )

        for row in rows:
            outcome, new_hits, new_disposition, fresh_text = self._evaluate(row, mode)
            summary.outcomes.append(outcome)

            if outcome.direction == "content_unavailable":
                continue

            if outcome.direction == "unchanged":
                if fresh_text is not None:
                    # The verdict didn't change, but extract mode had to
                    # re-extract regardless — e.g. this job's content had
                    # been purged and is only just being recovered. That's
                    # a real state change worth keeping even though it
                    # doesn't warrant a whole new assessment row.
                    self._refresh_content_only(row, fresh_text)
                    summary.content_refreshed += 1
                continue

            if new_hits is None or new_disposition is None:
                # _evaluate only returns these as None for
                # content_unavailable, which was handled above — so this
                # says "a new early-return path was added and did not
                # account for the write". Cheaper to state than to debug
                # as an AttributeError inside _write_assessment.
                raise AssertionError(
                    f"reassessment of {row['job_id']} reached the write with no verdict "
                    f"(direction={outcome.direction})"
                )
            self._write_assessment(row, new_hits, new_disposition, outcome.direction, fresh_text)
            summary.written += 1

        self.audit.append(
            "reprocess.completed",
            ruleset_version=self.ruleset_version,
            scope_size=len(rows),
            mode=mode,
            written=summary.written,
            escalated=summary.count("escalate"),
            deescalated=summary.count("deescalate"),
            content_unavailable=summary.count("content_unavailable"),
        )
        return summary

    @serialized
    def release(self, job_id: str, reason: str, actor: str) -> ReleaseResult:
        """Carry out a pending de-escalation: move the PDF from quarantine
        into the archive and append one more assessment recording that it
        happened. Does not re-run rules — it only executes a decision a
        prior `commit()` already made and recorded as release_pending;
        the verdict itself isn't reconsidered here.
        """
        rows = latest_index_rows(self.index_root, job_ids=[job_id])
        if not rows:
            return ReleaseResult(job_id=job_id, released=False, reason_denied="job not found")
        row = rows[0]
        if not row["release_pending"]:
            return ReleaseResult(
                job_id=job_id, released=False, reason_denied="no release is pending for this job"
            )

        current_path = Path(row["archive_path"])
        expected_archive = (
            self.destination.archive
            / f"dt={row['received_at'].date().isoformat()}"
            / f"{job_id}.pdf"
        )
        if not current_path.is_file() and not expected_archive.is_file():
            return ReleaseResult(
                job_id=job_id,
                released=False,
                reason_denied="original PDF is missing; release cannot be completed",
            )

        received_at = row["received_at"]
        new_path = self._destination_path(
            job_id, received_at, row["archive_path"], self.destination.archive
        )

        new_seq = row["assessment_seq"] + 1
        new_row = dict(row)
        new_row.update(
            assessed_at=datetime.now(UTC),
            assessment_seq=new_seq,
            supersedes_seq=row["assessment_seq"],
            release_pending=False,
            archive_path=new_path,
            reason="released",
        )
        self._commit_transition(row, new_row, None, {
            "event": "job.released", "job_id": job_id, "reason": reason, "actor": actor,
            "from_assessment_seq": row["assessment_seq"], "to_assessment_seq": new_seq,
            "old_path": row["archive_path"], "new_path": new_path,
        })
        return ReleaseResult(job_id=job_id, released=True)

    @serialized
    def _write_assessment(
        self,
        prior: dict,
        new_hits: list[DLPHit],
        new_disposition: str,
        direction: Direction,
        fresh_text: DocumentText | None = None,
    ) -> None:
        job_id = prior["job_id"]
        new_seq = prior["assessment_seq"] + 1
        current = latest_index_rows(self.index_root, job_ids=[job_id])
        if current and current[0]["assessment_seq"] != prior["assessment_seq"]:
            raise AssessmentExists(self.index_root / job_id)
        release_pending = new_disposition == "archive" and (direction == "deescalate" or bool(prior["release_pending"]))

        archive_path = prior["archive_path"]
        if direction == "escalate":
            archive_path = self._destination_path(job_id, prior["received_at"], archive_path, self.destination.quarantine)

        hits_payload = [
            {
                "rule_id": h.rule_id,
                "rule_name": h.rule_name,
                "severity": h.severity.value,
                "action": h.action,
                "page_number": h.page_number,
                "line_number": h.line_number,
                "line_on_page": h.line_on_page,
                "start": h.start,
                "end": h.end,
                "masked_text": h.masked_text,
                "match_hmac": h.match_hmac,
                "validator": h.validator,
            }
            for h in new_hits
        ]
        highest = max((h.severity for h in new_hits), key=lambda s: s.rank) if new_hits else None

        row = {
            "job_id": job_id,
            "received_at": prior["received_at"],  # fixed — dt= partition never moves
            "assessed_at": datetime.now(UTC),
            "assessment_seq": new_seq,
            "ruleset_version": self.ruleset_version,
            "supersedes_seq": prior["assessment_seq"],
            "release_pending": release_pending,
            "source_name": prior["source_name"],
            # Re-derived for real in extract mode; carried forward
            # unchanged in rules mode, which never touches the PDF.
            "page_count": fresh_text.page_count if fresh_text else prior["page_count"],
            "ocr_page_count": fresh_text.ocr_page_count if fresh_text else prior["ocr_page_count"],
            "min_ocr_confidence": (
                fresh_text.min_ocr_confidence if fresh_text else prior["min_ocr_confidence"]
            ),
            "degraded": fresh_text.degraded if fresh_text else prior["degraded"],
            "disposition": new_disposition,
            "reason": f"reprocessed:{direction}" + (":extract" if fresh_text else ""),
            "archive_path": archive_path,
            "pdf_sha256": prior["pdf_sha256"],
            "flagged": bool(new_hits),
            "highest_severity": highest.value if highest else None,
            "hit_count": len(new_hits),
            "rule_ids": sorted({h.rule_id for h in new_hits}),
            "hits": hits_payload,
            "metadata": prior["metadata"],
            "audit_fields": prior["audit_fields"],
        }
        self._commit_transition(prior, row, fresh_text, {
            "event": "job.reassessed", "job_id": job_id, "direction": direction,
            "from_assessment_seq": prior["assessment_seq"], "to_assessment_seq": new_seq,
            "from_ruleset_version": prior["ruleset_version"], "to_ruleset_version": self.ruleset_version,
            "old_disposition": prior["disposition"], "new_disposition": new_disposition,
            "old_hit_count": prior["hit_count"], "new_hit_count": len(new_hits),
            "release_pending": release_pending,
        })

    def _destination_path(self, job_id, received_at, current_path, into):
        dest = into / f"dt={received_at.date().isoformat()}" / f"{job_id}.pdf"
        return str(dest) if Path(current_path).is_file() or dest.is_file() else current_path

    def _commit_transition(self, prior, row, text, event):
        root = self.destination.work_dir / "transitions"
        root.mkdir(parents=True, exist_ok=True)
        path = root / f"{row['job_id']}.json"
        payload = {"prior_path": prior["archive_path"], "row": row,
                   "text": asdict(text) if text is not None else None, "event": event}
        write_atomically(path, json.dumps(payload, default=lambda v: v.isoformat()))
        self._apply_transition(path, payload)

    def _apply_transition(self, path, payload):
        row = payload["row"]
        for key in ("received_at", "assessed_at"):
            if isinstance(row[key], str):
                row[key] = datetime.fromisoformat(row[key])
        src, dest = Path(payload["prior_path"]), Path(row["archive_path"])
        if src != dest and src.is_file():
            move_durably(src, dest)
        if payload["text"] is not None:
            raw = payload["text"]
            text = DocumentText(**{**raw, "lines": [TextLine(**line) for line in raw["lines"]]})
            self._refresh_content_only(row, text)
        existing = latest_index_rows(self.index_root, job_ids=[row["job_id"]])
        if not existing or existing[0]["assessment_seq"] < row["assessment_seq"]:
            write_row(self.index_root, row, dt=row["received_at"].date(), job_id=row["job_id"],
                      assessment_seq=row["assessment_seq"], exclusive=True)
        event = payload["event"]
        if not any(e.get("to_assessment_seq") == row["assessment_seq"] and e.get("event") == event["event"]
                   for e in self.audit.events_for_job(row["job_id"])):
            self.audit.append(event["event"], **{key: value for key, value in event.items() if key != "event"})
        path.unlink()

    @serialized
    def _recover_transitions(self):
        for path in sorted((self.destination.work_dir / "transitions").glob("*.json")):
            self._apply_transition(path, json.loads(path.read_text()))

    def _refresh_content_only(self, row: dict, text: DocumentText) -> None:
        """extract mode: the content store holds only the current text,
        never a history — a fresh extraction replaces what was
        there, the same as a plain re-ingest would. Used both when a new
        assessment is written and when the verdict is unchanged but the
        content still needed recovering (e.g. it had been purged).
        """
        write_content_row(
            self.content_root,
            JobContext(
                job_id=row["job_id"],
                received_at=row["received_at"],
                source_name=row["source_name"],
                staging_dir=Path("."),  # unused by write_content_row
                pdf_path=Path(row["archive_path"]),  # unused by write_content_row
                pdf_sha256=row["pdf_sha256"],
                metadata={},
                text=text,
            ),
        )

    def _relocate_pdf(
        self, job_id: str, received_at: datetime, current_path: str, into: Path
    ) -> str:
        """Move a job's PDF into `into`, and return where it now is.

        Shared by escalation (→ quarantine) and release (→ archive), which
        are the same operation pointed in opposite directions and were
        drifting apart as two copies.

        Safe to repeat, which matters because the move happens before the
        index row that records it: a crash in that gap leaves the file
        already at the destination while the index still names the old
        location. Reading only `current_path` cannot tell that apart from
        "the document is gone", and answering "gone" writes the stale path
        into the new assessment — after which the console can never serve
        that document again, permanently, even though the file is sitting
        right there. So the destination is checked too.
        """
        src = Path(current_path)
        partition = into / f"dt={received_at.date().isoformat()}"
        dest = partition / f"{job_id}.pdf"

        if not src.is_file():
            if dest.is_file():
                return str(dest)  # the move already happened; adopt it
            # Genuinely gone (e.g. hard-purged) but its content wasn't —
            # evaluate() already required content to exist, so this is an
            # inconsistent-but-survivable state. Record the logical
            # change; there is no file left to move.
            return current_path

        partition.mkdir(parents=True, exist_ok=True)
        # shutil.move, not Path.replace — archive and quarantine are
        # deliberately recommended to sit on separate mounts for ACL
        # separation, and a plain rename() raises across filesystems.
        move_durably(src, dest)
        return str(dest)

    def _move_to_quarantine(self, job_id: str, received_at: datetime, current_path: str) -> str:
        return self._relocate_pdf(
            job_id, received_at, current_path, self.destination.quarantine
        )
