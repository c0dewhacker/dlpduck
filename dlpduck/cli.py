from __future__ import annotations

import getpass
import logging
import os
import signal
import sys
import threading
from collections import Counter
from datetime import date
from pathlib import Path

import click

from dlpduck import __version__
from dlpduck.audit import AuditLog
from dlpduck.config import ConfigError, config_warnings, load_config, validate_config
from dlpduck.content import InvalidJobId
from dlpduck.engine import DLPEngine
from dlpduck.extract import LineExtractor
from dlpduck.index import AssessmentExists, compact_partition, plan_compaction
from dlpduck.pipeline import Pipeline
from dlpduck.reprocess import Reprocessor, parse_mode
from dlpduck.retention import apply_retention, plan_retention
from dlpduck.search import QueryTimeout, SearchError, audit_terms
from dlpduck.search import search as run_search
from dlpduck.tracing import configure_logging
from dlpduck.types import EncryptedDocument, RuleBudgetExceeded
from dlpduck.watcher import Watcher

configure_logging()


@click.group()
@click.version_option(version=__version__, prog_name="dlpduck")
def main() -> None:
    """DLPDuck — line-aware OCR/DLP document ingestion engine."""


def _parse_date_option(value: str | None, flag: str) -> date | None:
    """A mistyped --start should tell the operator what to fix, not print
    a traceback at them."""
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        click.secho(f"{flag} must be a date in YYYY-MM-DD form, got {value!r}", fg="red")
        sys.exit(1)


@main.command("validate-config")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
def validate_config_cmd(config_path: str) -> None:
    """Parse config, compile every regex, check paths and permissions.
    Exit non-zero on any problem — run it in CI."""
    try:
        config = validate_config(config_path)
    except ConfigError as exc:
        click.secho(f"INVALID: {exc}", fg="red", err=True)
        sys.exit(1)
    rules = config.load_rules()
    click.secho(f"OK — {len(rules)} rules loaded, all paths present", fg="green")
    for rule in rules:
        click.echo(f"  {rule.id:28s} {rule.severity.value:8s} {rule.action}")

    # Warnings, not errors: each of these is legal and may be deliberate,
    # so none of them fails the exit code that CI gates on.
    warnings = config_warnings(config)
    if warnings:
        click.echo("")
        click.secho(f"{len(warnings)} warning(s):", fg="yellow")
        for warning in warnings:
            click.secho(f"  - {warning}", fg="yellow")


@main.command()
@click.argument("pdf_path", type=click.Path(exists=True))
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
def scan(pdf_path: str, config_path: str) -> None:
    """Dry run one document: print extracted lines with page/line indices
    and every hit. Nothing is written."""
    config = load_config(config_path)
    extractor = LineExtractor(
        dpi=config.extraction.dpi,
        isolate=config.extraction.isolate_worker,
        timeout=config.extraction.timeout_seconds,
    )
    extractor.NATIVE_MIN_CHARS = config.extraction.native_min_chars
    engine = DLPEngine(
        rules=config.load_rules(),
        hmac_key=config.hmac_key(),
        rule_budget_seconds=config.rule_budget_seconds,
    )

    pdf_bytes = Path(pdf_path).read_bytes()
    try:
        text = extractor.extract(pdf_bytes)
    except EncryptedDocument:
        click.secho("document is encrypted — would fail closed", fg="red")
        sys.exit(1)

    click.echo(f"{text.page_count} pages, {text.ocr_page_count} via OCR, degraded={text.degraded}")
    click.echo("")
    for line in text.lines:
        marker = f"[{line.source}]" if line.source == "ocr" else "        "
        click.echo(
            f"p{line.page_number:>3} L{line.line_number:>4} (on-page {line.line_on_page:>3}) "
            f"{marker} {line.text}"
        )

    click.echo("")
    try:
        hits = engine.scan(text)
    except RuleBudgetExceeded as exc:
        click.secho(f"rule {exc.rule_id} exceeded its time budget — would fail closed", fg="red")
        sys.exit(1)

    if not hits:
        click.secho("no hits", fg="green")
        return

    click.secho(f"{len(hits)} hit(s):", fg="yellow")
    for h in hits:
        click.echo(
            f"  [{h.severity.value:8s}] {h.rule_id:28s} action={h.action:10s} "
            f"p{h.page_number} L{h.line_number}  {h.masked_text!r}"
        )


@main.command("test-rules")
@click.option("--corpus", required=True, type=click.Path(exists=True, file_okay=False))
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--rule", "rule_id", default=None, help="Only report this rule id")
def test_rules(corpus: str, config_path: str, rule_id: str | None) -> None:
    """Run the ruleset over a directory of real documents; print per-rule
    hit counts and matching lines for false-positive tuning."""
    config = load_config(config_path)
    extractor = LineExtractor(
        dpi=config.extraction.dpi,
        isolate=config.extraction.isolate_worker,
        timeout=config.extraction.timeout_seconds,
    )
    extractor.NATIVE_MIN_CHARS = config.extraction.native_min_chars
    engine = DLPEngine(
        rules=config.load_rules(),
        hmac_key=config.hmac_key(),
        rule_budget_seconds=config.rule_budget_seconds,
    )

    counts: Counter[str] = Counter()
    samples: dict[str, list[str]] = {}
    pdfs = sorted(Path(corpus).glob("*.pdf"))
    if not pdfs:
        click.secho(f"no .pdf files found under {corpus}", fg="red")
        sys.exit(1)

    with click.progressbar(pdfs, label="scanning corpus") as bar:
        for pdf_path in bar:
            try:
                text = extractor.extract(pdf_path.read_bytes())
                hits = engine.scan(text)
            except Exception as exc:
                click.echo(f"\n  skipped {pdf_path.name}: {exc}")
                continue
            for h in hits:
                if rule_id and h.rule_id != rule_id:
                    continue
                counts[h.rule_id] += 1
                bucket = samples.setdefault(h.rule_id, [])
                if len(bucket) < 5:
                    bucket.append(f"{pdf_path.name} p{h.page_number} L{h.line_number}: {h.masked_text}")

    click.echo("")
    for rid, n in counts.most_common():
        click.secho(f"{rid}: {n} hit(s)", fg="yellow" if n else "green")
        for s in samples.get(rid, []):
            click.echo(f"    {s}")


@main.command("replay-sink")
@click.argument("sink_name")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
def replay_sink(sink_name: str, config_path: str) -> None:
    """Drain a sink's spool in order. Safe to run while the daemon is live."""
    config = load_config(config_path)
    plugins = config.load_plugins()
    target = next((p for p in plugins if p.name == sink_name), None)
    if target is None or not hasattr(target, "replay"):
        names = [p.name for p in plugins if hasattr(p, "replay")]
        click.secho(
            f"no replayable sink named {sink_name!r} — known sinks: {names}", fg="red"
        )
        sys.exit(1)
    delivered, pending = target.replay()
    click.echo(f"delivered {delivered} event(s), {pending} still pending")
    if pending:
        sys.exit(1)


@main.command()
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--commit", "do_commit", is_flag=True, default=False,
              help="Actually write new assessments. Default is preview: report only, write nothing.")
@click.option("--mode", type=click.Choice(["rules", "extract"]), default="rules",
              help="rules: re-run against stored text, fast, never opens the PDF (default). "
                   "extract: re-run OCR too — slower, but re-derives page_count/degraded for "
                   "real and refreshes the content store. For an OCR model upgrade or "
                   "recovering a degraded job.")
@click.option("--job", "job_ids", multiple=True, help="Limit to specific job id(s). Repeatable.")
@click.option("--start", "start_str", default=None, help="YYYY-MM-DD, inclusive")
@click.option("--end", "end_str", default=None, help="YYYY-MM-DD, inclusive")
def reprocess(
    config_path: str,
    do_commit: bool,
    mode: str,
    job_ids: tuple[str, ...],
    start_str: str | None,
    end_str: str | None,
) -> None:
    """Re-run the current ruleset against already-ingested documents
    without reopening the PDF. Preview by default; pass --commit to append new
    assessments.

    Escalations (archive -> quarantine) are applied and move the PDF
    immediately. De-escalations are recorded with release_pending, but
    the PDF is deliberately left where it is — release it with
    `dlpduck release <job_id>`."""
    config = load_config(config_path)
    pipeline = Pipeline(config)
    reprocessor = Reprocessor(pipeline)

    start = _parse_date_option(start_str, "--start")
    end = _parse_date_option(end_str, "--end")
    ids = list(job_ids) or None

    checked_mode = parse_mode(mode)  # click already constrains it; this narrows the type
    try:
        if do_commit:
            summary = reprocessor.commit(job_ids=ids, start=start, end=end, mode=checked_mode)
        else:
            summary = reprocessor.preview(job_ids=ids, start=start, end=end, mode=checked_mode)
    except AssessmentExists as exc:
        click.secho(
            f"{exc} — another writer recorded that assessment first. Nothing was "
            "overwritten; re-run to reassess against the current state.",
            fg="red",
        )
        sys.exit(1)

    click.echo(f"ruleset {summary.ruleset_version} — {summary.scope_size} document(s) in scope")
    click.echo(f"  escalated (now quarantined):    {summary.count('escalate')}")
    click.echo(f"  de-escalated (release pending):  {summary.count('deescalate')}")
    click.echo(f"  changed (disposition same):      {summary.count('changed')}")
    click.echo(f"  unavailable (content purged):    {summary.count('content_unavailable')}")
    click.echo(f"  unchanged:                        {summary.unchanged}")

    if do_commit:
        click.secho(f"wrote {summary.written} new assessment(s)", fg="green")
        if summary.content_refreshed:
            click.secho(
                f"{summary.content_refreshed} job(s) had content re-extracted and saved "
                "with no verdict change (e.g. recovering previously lost content)",
                fg="green",
            )
        if summary.count("deescalate"):
            click.secho(
                f"{summary.count('deescalate')} job(s) flagged release_pending — "
                "the PDF was NOT moved; releasing them is a manual step",
                fg="yellow",
            )
    else:
        click.secho("preview only — nothing was written. Pass --commit to apply.", fg="yellow")

    for outcome in summary.outcomes:
        if outcome.direction in ("unchanged",):
            continue
        click.echo(
            f"  [{outcome.direction:20s}] {outcome.job_id}  "
            f"{outcome.old_disposition or '-':10s} -> {outcome.new_disposition or '-':10s}  "
            f"hits {outcome.old_hit_count} -> {outcome.new_hit_count}"
        )


@main.command()
@click.argument("job_id")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--reason", required=True, help="Why — lands in the audit event verbatim")
@click.option(
    "--actor", default=None, help="Who authorised this (default: the OS user running the command)"
)
def release(job_id: str, config_path: str, reason: str, actor: str | None) -> None:
    """Carry out a pending de-escalation from `dlpduck reprocess`: move
    the PDF from quarantine into the archive. Only works on a job whose
    current assessment has release_pending set — reprocess's verdict is
    not reconsidered here, only executed."""
    config = load_config(config_path)
    pipeline = Pipeline(config)
    result = Reprocessor(pipeline).release(job_id, reason=reason, actor=actor or getpass.getuser())

    if result.released:
        click.secho(f"released job {job_id} — PDF moved into the archive", fg="green")
    else:
        click.secho(f"not released: {result.reason_denied}", fg="red")
        sys.exit(1)


@main.command("purge-content")
@click.argument("job_id")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--reason", required=True, help="Why — lands in the audit event verbatim")
@click.option(
    "--actor", default=None, help="Who authorised this (default: the OS user running the command)"
)
@click.option(
    "--hard",
    is_flag=True,
    default=False,
    help="Also delete the archived PDF — a real erasure, not just de-indexing",
)
def purge_content_cmd(
    job_id: str, config_path: str, reason: str, actor: str | None, hard: bool
) -> None:
    """Delete a job's raw text from the content store, making it
    unsearchable. The metadata index row and every prior audit event are
    untouched — neither ever held the raw text — and one new audit event
    records that this happened.

    By default the archived PDF is left in place. Pass --hard to delete it
    too."""
    config = load_config(config_path)
    pipeline = Pipeline(config)
    try:
        result = pipeline.purge_content(
            job_id, reason=reason, actor=actor or getpass.getuser(), hard=hard
        )
    except InvalidJobId as exc:
        click.secho(f"{exc} — expected 32 hex characters", fg="red")
        sys.exit(1)

    if result.content_removed:
        click.secho(f"purged content for job {job_id}", fg="green")
    else:
        click.secho(
            f"no content found for job {job_id} (already purged, or never existed)", fg="yellow"
        )

    if hard:
        if result.document_removed:
            click.secho(f"deleted the archived PDF for job {job_id}", fg="green")
        else:
            click.secho(f"no archived PDF found for job {job_id}", fg="yellow")

    click.echo("recorded in the audit trail regardless of what was found")


@main.command()
@click.argument("query")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--start", "start_str", default=None, help="YYYY-MM-DD, inclusive")
@click.option("--end", "end_str", default=None, help="YYYY-MM-DD, inclusive")
@click.option("--severity", default=None, help="INFO|LOW|MEDIUM|HIGH|CRITICAL")
@click.option("--limit", default=100, help="Max results (default 100)")
def search(
    query: str,
    config_path: str,
    start_str: str | None,
    end_str: str | None,
    severity: str | None,
    limit: int,
) -> None:
    """Full-text search, joining the content store against the metadata
    index. The date range is optional — omit it to search everything, at
    the cost of a full scan. A job whose content has been purged
    (see `purge-content`) never matches, even though its index row and
    audit trail still exist."""
    config = load_config(config_path)
    content_root = config.destination.work_dir / "content"
    index_root = config.destination.work_dir / "index"

    start = _parse_date_option(start_str, "--start")
    end = _parse_date_option(end_str, "--end")

    try:
        response = run_search(
            content_root, index_root, query, start=start, end=end, severity=severity, limit=limit
        )
    except SearchError as exc:
        click.secho(f"invalid search: {exc}", fg="red")
        sys.exit(1)
    except QueryTimeout as exc:
        click.secho(str(exc), fg="red")
        sys.exit(1)

    if response.unbounded:
        click.secho(
            f"no date range given — scanned the full index ({response.elapsed_seconds:.2f}s)",
            fg="yellow",
        )

    # An unbounded search is a legitimate query, not an incident — but
    # "who searched the entire archive, and for what" is a fair question
    # for a reviewer to be able to ask later.
    audit = AuditLog(config.audit_dir, integrity=config.audit.integrity)
    audit.append(
        "ui.search",
        actor=os.environ.get("DLPDUCK_ACTOR", getpass.getuser()),
        **audit_terms(query, config.console.audit_search_terms, config.hmac_key()),
        severity=severity,
        range=[start.isoformat() if start else None, end.isoformat() if end else None],
        unbounded=response.unbounded,
        results=len(response.results),
    )

    if not response.results:
        click.secho("no results", fg="green")
        return

    for r in response.results:
        click.echo(
            f"{r.job_id}  {r.received_at}  {r.disposition:10s} "
            f"sev={r.highest_severity or '-':8s} hits={r.hit_count}"
        )
        if r.snippet:
            click.echo(f"    ...{r.snippet}...")

    click.echo("")
    click.echo(f"{len(response.results)} result(s) in {response.elapsed_seconds:.2f}s"
               + (" (truncated — more may exist, narrow the query or range)" if response.truncated else ""))


@main.command()
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--apply", "do_apply", is_flag=True, default=False,
              help="Actually delete eligible partitions. Default is dry-run: report only.")
def retention(config_path: str, do_apply: bool) -> None:
    """Drop whole dt= partitions past each store's configured retention
    window. A store with no window configured is never touched.
    Dry run by default."""
    config = load_config(config_path)
    plans = plan_retention(config)

    any_configured = any(p.cutoff is not None for p in plans)
    if not any_configured:
        click.secho(
            "no retention windows configured — every store is kept forever. "
            "Set retention.documents_days / index_days / audit_days to enable.",
            fg="yellow",
        )
        return

    for p in plans:
        if p.cutoff is None:
            click.echo(f"  {p.store:10s} not configured — kept forever")
        else:
            click.echo(
                f"  {p.store:10s} cutoff {p.cutoff}  {len(p.eligible)} partition(s) eligible"
            )
            for path in p.eligible:
                click.echo(f"      {path}")

    if not do_apply:
        click.secho("dry run — nothing deleted. Pass --apply to actually remove these.", fg="yellow")
        return

    audit = AuditLog(config.audit_dir, integrity=config.audit.integrity)
    removed = apply_retention(plans, audit)
    click.secho(f"removed {removed} partition(s)", fg="green")


@main.command("redact-audit")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--seq", required=True, type=int, help="The audit event's sequence number")
@click.option(
    "--field", "fields", multiple=True, required=True,
    help="Field to empty, e.g. --field query. Repeatable.",
)
@click.option("--reason", required=True, help="Why — lands in the audit trail verbatim")
@click.option(
    "--actor", default=None, help="Who authorised this (default: the OS user running the command)"
)
def redact_audit_cmd(
    config_path: str, seq: int, fields: tuple[str, ...], reason: str, actor: str | None
) -> None:
    """Remove named fields from one already-written audit event.

    For when something that should not be permanent lands in the trail — a
    search term, a filename inside an error, an allowlisted metadata value
    — and an erasure request means it cannot simply stay there.

    The event keeps its place in the chain: verify-audit still proves
    nothing around it was inserted, removed or reordered. What it stops
    proving is that one event's contents. The redaction is itself recorded
    as a chained event naming you and your reason, so this removes
    evidence but never silently.
    """
    config = load_config(config_path)
    audit = AuditLog(config.audit_dir, integrity=config.audit.integrity)
    try:
        event = audit.redact(
            seq, list(fields), reason=reason, actor=actor or getpass.getuser()
        )
    except (KeyError, ValueError) as exc:
        click.secho(str(exc), fg="red")
        sys.exit(1)

    click.secho(f"redacted {', '.join(fields)} from event {seq}", fg="green")
    click.echo(f"  the event now reads: {event}")
    click.echo("  recorded as an audit.redacted event; verify-audit will report it")


@main.command("compact-index")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--commit", "do_commit", is_flag=True, default=False,
              help="Actually merge. Default is dry-run: report only.")
def compact_index(config_path: str, do_commit: bool) -> None:
    """Merge each day's assessment files into one.

    The write path deliberately produces one small Parquet file per
    assessment — atomic and safe under contention. The read path pays for
    that: DuckDB opens every file in the glob, so the jobs list and the
    Overview counters slow down linearly with the number of documents ever
    ingested, on a store that is permanent by default. This repacks the
    completed days; today's partition is left alone because it is still
    being written.

    Safe to run against a live system, and safe to interrupt.
    """
    config = load_config(config_path)
    plans = plan_compaction(config.destination.work_dir / "index")
    if not plans:
        click.secho("nothing to compact — every past partition is already one file", fg="green")
        return

    total_files = sum(len(p.files) for p in plans)
    total_bytes = sum(p.bytes_before for p in plans)
    click.echo(
        f"{len(plans)} partition(s), {total_files} file(s), {total_bytes / 1e6:.1f} MB"
    )
    for plan in plans:
        click.echo(f"  {plan.partition.name}  {len(plan.files):6d} file(s)  "
                   f"{plan.bytes_before / 1e6:8.1f} MB")

    if not do_commit:
        click.secho("dry run — nothing written. Pass --commit to apply.", fg="yellow")
        return

    reclaimed = 0
    with click.progressbar(plans, label="compacting") as bar:
        for plan in bar:
            reclaimed += compact_partition(plan)
    click.secho(
        f"merged {total_files} file(s) into {len(plans)}, reclaimed {reclaimed / 1e6:.1f} MB",
        fg="green",
    )


@main.command("verify-audit")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
def verify_audit_cmd(config_path: str) -> None:
    """Walk the hash chain and report the first break, if any."""
    config = load_config(config_path)
    audit = AuditLog(config.audit_dir, integrity=config.audit.integrity)
    if audit.integrity == "none":
        click.secho("audit.integrity is 'none' — chaining is off, nothing to verify", fg="yellow")
        return
    result = audit.verify()
    # Redactions are reported whether or not the chain is intact: "intact"
    # and "intact, with three events emptied" are different answers, and
    # only one of them means nothing was removed.
    if result.redactions:
        click.secho(f"{len(result.redactions)} redacted event(s):", fg="yellow")
        for redaction in result.redactions:
            click.echo(f"  {redaction}")
    if result.ok:
        click.secho(f"chain intact through seq {audit._seq}", fg="green")
        return
    click.secho(f"{len(result.breaks)} break(s) found:", fg="red")
    for b in result.breaks:
        click.echo(f"  {b}")
    sys.exit(1)


@main.command()
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
def run(config_path: str) -> None:
    """Start the daemon: resume any interrupted jobs, then watch."""
    config = validate_config(config_path)
    config.apply_umask()  # before anything is written — see Config.umask
    pipeline = Pipeline(config)

    staging_root = config.destination.work_dir / "_processing"
    resumed = pipeline.resume_staged(staging_root)
    if resumed:
        logging.getLogger("dlpduck.cli").info("resumed %d interrupted job(s)", len(resumed))

    watcher = Watcher(config, pipeline)
    stop_event = threading.Event()

    def _handle_signal(signum, frame):
        logging.getLogger("dlpduck.cli").info("received signal %s, shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    watcher.run_forever(stop_event)


@main.command()
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--commit", "do_commit", is_flag=True, default=False,
              help="Actually write rebuilt rows. Default is dry-run: report only.")
def reindex(config_path: str, do_commit: bool) -> None:
    """Rebuild the metadata index from the content store and, where
    content was also lost, the archived PDFs. Only touches jobs
    missing from the index — already-indexed jobs are left alone. Dry
    run by default."""
    from dlpduck.reindex import Reindexer

    config = load_config(config_path)
    pipeline = Pipeline(config)
    summary = Reindexer(pipeline).run(commit=do_commit)

    click.echo(f"{summary.scanned_pdfs} PDF(s) found on disk")
    click.echo(f"  already indexed:      {summary.already_indexed}")
    click.echo(f"  rebuilt from content:  {summary.count('content')}")
    click.echo(f"  rebuilt from PDF (re-extracted): {summary.count('pdf')}")
    click.echo(f"  failed:                {summary.count('failed')}")
    if summary.ruleset_disagreements:
        click.secho(
            f"  {summary.ruleset_disagreements} document(s) are filed somewhere the CURRENT "
            "ruleset would not put them.\n"
            "    Each was restored to where it actually sits — reindex never moves a document "
            "or quietly\n"
            "    declassifies one. Run `dlpduck reprocess --commit` to re-judge them properly; "
            "a de-escalation\n"
            "    out of quarantine still needs `dlpduck release`.",
            fg="yellow",
        )

    if summary.content_withheld:
        click.secho(
            f"  {summary.content_withheld} document(s) had their content purged before the "
            "index was lost.\n"
            "    Their index rows were rebuilt — a soft purge never touched those — but the "
            "text was NOT\n"
            "    written back. Re-extracting it would make erased content searchable again "
            "and silently\n"
            "    reverse someone's erasure. To restore it deliberately, run `dlpduck reprocess "
            "--mode extract`.",
            fg="yellow",
        )

    if not do_commit:
        click.secho("dry run — nothing written. Pass --commit to apply.", fg="yellow")
    else:
        click.secho("done.", fg="green")

    for o in summary.outcomes:
        withheld = "  [content withheld — previously purged]" if o.content_withheld else ""
        if o.source == "failed":
            click.secho(f"  FAILED {o.job_id}: {o.detail}", fg="red")
        elif o.source == "content":
            click.secho(
                f"  {o.job_id}  from content — original degraded flag unrecoverable, assumed False",
                fg="yellow",
            )
        elif o.source == "pdf":
            click.echo(
                f"  {o.job_id}  from PDF (re-extracted — degraded flag is trustworthy){withheld}"
            )


@main.group()
def console() -> None:
    """Admin console with authentication, job queue, and job details."""


@console.command("hash-password")
@click.argument("password", required=False)
def console_hash_password(password: str | None) -> None:
    """Hash a password for console.auth.users[].password_hash. Prompts
    for the password if not given on the command line, so it doesn't end
    up in your shell history."""
    from dlpduck.console.auth import hash_password

    if password is None:
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    click.echo(hash_password(password))


@console.command("run")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
def console_run(config_path: str) -> None:
    """Start the admin console web server."""
    import uvicorn

    from dlpduck.console.app import create_app

    config = load_config(config_path)
    config.apply_umask()
    pipeline = Pipeline(config)
    app = create_app(config, pipeline)

    host, port = config.console.host_port()
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
