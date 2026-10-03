"""Query commands: `search`, `jobs` and `correlate`.

The same filters as the console (dlpduck.search.IndexFilters), and the same
audit events, so a question asked from a shell is as visible to a reviewer
as one asked in the browser. `--json` prints one JSON object per line for
scripting; nothing here ever prints a raw matched value — only what the
index already holds (masked text, keyed digests) or, for `search`, the
snippet an operator with shell access to the content store could read
anyway.
"""

from __future__ import annotations

import functools
import getpass
import json
import os
import sys
from datetime import date

import click

from dlpduck.audit import AuditLog
from dlpduck.search import IndexFilters, QueryTimeout, SearchError, audit_terms
from dlpduck.search import search as run_search


def _actor() -> str:
    return os.environ.get("DLPDUCK_ACTOR", getpass.getuser())


def _date(value: str | None, flag: str) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        click.secho(f"{flag} must be a date in YYYY-MM-DD form, got {value!r}", fg="red")
        sys.exit(1)


def _fail(message: str) -> None:
    click.secho(message, fg="red", err=True)
    sys.exit(1)


def _emit(record: dict) -> None:
    click.echo(json.dumps(record, default=str, sort_keys=True))


def filter_options(func):
    """--start/--end and every IndexFilters field, as one decorator so the
    three commands cannot drift apart."""

    @click.option("--start", "start_str", default=None, help="YYYY-MM-DD, inclusive")
    @click.option("--end", "end_str", default=None, help="YYYY-MM-DD, inclusive")
    @click.option("--severity", default=None, help="Exactly this highest severity")
    @click.option("--min-severity", default=None,
                  help="This highest severity or worse: INFO|LOW|MEDIUM|HIGH|CRITICAL")
    @click.option("--rule", "rule_id", default=None, help="At least one hit from this rule id")
    @click.option("--disposition", type=click.Choice(["archive", "quarantine"]), default=None)
    @click.option("--source", "source_name", default=None, help="Only this source.name")
    @click.option("--flagged/--unflagged", default=None, help="Only jobs with / without hits")
    @click.option("--json", "as_json", is_flag=True, help="One JSON object per line")
    @functools.wraps(func)
    def wrapper(*args, start_str, end_str, severity, min_severity, rule_id, disposition,
                source_name, flagged, **kwargs):
        try:
            filters = IndexFilters(
                severity=severity, min_severity=min_severity, rule_id=rule_id,
                disposition=disposition, source_name=source_name, flagged=flagged,
            )
        except SearchError as exc:
            _fail(f"invalid filter: {exc}")
        return func(*args, start=_date(start_str, "--start"), end=_date(end_str, "--end"),
                    filters=filters, **kwargs)

    return wrapper


@click.command()
@click.argument("query")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--limit", default=100, help="Max results (default 100)")
@click.option("--offset", default=0, help="Skip this many results (paging)")
@filter_options
def search(query, config_path, limit, offset, start, end, filters, as_json) -> None:
    """Full-text search, joining the content store against the metadata
    index. Every word must appear; "quoted phrases" match together, even
    across a line break; -word excludes. The date range is optional — omit
    it to search everything, at the cost of a full scan. A job whose content
    has been purged never matches, even though its index row and audit
    trail still exist."""
    from dlpduck.cli import _load

    config = _load(config_path)
    try:
        response = run_search(
            config.destination.work_dir / "content", config.destination.work_dir / "index",
            query, start=start, end=end, limit=limit, offset=offset, filters=filters,
        )
    except SearchError as exc:
        _fail(f"invalid search: {exc}")
    except QueryTimeout as exc:
        _fail(str(exc))

    # An unbounded search is a legitimate query, not an incident — but
    # "who searched the entire archive, and for what" is a fair question
    # for a reviewer to be able to ask later.
    AuditLog(config.audit_dir, integrity=config.audit.integrity).append(
        "ui.search",
        actor=_actor(),
        **audit_terms(query, config.console.audit_search_terms, config.hmac_key()),
        severity=filters.severity,
        filters={k: v for k, v in {
            "min_severity": filters.min_severity, "rule": filters.rule_id,
            "disposition": filters.disposition, "source": filters.source_name,
            "flagged": filters.flagged,
        }.items() if v is not None} or None,
        range=[start.isoformat() if start else None, end.isoformat() if end else None],
        unbounded=response.unbounded,
        results=len(response.results),
        via="cli",
    )

    if as_json:
        for r in response.results:
            _emit({"job_id": r.job_id, "received_at": r.received_at, "disposition": r.disposition,
                   "highest_severity": r.highest_severity, "hit_count": r.hit_count,
                   "rule_ids": r.rule_ids, "source_name": r.source_name, "snippet": r.snippet})
        return
    if response.unbounded:
        click.secho(
            f"no date range given — scanned the full index ({response.elapsed_seconds:.2f}s)",
            fg="yellow",
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
               + (" (truncated — more may exist; use --offset, or narrow the query or range)"
                  if response.truncated else ""))


@click.command()
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--limit", default=100, help="Max rows (default 100)")
@click.option("--offset", default=0, help="Skip this many rows (paging)")
@click.option("--pending", is_flag=True, help="Only jobs with a release pending")
@click.option("--job", "job_ids", multiple=True, help="Only these job id(s). Repeatable.")
@filter_options
def jobs(config_path, limit, offset, pending, job_ids, start, end, filters, as_json) -> None:
    """List the current assessment of each job, newest first — the
    console's Jobs screen from a shell. Reads only the index: no document
    text is involved, so this works after content has been purged."""
    from dataclasses import replace

    from dlpduck.cli import _load
    from dlpduck.content import InvalidJobId, validate_job_id
    from dlpduck.reprocess import latest_index_rows

    config = _load(config_path)
    if not 0 < limit <= 10000:
        _fail("--limit must be between 1 and 10000")
    try:
        for job_id in job_ids:
            validate_job_id(job_id)
    except InvalidJobId as exc:
        _fail(f"{exc} — expected 32 hex characters")
    rows = latest_index_rows(
        config.destination.work_dir / "index", job_ids=list(job_ids) or None, start=start,
        end=end, limit=limit + 1, offset=offset, newest_first=True,
        filters=replace(filters, release_pending=pending),
    )
    truncated = len(rows) > limit
    for row in rows[:limit]:
        if as_json:
            _emit({k: row[k] for k in (
                "job_id", "received_at", "assessed_at", "assessment_seq", "disposition", "reason",
                "highest_severity", "hit_count", "rule_ids", "release_pending", "source_name",
                "page_count", "degraded",
            )})
        else:
            pending_note = "  release-pending" if row["release_pending"] else ""
            click.echo(
                f"{row['job_id']}  {row['received_at']}  {row['disposition']:10s} "
                f"sev={row['highest_severity'] or '-':8s} hits={row['hit_count']:<3} "
                f"#{row['assessment_seq']}{pending_note}"
            )
    if not as_json:
        click.echo(f"{min(len(rows), limit)} job(s)"
                   + (" — more exist; use --offset" if truncated else ""))


@click.command()
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("--value", "read_value", is_flag=True,
              help="Prompt for a value to look up (never taken from the command line, "
                   "so it stays out of shell history and the process list)")
@click.option("--hmac", "match_hmac", default=None, help="A hit's match_hmac to correlate")
@click.option("--limit", default=200, help="Max hits (default 200)")
@click.option("--offset", default=0, help="Skip this many hits (paging)")
@filter_options
def correlate(config_path, read_value, match_hmac, limit, offset, start, end, filters,
              as_json) -> None:
    """Every document in which one sensitive value was found, from the
    masked hits in the permanent index. Give a hit's --hmac, or --value to
    be prompted for the value itself (digested with the deployment's key,
    never stored or printed). Works after content has been purged."""
    from dlpduck.cli import _load
    from dlpduck.correlate import digest_for, find

    if bool(read_value) == bool(match_hmac):
        _fail("give exactly one of --value or --hmac")
    config = _load(config_path)
    audit = AuditLog(config.audit_dir, integrity=config.audit.integrity)
    try:
        if read_value:
            value = click.prompt("Value", hide_input=True)
            match_hmac = digest_for(value, config.hmac_key())
            audit.append(
                "ui.correlate_lookup", actor=_actor(), match_hmac=match_hmac, via="cli",
                **({"query": value} if config.console.audit_search_terms == "plain" else {}),
            )
        result = find(config.destination.work_dir / "index", match_hmac, start=start, end=end,
                      filters=filters, limit=limit, offset=offset)
    except SearchError as exc:
        _fail(str(exc))
    except QueryTimeout as exc:
        _fail(str(exc))
    audit.append("ui.correlate", actor=_actor(), match_hmac=match_hmac,
                 results=len(result.hits), documents=result.documents, via="cli")

    for h in result.hits:
        if as_json:
            _emit(h.__dict__)
        else:
            click.echo(f"{h.job_id}  {h.received_at}  {h.disposition:10s} {h.rule_id:24s} "
                       f"p{h.page_number} L{h.line_number}  {h.masked_text}")
    if not as_json:
        click.echo(f"{len(result.hits)} hit(s) in {result.documents} document(s)"
                   + (" — more exist; use --offset" if result.truncated else ""))
