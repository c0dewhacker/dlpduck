"""The console's query surface: the jobs list, full-text search, value
correlation, and CSV export of each.

Registered onto the app by `register()` so app.py stays about documents
and actions, not result tables. Every filter here goes through
dlpduck.search.IndexFilters, so the jobs list, search and correlation
agree on what each one means, and every value reaches DuckDB as a bound
parameter.

Permissions follow what each result exposes, not the page it is on:

- the jobs list shows index metadata (`jobs.list`); filtering it by rule
  reveals which rules matched, so that filter needs `dlp.hits.read`;
- search returns slices of raw text (`jobs.text.read`), withheld for a
  contained document unless the viewer may open quarantined PDFs;
- correlating from a digest shows masked hits only (`dlp.hits.read`);
- looking up a typed value is a membership test on flagged values, so it
  is gated like text search (`jobs.text.read`) and audited the same way.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Callable, Iterable
from datetime import date
from typing import Any

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from dlpduck.config import Config
from dlpduck.console.auth import require_permission
from dlpduck.console.csrf import get_csrf_token, verify_csrf
from dlpduck.console.rbac import has_permission
from dlpduck.correlate import digest_for, find
from dlpduck.reprocess import latest_index_rows
from dlpduck.search import (
    SEVERITIES,
    IndexFilters,
    QueryTimeout,
    SearchError,
    audit_terms,
)
from dlpduck.search import search as run_search

PAGE_SIZE = 100
# One export is one query: large enough for a real investigation, bounded
# so a single click cannot pull the whole archive into one response.
EXPORT_LIMIT = 1000


def parse_date_param(value: str, field: str) -> date | None:
    """Date filters arrive as raw query strings. They normally come from an
    <input type="date">, but a bookmarked, hand-edited or truncated URL is
    ordinary traffic too — and `date.fromisoformat` raising into the route
    turned every one of those into a 500."""
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"{field}={value!r} is not a date — use YYYY-MM-DD.",
        ) from None


def relative_url(url) -> str:
    """Path and query only. Links built from the request's own absolute URL
    come out as http:// behind a TLS-terminating proxy that isn't trusted
    for forwarded headers, and a page has no reason to name its host."""
    return url.path + (f"?{url.query}" if url.query else "")


def _csv_cell(value: Any) -> str:
    """Neutralise spreadsheet formula injection. Filenames, metadata and
    snippets come from untrusted documents; a cell starting with = + - @
    (or a tab/CR that some importers strip first) is executed by Excel and
    LibreOffice when the export is opened."""
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def csv_response(filename: str, header: list[str], rows: Iterable[list[Any]]) -> Response:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(header)
    for row in rows:
        writer.writerow([_csv_cell(v) for v in row])
    return Response(
        out.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _filters(
    *,
    min_severity: str = "",
    severity: str = "",
    rule: str = "",
    disposition: str = "",
    source: str = "",
    flagged: str = "",
    pending: bool = False,
) -> IndexFilters:
    try:
        return IndexFilters(
            severity=severity or None,
            min_severity=min_severity or None,
            rule_id=rule or None,
            disposition=disposition or None,
            source_name=source or None,
            flagged={"yes": True, "no": False}.get(flagged),
            release_pending=pending,
        )
    except SearchError as exc:
        raise HTTPException(400, str(exc)) from None


def register(
    app: FastAPI,
    *,
    templates,
    pipeline,
    config: Config,
    is_contained: Callable[..., bool],
) -> None:
    rule_ids = sorted(rule.id for rule in pipeline.engine.rules)

    def _filter_context(user, **values: Any) -> dict[str, Any]:
        return {
            "filters": values,
            "rule_ids": rule_ids,
            "severities": [s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if s in SEVERITIES],
            "can_filter_rules": has_permission(set(user.roles), "dlp.hits.read"),
        }

    def _audit_export(user, what: str, count: int, **detail: Any) -> None:
        # An export leaves the console with a copy; who took which list is
        # as auditable as who opened which document.
        pipeline.audit.append("ui.export", actor=user.username, what=what, rows=count, **detail)

    # ── jobs list ────────────────────────────────────────────────────

    @app.get("/jobs", response_model=None)
    def jobs_list(
        request: Request,
        disposition: str = "",
        start: str = "",
        end: str = "",
        min_severity: str = "",
        rule: str = "",
        source: str = "",
        flagged: str = "",
        page: int = Query(1, ge=1, le=100000),
        pending: bool = False,
        format: str = "",
        user=Depends(require_permission("jobs.list")),
    ) -> HTMLResponse | RedirectResponse | Response:
        if disposition == "failed":
            return RedirectResponse("/failed", status_code=303)
        if rule and not has_permission(set(user.roles), "dlp.hits.read"):
            raise HTTPException(403, "Filtering by rule needs the 'dlp.hits.read' permission.")
        filters = _filters(min_severity=min_severity, rule=rule, disposition=disposition,
                           source=source, flagged=flagged, pending=pending)
        start_d = parse_date_param(start, "start")
        end_d = parse_date_param(end, "end")
        exporting = format == "csv"
        size = EXPORT_LIMIT if exporting else PAGE_SIZE
        # One more than shown, so "there is more" is a length check rather
        # than a second counting query.
        rows = latest_index_rows(
            pipeline.index_root, start=start_d, end=end_d, limit=size + 1, newest_first=True,
            offset=0 if exporting else (page - 1) * PAGE_SIZE, filters=filters,
        )
        truncated = len(rows) > size
        rows = rows[:size]
        names = pipeline.operations.display_names(row["job_id"] for row in rows)
        if exporting:
            _audit_export(user, "jobs", len(rows), truncated=truncated)
            return csv_response(
                "dlpduck-jobs.csv",
                ["received_at", "job_id", "name", "disposition", "highest_severity",
                 "hit_count", "rule_ids", "assessment_seq", "release_pending", "source_name"],
                ([r["received_at"].isoformat(), r["job_id"], names.get(r["job_id"], ""),
                  r["disposition"], r["highest_severity"] or "", r["hit_count"],
                  " ".join(r["rule_ids"] or []) if has_permission(set(user.roles), "dlp.hits.read") else "",
                  r["assessment_seq"], r["release_pending"], r["source_name"]] for r in rows),
            )
        return templates.TemplateResponse(
            request,
            "jobs_list.html",
            {
                "user": user,
                "jobs": rows,
                "truncated": truncated,
                "page_size": PAGE_SIZE,
                "page": page,
                "pending": pending,
                "names": names,
                "previous_url": relative_url(request.url.include_query_params(page=page - 1)) if page > 1 else None,
                "next_url": relative_url(request.url.include_query_params(page=page + 1)) if truncated else None,
                "export_url": relative_url(request.url.include_query_params(format="csv").remove_query_params("page")),
                **_filter_context(user, disposition=disposition, start=start, end=end,
                                  min_severity=min_severity, rule=rule, source=source,
                                  flagged=flagged),
            },
        )

    # ── full-text search ─────────────────────────────────────────────

    @app.get("/search", response_model=None)
    def search_page(
        request: Request,
        q: str = "",
        severity: str = "",
        min_severity: str = "",
        rule: str = "",
        disposition: str = "",
        source: str = "",
        flagged: str = "",
        start: str = "",
        end: str = "",
        page: int = Query(1, ge=1, le=100000),
        format: str = "",
        user=Depends(require_permission("jobs.text.read")),
    ) -> HTMLResponse | Response:
        # jobs.text.read, not jobs.list — a search result's snippet is a
        # slice of raw full_text, the same content that gate protects
        # everywhere else, so Viewer/Auditor don't get a search box.
        exporting = format == "csv"
        context: dict[str, Any] = {
            "user": user,
            "response": None,
            "error": None,
            "page": page,
            "previous_url": relative_url(request.url.include_query_params(page=page - 1)) if page > 1 else None,
            "next_url": None,
            "export_url": None,
            "csrf_token": get_csrf_token(request),
            **_filter_context(user, q=q, severity=severity, min_severity=min_severity,
                              rule=rule, disposition=disposition, source=source,
                              flagged=flagged, start=start, end=end),
        }
        if not q:
            return templates.TemplateResponse(request, "search.html", context)
        # Inline rather than a 400 page: the operator's query is right there
        # in the form to correct.
        try:
            start_d = date.fromisoformat(start) if start else None
            end_d = date.fromisoformat(end) if end else None
        except ValueError:
            context["error"] = "Start and end must be dates in YYYY-MM-DD form."
            return templates.TemplateResponse(request, "search.html", context)
        try:
            filters = IndexFilters(
                severity=severity or None, min_severity=min_severity or None,
                rule_id=rule or None, disposition=disposition or None,
                source_name=source or None, flagged={"yes": True, "no": False}.get(flagged),
            )
            response = run_search(
                pipeline.content_root, pipeline.index_root, q, start=start_d, end=end_d,
                limit=EXPORT_LIMIT if exporting else PAGE_SIZE,
                offset=0 if exporting else (page - 1) * PAGE_SIZE, filters=filters,
            )
        except (SearchError, QueryTimeout) as exc:
            context["error"] = str(exc)
            return templates.TemplateResponse(request, "search.html", context)

        # A snippet is a raw slice of the document, so it belongs behind the
        # same gate as opening that document. Without this, a quarantined
        # document's PDF was admin-only while its text was searchable by any
        # investigator — and since the snippet is centred on the match,
        # searching a word near a hit returned the very value the
        # quarantine, the masking, and the admin-only dlp.reveal all exist
        # to protect. The result itself still shows (finding a quarantined
        # document is the investigator's job); only the excerpt is withheld.
        if not has_permission(set(user.roles), "jobs.pdf.read.quarantined"):
            for result in response.results:
                if is_contained(result.disposition, result.archive_path, result.release_pending):
                    result.snippet = ""
                    result.snippet_withheld = True
        # "Who searched everything, and for what" stays answerable. Query
        # recording follows console.audit_search_terms: the private default
        # stores a keyed digest; deployments can choose readable terms.
        pipeline.audit.append(
            "ui.search",
            actor=user.username,
            **audit_terms(q, config.console.audit_search_terms, pipeline.config.hmac_key()),
            severity=severity or None,
            filters={k: v for k, v in {"min_severity": min_severity, "rule": rule,
                                       "disposition": disposition, "source": source,
                                       "flagged": flagged}.items() if v} or None,
            range=[start_d.isoformat() if start_d else None, end_d.isoformat() if end_d else None],
            unbounded=response.unbounded,
            results=len(response.results),
            export=exporting,
        )
        names = pipeline.operations.display_names(r.job_id for r in response.results)
        if exporting:
            _audit_export(user, "search", len(response.results), truncated=response.truncated)
            return csv_response(
                "dlpduck-search.csv",
                ["received_at", "job_id", "name", "disposition", "highest_severity", "hit_count",
                 "snippet"],
                ([r.received_at.isoformat(), r.job_id, names.get(r.job_id, ""), r.disposition,
                  r.highest_severity or "", r.hit_count,
                  "[withheld]" if r.snippet_withheld else r.snippet] for r in response.results),
            )
        context["response"] = response
        context["names"] = names
        context["next_url"] = (
            relative_url(request.url.include_query_params(page=page + 1)) if response.truncated else None
        )
        context["export_url"] = relative_url(
            request.url.include_query_params(format="csv").remove_query_params("page")
        )
        return templates.TemplateResponse(request, "search.html", context)

    # ── value correlation ────────────────────────────────────────────

    @app.get("/correlate", response_model=None)
    def correlate_page(
        request: Request,
        hmac: str = "",
        start: str = "",
        end: str = "",
        page: int = Query(1, ge=1, le=100000),
        format: str = "",
        user=Depends(require_permission("dlp.hits.read")),
    ) -> HTMLResponse | Response:
        context: dict[str, Any] = {
            "user": user,
            "result": None,
            "error": request.session.pop("correlate_error", None),
            "filters": {"hmac": hmac, "start": start, "end": end},
            "can_lookup_value": has_permission(set(user.roles), "jobs.text.read"),
            "csrf_token": get_csrf_token(request),
            "previous_url": relative_url(request.url.include_query_params(page=page - 1)) if page > 1 else None,
            "next_url": None,
            "export_url": None,
            "page": page,
        }
        if not hmac:
            return templates.TemplateResponse(request, "correlate.html", context)
        exporting = format == "csv"
        try:
            result = find(
                pipeline.index_root, hmac,
                start=parse_date_param(start, "start"), end=parse_date_param(end, "end"),
                limit=EXPORT_LIMIT if exporting else PAGE_SIZE,
                offset=0 if exporting else (page - 1) * PAGE_SIZE,
            )
        except (SearchError, QueryTimeout) as exc:
            context["error"] = str(exc)
            return templates.TemplateResponse(request, "correlate.html", context)
        pipeline.audit.append(
            "ui.correlate", actor=user.username, match_hmac=hmac,
            results=len(result.hits), documents=result.documents, export=exporting,
        )
        names = pipeline.operations.display_names(h.job_id for h in result.hits)
        if exporting:
            _audit_export(user, "correlation", len(result.hits), match_hmac=hmac)
            return csv_response(
                "dlpduck-correlation.csv",
                ["received_at", "job_id", "name", "disposition", "rule_id", "severity",
                 "page", "line", "masked_text"],
                ([h.received_at.isoformat(), h.job_id, names.get(h.job_id, ""), h.disposition,
                  h.rule_id, h.severity, h.page_number, h.line_number, h.masked_text]
                 for h in result.hits),
            )
        context.update(
            result=result,
            names=names,
            next_url=relative_url(request.url.include_query_params(page=page + 1)) if result.truncated else None,
            export_url=relative_url(request.url.include_query_params(format="csv").remove_query_params("page")),
        )
        return templates.TemplateResponse(request, "correlate.html", context)

    @app.post("/correlate", response_model=None)
    def correlate_value(
        request: Request,
        value: str = Form(...),
        csrf_token: str = Form(...),
        user=Depends(require_permission("jobs.text.read")),
    ) -> RedirectResponse:
        """Typed value → its digest → the GET view. A POST, so the value
        never lands in a URL, browser history, or a proxy's access log;
        only the keyed digest does."""
        verify_csrf(request, csrf_token)
        try:
            digest = digest_for(value, pipeline.config.hmac_key())
        except SearchError as exc:
            request.session["correlate_error"] = str(exc)
            return RedirectResponse("/correlate", status_code=303)
        pipeline.audit.append(
            "ui.correlate_lookup", actor=user.username, match_hmac=digest,
            **({"query": value} if config.console.audit_search_terms == "plain" else {}),
        )
        return RedirectResponse(f"/correlate?hmac={digest}", status_code=303)
