"""DLPDuck's RBAC-protected admin console.

OIDC is the primary authentication path; local accounts provide an
air-gapped and break-glass fallback.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from dlpduck.config import Config
from dlpduck.console.auth import (
    LocalUserStore,
    LoginThrottle,
    establish_session,
    get_current_user,
    require_login,
    require_permission,
)
from dlpduck.console.csrf import get_csrf_token, verify_csrf
from dlpduck.console.rbac import ALL_ROLES, has_permission
from dlpduck.content import InvalidJobId, has_content, read_document_text, validate_job_id
from dlpduck.failures import FailureQueue
from dlpduck.index import AssessmentExists
from dlpduck.masking import mask
from dlpduck.pipeline import Pipeline
from dlpduck.reprocess import Reprocessor, index_stats, latest_index_rows, parse_mode
from dlpduck.search import QueryTimeout, SearchError, audit_terms
from dlpduck.search import search as run_search

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

logger = logging.getLogger("dlpduck.console")

# The job list is unbounded by nature — every document ever ingested is a
# row. Show the newest page of them and say when there are more, rather
# than rendering a year of history into one table.
JOBS_PAGE_SIZE = 100


def _rederive_hit_value(doc, hit: dict[str, Any], rules) -> str | None:
    """Recover a hit's cleartext from the content store.

    The raw value is never stored, so reveal re-derives it from the
    position the hit recorded. `start`/`end` are relative to the hit's own
    line, and the slice runs from that line's offset through `full_text`
    rather than through the line alone — a document-scope match can span a
    line break, and truncating it at the line would show a fragment.

    The candidate is then checked against the masked form that WAS stored:
    if it doesn't reproduce it, the offsets no longer describe this text
    (content re-extracted since, an older index row) and reveal reports
    nothing rather than displaying some unrelated slice of the document
    under a legitimate-looking audit entry.
    """
    if doc is None:
        return None
    try:
        base = doc.offset_of(hit["line_number"])
    except (IndexError, TypeError):
        return None
    start, end = base + hit["start"], base + hit["end"]
    if start < 0 or end > len(doc.full_text) or start >= end:
        return None
    candidate = doc.full_text[start:end]

    rule = next((r for r in rules if r.id == hit["rule_id"]), None)
    if rule is not None and mask(candidate, rule.mask_keep) != hit["masked_text"]:
        return None
    return candidate


def _parse_date_param(value: str, field: str) -> date | None:
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


def _json_or_empty(raw: Any) -> dict[str, Any]:
    """Index rows store metadata as a JSON string. A row written by an
    older version — or by hand — shouldn't be able to break the page."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def create_app(config: Config, pipeline: Pipeline) -> FastAPI:
    app = FastAPI(title="DLPDuck Console")
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.state.config = config
    app.state.pipeline = pipeline
    app.state.operations = pipeline.operations
    app.state.user_store = LocalUserStore(
        [u.model_dump() for u in config.console.auth.users]
    )
    app.state.login_throttle = LoginThrottle(
        max_failures=config.console.auth.max_failed_logins,
        lockout_seconds=config.console.auth.lockout_seconds,
    )
    app.add_middleware(
        SessionMiddleware,
        secret_key=config.console.session_secret(),
        same_site="lax",
        max_age=config.console.session_max_age_seconds,
        https_only=config.console.session_cookie_secure,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        """Headers that make the browser enforce what the code already
        assumes.

        The console renders text lifted out of untrusted documents —
        filenames, PDF metadata, search queries — and serves the untrusted
        documents themselves. Jinja autoescapes and the PDF paths are
        confined, but neither of those is what stops a mistake becoming an
        account takeover; a browser that refuses to run injected script,
        refuses to be framed, and refuses to guess at content types is.

        `frame-ancestors 'none'` matters more here than on most apps: purge
        is one click behind a confirmation, and clickjacking is exactly the
        attack that turns a click the user meant for something else into an
        irreversible deletion. `no-referrer` keeps job ids — which name
        real documents — out of the Referer header on any outbound link.
        """
        response = await call_next(request)
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        response.headers.setdefault(
            "Content-Security-Policy",
            # 'unsafe-inline' is honest rather than aspirational: the
            # stylesheet and two small behaviours live in the templates.
            # Everything else is same-origin, which is now literally true
            # — the fonts are served from /static rather than a CDN.
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        # Nothing here needs a camera, a microphone or a location, and a
        # console that handles other people's documents should not be able
        # to ask for them.
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        return response

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    # Lets base.html's nav hide links a role can't use, without every
    # route having to compute and pass that set itself.
    templates.env.globals["has_permission"] = has_permission
    reprocessor = Reprocessor(pipeline)
    failures = FailureQueue(pipeline)

    oidc_cfg = config.console.auth.oidc
    oauth = OAuth()
    if oidc_cfg is not None:
        oauth.register(
            name="oidc",
            server_metadata_url=f"{oidc_cfg.issuer.rstrip('/')}/.well-known/openid-configuration",
            client_id=oidc_cfg.client_id,
            client_secret=oidc_cfg.client_secret(),
            client_kwargs={"scope": "openid profile email"},
            # Sent as an authorize-request param, not just a client
            # capability — without this authlib doesn't send
            # code_challenge/code_challenge_method at all, which a PKCE-
            # required client (as ours should be) rejects outright.
            code_challenge_method="S256",
        )
    app.state.oauth = oauth  # exposed for tests to stub token exchange without a live IdP

    def _get_job_or_404(job_id: str) -> dict[str, Any]:
        try:
            validate_job_id(job_id)
        except InvalidJobId:
            raise HTTPException(status_code=404, detail="job not found") from None
        rows = latest_index_rows(pipeline.index_root, job_ids=[job_id])
        if not rows:
            raise HTTPException(status_code=404, detail=f"job {job_id!r} not found")
        return rows[0]

    quarantine_root = config.destination.quarantine.resolve()

    def _is_contained(disposition: str, archive_path: str, release_pending: bool = False) -> bool:
        """Is this document still contained, i.e. does reading it need the
        quarantined tier? True if the row says quarantine, if a release is
        still pending, or if the file actually sits under the quarantine
        root whatever the row claims."""
        if disposition == "quarantine" or release_pending:
            return True
        try:
            return Path(archive_path).resolve().is_relative_to(quarantine_root)
        except (OSError, ValueError):
            return True  # unresolvable — fail closed

    def _pdf_permission_for(job: dict[str, Any]) -> str:
        """Which permission this job's PDF needs. A quarantined document is
        gated more tightly than an archived one — same split as
        quarantine.release, and why Investigator (jobs.pdf.read only) can
        open an archived PDF but not a quarantined one.

        `disposition` alone is not enough to decide that. A de-escalation
        records the new disposition immediately but deliberately
        leaves the PDF in quarantine until a human with quarantine.release
        approves the move — so between those two events the row says
        "archive" while the document is still, physically and by policy,
        quarantined. Keying only on disposition handed that window to
        Investigator, which is the exact thing release_pending exists to
        prevent. So: a pending release counts as quarantined, and so does
        a file that actually sits under the quarantine root, whatever the
        row claims.
        """
        if _is_contained(job["disposition"], job["archive_path"], job["release_pending"]):
            return "jobs.pdf.read.quarantined"
        return "jobs.pdf.read"

    archive_roots = [
        config.destination.archive.resolve(),
        config.destination.quarantine.resolve(),
    ]

    def _render_job_detail(
        request: Request,
        job_id: str,
        user,
        revealed: dict[str, Any] | None = None,
        flash: str | None = None,
        status_code: int = 200,
        reprocess_result: dict[str, Any] | None = None,
        purge_error: dict[str, Any] | None = None,
    ) -> HTMLResponse:
        job = _get_job_or_404(job_id)
        roles = set(user.roles)
        can_see_hits = has_permission(roles, "dlp.hits.read")
        can_see_audit = has_permission(roles, "audit.read")
        can_reveal = has_permission(roles, "dlp.reveal")
        can_release = has_permission(roles, "quarantine.release")
        pdf_permission_needed = _pdf_permission_for(job)
        can_view_pdf = has_permission(roles, pdf_permission_needed)
        audit_events = pipeline.audit.events_for_job(job_id) if can_see_audit else []
        # Purge never touches the index row because it proves the job
        # happened, so "was this purged" isn't a stored
        # field anywhere; it's derived the same way the PDF route already
        # decides whether it has a file to serve.
        content_purged = not has_content(pipeline.content_root, job_id)
        document_purged = not Path(job["archive_path"]).is_file()
        # Missing files say WHAT is gone, not WHY: retention deletes
        # whole partitions and would otherwise be reported as a purge that
        # nobody performed. The audit trail is the only thing that knows,
        # and it's already in memory for anyone who can read it — so the
        # cause is confirmed from there when available, and the wording
        # stays cause-neutral when it isn't.
        purge_confirmed = any(e.get("event") == "content.purged" for e in audit_events)
        # Whatever the companion file (and the PDF's own Info dictionary)
        # carried, after the source.metadata_fields allowlist ran at
        # ingest — so an empty dict means "nothing was allowlisted", not
        # "nothing was supplied", and the screen says which.
        doc_metadata = _json_or_empty(job.get("metadata"))
        audit_fields = _json_or_empty(job.get("audit_fields"))
        # Both remaining actions need something that's already gone:
        # there is nothing left to purge once content and (for a hard
        # purge) the PDF are deleted, and reprocessing reads the content
        # store in "rules" mode and the PDF in "extract" mode — with
        # neither on disk there is no mode that can run.
        reprocessable = not (content_purged and document_purged)
        may_purge = has_permission(roles, "jobs.purge")
        may_reprocess = has_permission(roles, "jobs.reprocess.preview")
        can_purge = may_purge and reprocessable  # nothing left once both are gone
        can_reprocess_preview = may_reprocess and reprocessable
        can_reprocess_commit = has_permission(roles, "jobs.reprocess.commit") and reprocessable
        receipts = pipeline.operations.receipts(job_id)
        for receipt in receipts:
            receipt["metadata"] = _json_or_empty(receipt.get("metadata"))

        return templates.TemplateResponse(
            request,
            "job_detail.html",
            {
                "user": user,
                "job": job,
                "receipts": receipts,
                "live_ruleset": pipeline.ruleset_version,
                "can_see_hits": can_see_hits,
                "can_see_audit": can_see_audit,
                "can_reveal": can_reveal,
                "can_release": can_release,
                "can_purge": can_purge,
                "can_view_pdf": can_view_pdf,
                "pdf_permission_needed": pdf_permission_needed,
                "content_purged": content_purged,
                "document_purged": document_purged,
                "purge_confirmed": purge_confirmed,
                "reprocessable": reprocessable,
                "may_purge": may_purge,
                "may_reprocess": may_reprocess,
                "doc_metadata": doc_metadata,
                "audit_fields": audit_fields,
                "metadata_allowlist": list(config.source.metadata_fields),
                "can_reprocess_preview": can_reprocess_preview,
                "can_reprocess_commit": can_reprocess_commit,
                "reprocess_result": reprocess_result,
                "purge_error": purge_error,
                "audit_events": audit_events,
                "revealed": revealed,
                "flash": flash,
                "csrf_token": get_csrf_token(request),
            },
            status_code=status_code,
        )

    @app.exception_handler(HTTPException)
    def handle_http_exception(request: Request, exc: HTTPException) -> Response:
        # 401 (not logged in) sends the browser to the login page; 403
        # (logged in, wrong role) and everything else render as a real,
        # styled page — the nav already hides links a role can't use, but
        # a bookmarked or typed URL still needs to land somewhere better
        # than a bare unstyled error string.
        if exc.status_code == 401:
            return RedirectResponse("/login", status_code=303)
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "user": get_current_user(request),
                "status_code": exc.status_code,
                "detail": exc.detail,
            },
            status_code=exc.status_code,
        )

    def _worker_health():
        path = config.destination.work_dir / "watcher.json"
        try:
            health = json.loads(path.read_text())
            age = (datetime.now(UTC) - datetime.fromisoformat(health["updated_at"])).total_seconds()
            health["stale"] = age > max(config.source.poll_seconds * 3, 30)
            return health
        except (OSError, ValueError, KeyError):
            return {"stale": True, "state": "No worker heartbeat", "backlog": None}

    @app.get("/failed", response_model=None)
    def failed_jobs(request: Request, resolved: bool = False, page: int = Query(1, ge=1),
                    user=Depends(require_permission("jobs.failed.manage"))):
        rows = failures.items(resolved=resolved)
        return templates.TemplateResponse(request, "failed.html", {
            "user": user, "items": rows[(page - 1) * 100:page * 100], "resolved": resolved,
            "csrf_token": get_csrf_token(request), "page": page,
            "previous_url": str(request.url.include_query_params(page=page - 1)) if page > 1 else None,
            "next_url": str(request.url.include_query_params(page=page + 1)) if len(rows) > page * 100 else None,
            "flash": request.session.pop("queue_flash", None),
        })

    @app.get("/failed/{kind}/{job_id}/pdf", response_model=None)
    def failed_pdf(kind: str, job_id: str, user=Depends(require_permission("jobs.failed.manage"))):
        try:
            path = failures.folder(kind, job_id) / "document.pdf"
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from None
        if path.is_symlink() or not path.is_file():
            raise HTTPException(404, "Regular PDF unavailable")
        pipeline.audit.append("pdf.failed_viewed", job_id=job_id, actor=user.username)
        return FileResponse(path, media_type="application/pdf", filename=f"{job_id}.pdf")

    @app.post("/failed/{kind}/{job_id}/{action}", response_model=None)
    def failed_action(request: Request, kind: str, job_id: str, action: str,
                      reason: str = Form(...), csrf_token: str = Form(...), confirm_delivery: bool = Form(False),
                      user=Depends(require_permission("jobs.failed.manage"))):
        verify_csrf(request, csrf_token)
        try:
            if action == "retry":
                failures.retry(kind, job_id, reason, user.username, confirm_delivery)
                message = "Retry completed. Review the resulting job in Jobs."
            elif action == "resolve":
                failures.resolve(kind, job_id, reason, user.username)
                message = "Marked resolved. The file is retained in the resolved queue."
            else:
                raise ValueError("Unknown action")
        except ValueError as exc:
            message = str(exc)
        request.session["queue_flash"] = message
        return RedirectResponse("/failed", status_code=303)

    @app.get("/", response_model=None)
    def overview(
        request: Request, user=Depends(require_permission("jobs.list"))
    ) -> HTMLResponse:
        today_utc = datetime.now(UTC).date()  # matches dt= partitioning, not local time
        # Counted in the query engine and fetched at the size shown: this
        # page used to pull every row ever ingested into Python to produce
        # five integers and a ten-row table.
        stats = index_stats(pipeline.index_root, today_utc)
        stats["failed"] = len(failures.items())
        recent = latest_index_rows(pipeline.index_root, limit=10, newest_first=True)
        return templates.TemplateResponse(
            request,
            "overview.html",
            {
                "user": user,
                "stats": stats,
                "recent_jobs": recent,
                "names": pipeline.operations.display_names(row["job_id"] for row in recent),
                "health": _worker_health(),
                "today": today_utc.isoformat(),
                "extraction_timeout": config.extraction.timeout_seconds,
                "can_verify": has_permission(set(user.roles), "audit.verify"),
                "chain_status": config.audit.integrity,
            },
        )

    @app.get("/login", response_model=None)
    def login_form(
        request: Request, auth: str = "", loggedout: str = ""
    ) -> HTMLResponse | RedirectResponse:
        # With an IdP configured, SSO is THE way in: don't make everyone
        # pick it off a menu every time, just go. `?auth=local` is the
        # documented escape hatch to the break-glass form, and a
        # fresh logout stops here too — otherwise signing out would bounce
        # straight back through a still-live IdP session and silently sign
        # the user back in, which isn't a logout at all.
        error = request.session.pop("login_error", None)
        if oidc_cfg is not None and auth != "local" and not loggedout and not error:
            return RedirectResponse("/login/oidc", status_code=303)
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "user": None,
                "oidc_enabled": oidc_cfg is not None,
                "error": error,
                "loggedout": bool(loggedout),
            },
        )

    @app.post("/login", response_model=None)
    def login_submit(
        request: Request, username: str = Form(...), password: str = Form(...)
    ) -> HTMLResponse | RedirectResponse:
        throttle = app.state.login_throttle
        client = request.client.host if request.client else ""

        def _refuse(message: str, status_code: int):
            # Deliberately the same message whichever way it failed: "that
            # account is locked out" tells an anonymous caller the account
            # exists, which is the enumeration this endpoint otherwise
            # avoids by burning equal argon2 work on unknown usernames.
            return templates.TemplateResponse(
                request,
                "login.html",
                {
                    "user": None,
                    "oidc_enabled": oidc_cfg is not None,
                    "error": message,
                },
                status_code=status_code,
            )

        if throttle.is_locked(username, client):
            # Checked before authenticate(), so a locked-out caller never
            # reaches the argon2 work — the point is to stop paying for
            # attempts, not just to stop believing them.
            pipeline.audit.append(
                "auth.throttled", actor=username, client=client, method="local"
            )
            return _refuse("Too many failed attempts. Try again shortly.", 429)

        account = app.state.user_store.authenticate(username, password)
        if account is None:
            throttle.record_failure(username, client)
            # Who tried to get in, and failed, is exactly as auditable as
            # what they did once inside. Without it a brute-force campaign
            # leaves no trace in the one record an auditor actually reads.
            pipeline.audit.append(
                "auth.failed", actor=username, client=client, method="local"
            )
            return _refuse("Invalid username or password.", 401)

        throttle.record_success(username, client)
        establish_session(request, account.username, account.roles)
        pipeline.audit.append(
            "auth.succeeded",
            actor=account.username,
            client=client,
            method="local",
            roles=sorted(account.roles),
        )
        return RedirectResponse("/jobs", status_code=303)

    if oidc_cfg is not None:

        @app.get("/login/oidc", response_model=None)
        async def login_oidc(request: Request):
            redirect_uri = str(request.url_for("auth_callback"))
            return await oauth.oidc.authorize_redirect(request, redirect_uri)

        @app.get("/auth/callback", response_model=None)
        async def auth_callback(request: Request) -> RedirectResponse:
            try:
                token = await oauth.oidc.authorize_access_token(request)
            except Exception as exc:
                # Land on the local form, not a bare 401: a 401 redirects
                # to /login, which now auto-redirects back into SSO — a
                # broken IdP would put the browser in a redirect loop. The
                # specific failure goes to the log, not the page; it can
                # carry issuer/token detail a login screen shouldn't.
                logger.warning("OIDC login failed: %s", exc)
                pipeline.audit.append(
                    "auth.failed",
                    actor=None,
                    client=request.client.host if request.client else "",
                    method="oidc",
                    reason="token_exchange_failed",
                )
                request.session["login_error"] = (
                    "Single sign-on failed. Try again, or use a local account."
                )
                return RedirectResponse("/login?auth=local", status_code=303)

            claims = token.get("userinfo") or {}
            username = claims.get("preferred_username") or claims.get("sub")
            if not username:
                # Same reasoning as the exchange failure above: a 401 here
                # would redirect into /login, which redirects back into
                # SSO. Send the operator somewhere they can actually act.
                logger.warning("OIDC login failed: no subject/username claim in ID token")
                pipeline.audit.append(
                    "auth.failed",
                    actor=None,
                    client=request.client.host if request.client else "",
                    method="oidc",
                    reason="no_username_claim",
                )
                request.session["login_error"] = (
                    "Single sign-on returned no username. Try again, or use a local account."
                )
                return RedirectResponse("/login?auth=local", status_code=303)

            # External role/group names, mapped to our internal ones where
            # they differ, then intersected with what we actually know —
            # an IdP's own default/composite roles (e.g. Keycloak's
            # "offline_access") are noise here, not a privilege.
            external = claims.get(oidc_cfg.roles_claim) or []
            mapped = {oidc_cfg.role_map.get(r, r) for r in external}
            granted = frozenset(mapped & set(ALL_ROLES))
            if not granted:
                pipeline.audit.append(
                    "auth.failed",
                    actor=username,
                    client=request.client.host if request.client else "",
                    method="oidc",
                    reason="no_recognised_role",
                )
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"authenticated as {username!r}, but the '{oidc_cfg.roles_claim}' claim "
                        f"granted no recognised role"
                    ),
                )

            establish_session(request, username, granted, method="oidc")
            pipeline.audit.append(
                "auth.succeeded",
                actor=username,
                client=request.client.host if request.client else "",
                method="oidc",
                roles=sorted(granted),
            )
            return RedirectResponse("/jobs", status_code=303)

    @app.post("/logout", response_model=None)
    def logout(request: Request) -> RedirectResponse:
        # Read before clearing — afterwards there is no one to name, and
        # a sign-out with no actor is not worth recording.
        user = get_current_user(request)
        pipeline.operations.revoke(token=request.session.get("token"))
        request.session.clear()
        if user is not None:
            pipeline.audit.append("auth.logout", actor=user.username)
        return RedirectResponse("/login?loggedout=1", status_code=303)

    @app.get("/jobs", response_model=None)
    def jobs_list(
        request: Request,
        disposition: str = "",
        start: str = "",
        end: str = "",
        page: int = Query(1, ge=1, le=100000),
        pending: bool = False,
        user=Depends(require_permission("jobs.list")),
    ) -> HTMLResponse | RedirectResponse:
        if disposition == "failed":
            return RedirectResponse("/failed", status_code=303)
        if disposition not in ("", "archive", "quarantine"):
            raise HTTPException(400, "Unknown disposition")
        start_d = _parse_date_param(start, "start")
        end_d = _parse_date_param(end, "end")
        # Ask for one more than shown so "there is more" is a length check
        # rather than a second counting query — the same trick search uses.
        rows = latest_index_rows(
            pipeline.index_root, start=start_d, end=end_d,
            limit=JOBS_PAGE_SIZE + 1, newest_first=True,
            disposition=disposition or None, release_pending=pending, offset=(page - 1) * JOBS_PAGE_SIZE,
        )
        truncated = len(rows) > JOBS_PAGE_SIZE
        rows = rows[:JOBS_PAGE_SIZE]
        return templates.TemplateResponse(
            request,
            "jobs_list.html",
            {
                "user": user,
                "jobs": rows,
                "truncated": truncated,
                "page_size": JOBS_PAGE_SIZE,
                "page": page,
                "pending": pending,
                "names": pipeline.operations.display_names(row["job_id"] for row in rows),
                "previous_url": str(request.url.include_query_params(page=page - 1)) if page > 1 else None,
                "next_url": str(request.url.include_query_params(page=page + 1)) if truncated else None,
                "filters": {"disposition": disposition, "start": start, "end": end},
            },
        )

    @app.get("/jobs/{job_id}", response_model=None)
    def job_detail(
        request: Request,
        job_id: str,
        user=Depends(require_permission("jobs.metadata.read")),
    ) -> HTMLResponse:
        return _render_job_detail(request, job_id, user)

    def _serve_pdf(job_id: str, user, *, event: str, disposition_type: str) -> FileResponse:
        job = _get_job_or_404(job_id)
        permission = _pdf_permission_for(job)
        if not has_permission(set(user.roles), permission):
            raise HTTPException(
                status_code=403,
                detail=f"This page needs the '{permission}' permission, which your role doesn't grant.",
            )
        pdf_path = Path(job["archive_path"]).resolve()
        # Defense in depth: archive_path comes from the index, not the
        # request, but a request should still never be able to walk an
        # index row into serving a file outside the two roots PDFs are
        # ever written to.
        if not pdf_path.is_file() or not any(
            pdf_path.is_relative_to(root) for root in archive_roots
        ):
            raise HTTPException(status_code=404, detail="original PDF not found on disk")
        pipeline.audit.append(event, job_id=job_id, actor=user.username)
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=f"{job_id}.pdf",
            content_disposition_type=disposition_type,
        )

    @app.get("/jobs/{job_id}/pdf", response_model=None)
    def job_pdf_preview(job_id: str, user=Depends(require_login)) -> FileResponse:
        # inline — the browser renders it in place rather than saving a
        # copy to the viewer's machine, which is its own audit-worthy
        # event distinct from a deliberate download.
        return _serve_pdf(job_id, user, event="pdf.viewed", disposition_type="inline")

    @app.get("/jobs/{job_id}/pdf/download", response_model=None)
    def job_pdf_download(job_id: str, user=Depends(require_login)) -> FileResponse:
        return _serve_pdf(job_id, user, event="pdf.downloaded", disposition_type="attachment")

    @app.post("/jobs/{job_id}/reveal", response_model=None)
    def reveal_hit(
        request: Request,
        job_id: str,
        hit_index: int = Form(...),
        csrf_token: str = Form(...),
        user=Depends(require_permission("dlp.reveal")),
    ) -> HTMLResponse:
        verify_csrf(request, csrf_token)
        job = _get_job_or_404(job_id)
        if not 0 <= hit_index < len(job["hits"]):
            raise HTTPException(status_code=400, detail="invalid hit index")
        hit = job["hits"][hit_index]

        # The content store's `lines` are the one place raw (unmasked)
        # text lives, stored as structured lines for reprocessing —
        # reveal re-derives the value from the hit's own recorded
        # position rather than from any value stored at scan time, since
        # none is: DLPHit never carries the raw match.
        doc = read_document_text(pipeline.content_root, job_id)
        raw_value = _rederive_hit_value(doc, hit, pipeline.engine.rules)

        pipeline.audit.append(
            "dlp.revealed",
            job_id=job_id,
            actor=user.username,
            rule_id=hit["rule_id"],
            hit_index=hit_index,
            line_number=hit["line_number"],
            found=raw_value is not None,
        )
        return _render_job_detail(
            request, job_id, user, revealed={"index": hit_index, "value": raw_value}
        )

    @app.post("/jobs/{job_id}/release", response_model=None)
    def release_job(
        request: Request,
        job_id: str,
        reason: str = Form(...),
        csrf_token: str = Form(...),
        user=Depends(require_permission("quarantine.release")),
    ) -> HTMLResponse:
        verify_csrf(request, csrf_token)
        if not reason.strip():
            raise HTTPException(400, "A reason is required.")
        result = reprocessor.release(job_id, reason=reason.strip(), actor=user.username)
        flash = "Released." if result.released else f"Not released: {result.reason_denied}"
        return _render_job_detail(request, job_id, user, flash=flash)

    @app.post("/jobs/{job_id}/purge", response_model=None)
    def purge_job(
        request: Request,
        job_id: str,
        reason: str = Form(...),
        hard: bool = Form(False),
        confirm_text: str = Form(...),
        csrf_token: str = Form(...),
        user=Depends(require_permission("jobs.purge")),
    ) -> HTMLResponse:
        # One form, in a modal — reason, hard-delete, and the typed
        # "purge" confirmation are all gathered together because purge is
        # the one action nothing else in the console can walk back), but
        # the server still enforces confirm_text itself rather than
        # trusting the modal's own gating, since nothing stops a request
        # from skipping the UI entirely.
        verify_csrf(request, csrf_token)
        # Resolve the job BEFORE deleting anything: purge addresses files
        # by globbing the job id, so an id that isn't a real, single job
        # must never reach the filesystem layer.
        _get_job_or_404(job_id)
        if confirm_text != "purge":
            return _render_job_detail(
                request,
                job_id,
                user,
                purge_error={
                    "reason": reason,
                    "hard": hard,
                    "message": "Type 'purge' exactly to confirm — nothing was deleted.",
                },
            )
        if not reason.strip():
            raise HTTPException(400, "A reason is required.")
        result = pipeline.purge_content(job_id, reason=reason.strip(), actor=user.username, hard=hard)
        return _render_job_detail(request, job_id, user, flash="Extracted text deleted." + (" Original PDF deleted." if result.hard else " Original PDF retained."))

    @app.post("/jobs/{job_id}/reprocess", response_model=None)
    def reprocess_job(
        request: Request,
        job_id: str,
        mode: str = Form("rules"),
        reprocess_action: str = Form(...),  # "preview" or "commit"
        csrf_token: str = Form(...),
        user=Depends(require_login),
    ) -> HTMLResponse:
        verify_csrf(request, csrf_token)
        try:
            checked_mode = parse_mode(mode)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid reprocess request") from None
        if reprocess_action not in ("preview", "commit"):
            raise HTTPException(status_code=400, detail="invalid reprocess request")
        permission = (
            "jobs.reprocess.commit" if reprocess_action == "commit" else "jobs.reprocess.preview"
        )
        if not has_permission(set(user.roles), permission):
            raise HTTPException(
                status_code=403,
                detail=f"This page needs the '{permission}' permission, which your role doesn't grant.",
            )
        _get_job_or_404(job_id)
        runner = reprocessor.commit if reprocess_action == "commit" else reprocessor.preview
        try:
            summary = runner(job_ids=[job_id], mode=checked_mode)
        except AssessmentExists:
            # Something else recorded this assessment first — another
            # operator, or the CLI. Refusing beats silently overwriting
            # their assessment; the page reloads showing the state that
            # actually won, and the operator can decide again from there.
            return _render_job_detail(
                request,
                job_id,
                user,
                flash=(
                    "This job was reassessed by someone else while you were looking at it. "
                    "Nothing was overwritten — review the current assessment and retry if "
                    "you still want to."
                ),
            )
        outcome = summary.outcomes[0] if summary.outcomes else None
        return _render_job_detail(
            request,
            job_id,
            user,
            reprocess_result={"action": reprocess_action, "mode": mode, "outcome": outcome},
        )

    @app.get("/search", response_model=None)
    def search_page(
        request: Request,
        q: str = "",
        severity: str = "",
        start: str = "",
        end: str = "",
        page: int = Query(1, ge=1, le=100000),
        user=Depends(require_permission("jobs.text.read")),
    ) -> HTMLResponse:
        # jobs.text.read, not jobs.list — a search result's snippet is a
        # slice of raw full_text, the same content that gate protects
        # everywhere else, so Viewer/Auditor don't get a search box.
        context: dict[str, Any] = {
            "user": user,
            "filters": {"q": q, "severity": severity, "start": start, "end": end},
            "response": None,
            "error": None,
            "page": page,
            "previous_url": str(request.url.include_query_params(page=page - 1)) if page > 1 else None,
            "next_url": None,
        }
        if q:
            # Inline rather than a 400 page: this screen already reports a
            # bad severity the same way, and the operator's query is right
            # there in the form to correct.
            try:
                start_d = date.fromisoformat(start) if start else None
                end_d = date.fromisoformat(end) if end else None
            except ValueError:
                context["error"] = "Start and end must be dates in YYYY-MM-DD form."
                return templates.TemplateResponse(request, "search.html", context)
            try:
                response = run_search(
                    pipeline.content_root,
                    pipeline.index_root,
                    q,
                    start=start_d,
                    end=end_d,
                    severity=severity or None,
                    offset=(page - 1) * 100,
                )
            except (SearchError, QueryTimeout) as exc:
                context["error"] = str(exc)
            else:
                # A snippet is a raw slice of the document, so it belongs
                # behind the same gate as opening that document. Without
                # this, a quarantined document's PDF was admin-only while
                # its text was searchable by any investigator — and since
                # the snippet is centred on the match, searching a word
                # near a hit returned the very value the quarantine, the
                # masking, and the admin-only dlp.reveal all exist to
                # protect. The result itself still shows (finding a
                # quarantined document is the investigator's job); only
                # the excerpt is withheld.
                if not has_permission(set(user.roles), "jobs.pdf.read.quarantined"):
                    for result in response.results:
                        if _is_contained(result.disposition, result.archive_path):
                            result.snippet = ""
                            result.snippet_withheld = True
                context["response"] = response
                context["names"] = pipeline.operations.display_names(
                    result.job_id for result in response.results
                )
                context["next_url"] = str(request.url.include_query_params(page=page + 1)) if response.truncated else None
                # Same shape as the CLI's `dlpduck search` audit event —
                # an unbounded search is legitimate, not an incident, but
                # "who searched everything, and for what" stays answerable.
                # Query recording follows console.audit_search_terms. The
                # private default stores a keyed digest for correlation;
                # deployments can explicitly choose readable terms.
                pipeline.audit.append(
                    "ui.search",
                    actor=user.username,
                    **audit_terms(
                        q, config.console.audit_search_terms, pipeline.config.hmac_key()
                    ),
                    severity=severity or None,
                    range=[
                        start_d.isoformat() if start_d else None,
                        end_d.isoformat() if end_d else None,
                    ],
                    unbounded=response.unbounded,
                    results=len(response.results),
                )
        return templates.TemplateResponse(request, "search.html", context)

    @app.get("/rules", response_model=None)
    def rules_page(
        request: Request, user=Depends(require_permission("rules.read"))
    ) -> HTMLResponse:
        rules_data = [
            {
                "id": r.id,
                "name": r.name,
                "pattern": r.regex.pattern,
                "severity": r.severity.value,
                "action": r.action,
                "scope": r.scope,
                "line_scope": r.line_scope,
                "from_end": r.from_end,
                "min_line": r.min_line,
                "max_line": r.max_line,
                "validator": r.validator_name,
                "mask_keep": r.mask_keep,
                "requires_context": r.ctx_regex.pattern if r.ctx_regex else None,
                "context_window": r.ctx_window,
            }
            for r in pipeline.engine.rules
        ]
        return templates.TemplateResponse(
            request,
            "rules.html",
            {"user": user, "rules": rules_data, "ruleset_version": pipeline.ruleset_version},
        )

    @app.get("/audit", response_model=None)
    def audit_page(
        request: Request,
        start: str = "",
        end: str = "",
        before: int | None = Query(None, gt=0),
        user=Depends(require_permission("audit.read")),
    ) -> HTMLResponse:
        start_d = _parse_date_param(start, "start")
        end_d = _parse_date_param(end, "end")
        events = pipeline.audit.events(start=start_d, end=end_d, before=before, limit=101)
        return templates.TemplateResponse(
            request,
            "audit.html",
            {
                "user": user,
                "events": events[:100],
                "next_url": str(request.url.include_query_params(before=events[99]["seq"])) if len(events) > 100 else None,
                "filters": {"start": start, "end": end},
                "can_verify": has_permission(set(user.roles), "audit.verify"),
                "verify_result": None,
                "csrf_token": get_csrf_token(request),
            },
        )

    @app.post("/audit/verify", response_model=None)
    def audit_verify(
        request: Request,
        csrf_token: str = Form(...),
        user=Depends(require_permission("audit.verify")),
    ) -> HTMLResponse:
        verify_csrf(request, csrf_token)
        result = pipeline.audit.verify()
        events = pipeline.audit.events()
        return templates.TemplateResponse(
            request,
            "audit.html",
            {
                "user": user,
                "events": events,
                "filters": {"start": "", "end": ""},
                "can_verify": True,
                "verify_result": {
                    "ok": result.ok,
                    "breaks": result.breaks,
                    "detail": "; ".join(str(b) for b in result.breaks[:5]),
                    # Reported even when the chain is intact — an emptied
                    # event is a thing an auditor needs to see, and "no
                    # breaks" alone would imply nothing had been removed.
                    "redactions": result.redactions,
                    "redaction_detail": "; ".join(str(r) for r in result.redactions[:5]),
                },
                "csrf_token": get_csrf_token(request),
            },
        )

    @app.get("/access", response_model=None)
    def access_page(
        request: Request, user=Depends(require_permission("access.write"))
    ) -> HTMLResponse:
        # Read-only: accounts live in static config, not a store this
        # screen can write to — see the template for why, and how to
        # actually add or remove one.
        users_data = [
            {"username": u.username, "roles": sorted(u.roles)}
            for u in app.state.user_store.all_users()
        ]
        return templates.TemplateResponse(
            request, "access.html", {"user": user, "users": users_data, "csrf_token": get_csrf_token(request)}
        )

    @app.post("/access/revoke", response_model=None)
    def revoke_sessions(request: Request, username: str = Form(...), reason: str = Form(...),
                        csrf_token: str = Form(...), user=Depends(require_permission("access.write"))):
        verify_csrf(request, csrf_token)
        if not username.strip() or not reason.strip():
            raise HTTPException(400, "Username and reason are required.")
        pipeline.operations.revoke(username=username.strip())
        pipeline.audit.append("auth.sessions_revoked", actor=user.username, username=username.strip(), reason=reason.strip())
        return RedirectResponse("/access?revoked=1", status_code=303)

    return app
