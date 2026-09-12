"""Integration tests for the console web app: login, RBAC enforcement per
route, and that the job screens actually reflect real pipeline data —
including that hit details are hidden from a role without dlp.hits.read
and the audit timeline is hidden from a role without audit.read.
"""

import json
import re
import shutil
import threading
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from dlpduck import __version__
from dlpduck.config import Config
from dlpduck.console.app import create_app
from dlpduck.console.auth import hash_password
from dlpduck.masking import mask
from dlpduck.pipeline import Pipeline
from dlpduck.reprocess import Reprocessor, latest_index_rows
from tests.pdf_factory import write_pdf

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"
PASSWORD = "correct horse battery staple"
# Password hashing deliberately uses production-cost Argon2 parameters. The
# console fixture is rebuilt for every test to isolate its files and sessions,
# but recomputing the same four hashes each time only burns CPU. One salted,
# valid hash can safely be shared by these fixed test accounts.
PASSWORD_HASH = hash_password(PASSWORD)


def _pdf(path: Path, lines: list[str]) -> Path:
    return write_pdf(path, lines)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
    monkeypatch.setenv("DLPDUCK_SESSION_SECRET", "test-session-secret-not-for-production")
    src = tmp_path / "drops"
    src.mkdir()
    config = Config.model_validate(
        {
            "source": {"name": "test", "path": str(src), "metadata_format": "none"},
            "destination": {
                "archive": str(tmp_path / "archive"),
                "quarantine": str(tmp_path / "quarantine"),
                "work_dir": str(tmp_path / "work"),
            },
            "extraction": {"isolate_worker": False, "native_min_chars": 0},
            "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
            "console": {
                "auth": {
                    "users": [
                        {"username": "viewer1", "password_hash": PASSWORD_HASH, "role": "viewer"},
                        {"username": "inv1", "password_hash": PASSWORD_HASH, "role": "investigator"},
                        {"username": "aud1", "password_hash": PASSWORD_HASH, "role": "auditor"},
                        {"username": "admin1", "password_hash": PASSWORD_HASH, "role": "dlp_admin"},
                    ]
                }
            },
        }
    )
    pipeline = Pipeline(config)
    staging = config.destination.work_dir / "_processing"

    clean_pdf = _pdf(tmp_path / "clean.pdf", ["An ordinary memo about the office party."])
    clean_ctx = pipeline.run_job(clean_pdf, None, staging)

    sensitive_pdf = _pdf(tmp_path / "card.pdf", ["Card 4111 1111 1111 1111 on file"])
    sensitive_ctx = pipeline.run_job(sensitive_pdf, None, staging)

    app = create_app(config, pipeline)
    client = TestClient(app)
    return {
        "client": client,
        "config": config,
        "pipeline": pipeline,
        "clean_job": clean_ctx.job_id,
        "sensitive_job": sensitive_ctx.job_id,
    }


@pytest.fixture
def env_with_metadata(tmp_path, monkeypatch):
    """A source that both configures a companion format AND allowlists the
    fields it carries — the shape where document metadata actually
    survives ingest and has something to show.
    """
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
    monkeypatch.setenv("DLPDUCK_SESSION_SECRET", "test-session-secret-not-for-production")
    src = tmp_path / "drops"
    src.mkdir()
    config = Config.model_validate(
        {
            "source": {
                "name": "test",
                "path": str(src),
                "metadata_format": "text",
                "metadata_suffix": ".txt",
                "metadata_fields": ["device_id", "department", "pdf_title"],
            },
            "destination": {
                "archive": str(tmp_path / "archive"),
                "quarantine": str(tmp_path / "quarantine"),
                "work_dir": str(tmp_path / "work"),
            },
            "extraction": {"isolate_worker": False, "native_min_chars": 0},
            "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
            "console": {
                "auth": {
                    "users": [
                        {"username": "admin1", "password_hash": PASSWORD_HASH, "role": "dlp_admin"},
                    ]
                }
            },
        }
    )
    pipeline = Pipeline(config)
    staging = config.destination.work_dir / "_processing"

    pdf = _pdf(tmp_path / "scan.pdf", ["An ordinary scanned memo."])
    meta = tmp_path / "scan.txt"
    meta.write_text("device_id=MFP-3F-04\ndepartment=Finance\nsecret_field=should-be-dropped\n")
    ctx = pipeline.run_job(pdf, meta, staging)

    app = create_app(config, pipeline)
    return {"client": TestClient(app), "config": config, "pipeline": pipeline, "job_id": ctx.job_id}


def _csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "no CSRF token found in page"
    return match.group(1)


def test_health_endpoints_report_process_and_watcher_state(env):
    client = env["client"]
    assert client.get("/health/live").json() == {"status": "ok"}

    missing = client.get("/health/ready")
    assert missing.status_code == 503
    assert missing.json()["watcher"]["stale"] is True

    (env["config"].destination.work_dir / "watcher.json").write_text(
        json.dumps(
            {
                "updated_at": datetime.now(UTC).isoformat(),
                "state": "Watching",
                "current_job": None,
                "backlog": 0,
            }
        )
    )
    ready = client.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"


def _login(client: TestClient, username: str) -> None:
    resp = client.post("/login", data={"username": username, "password": PASSWORD})
    assert resp.status_code in (200, 303)


class TestLogin:
    def test_login_page_renders_without_auth(self, env):
        resp = env["client"].get("/login")
        assert resp.status_code == 200
        assert "Log in" in resp.text
        assert f"DLPDuck v{__version__}" in resp.text
        assert resp.headers["cache-control"] == "no-store"

    def test_logout_revokes_a_captured_session_cookie(self, env):
        client = env["client"]
        _login(client, "viewer1")
        captured = client.cookies.get("session")
        assert captured

        client.post("/logout")

        replay = TestClient(client.app)
        replay.cookies.set("session", captured)
        response = replay.get("/jobs", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"

    def test_admin_can_revoke_another_users_active_sessions(self, env):
        app = env["client"].app
        viewer = TestClient(app)
        admin = TestClient(app)
        _login(viewer, "viewer1")
        _login(admin, "admin1")
        token = _csrf_token(admin.get("/access").text)

        response = admin.post(
            "/access/revoke",
            data={
                "username": "viewer1",
                "reason": "account disabled",
                "csrf_token": token,
            },
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert viewer.get("/jobs", follow_redirects=False).headers["location"] == "/login"


    def test_correct_credentials_log_in_and_redirect_to_jobs(self, env):
        client = env["client"]
        resp = client.post(
            "/login", data={"username": "viewer1", "password": PASSWORD}, follow_redirects=False
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/jobs"
        assert f"DLPDuck v{__version__}" in client.get("/jobs").text

    def test_wrong_password_is_rejected_with_401_and_stays_on_login(self, env):
        resp = env["client"].post("/login", data={"username": "viewer1", "password": "wrong"})
        assert resp.status_code == 401
        assert "Invalid username or password" in resp.text

    def test_unauthenticated_request_to_a_protected_route_redirects_to_login(self, env):
        resp = env["client"].get("/jobs", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login"


class TestLoginContinued:
    def test_logout_clears_the_session(self, env):
        client = env["client"]
        _login(client, "viewer1")
        assert client.get("/jobs").status_code == 200

        client.post("/logout")
        resp = client.get("/jobs", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login"

    def test_unauthenticated_root_redirects_to_login(self, env):
        resp = env["client"].get("/", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login"

    def test_authenticated_root_renders_the_overview(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Overview" in resp.text


class TestNeedsAttentionQueue:
    def test_admin_can_inspect_and_resolve_a_failed_document(self, env):
        client = env["client"]
        _login(client, "admin1")
        job_id = "f" * 32
        folder = env["config"].destination.work_dir / "failed" / job_id
        folder.mkdir(parents=True)
        (folder / "document.pdf").write_bytes(b"%PDF-1.4\n")
        (folder / "metadata.json").write_text(
            json.dumps(
                {
                    "job_id": job_id,
                    "filename": "unreadable scan.pdf",
                    "reason": "extraction_error",
                    "received_at": "2026-09-08T00:00:00+00:00",
                }
            )
        )

        page = client.get("/failed")
        assert page.status_code == 200
        assert "unreadable scan.pdf" in page.text
        assert "Retry processing" in page.text
        token = _csrf_token(page.text)

        response = client.post(
            f"/failed/failed/{job_id}/resolve",
            data={"reason": "invalid scanner export", "csrf_token": token},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "unreadable scan.pdf" not in client.get("/failed").text
        assert "unreadable scan.pdf" in client.get("/failed?resolved=true").text


class TestRetryDoesNotBlockTheRequest:
    """A retry re-runs extraction — for a large document, real minutes.
    The request that triggers it must come back immediately regardless,
    not make the operator's own browser tab wait the whole thing out."""

    def _failed_job(self, env, tmp_path, filename="scan.pdf"):
        pipeline = env["pipeline"]
        original_extract = pipeline.extractor.extract
        pipeline.extractor.extract = Mock(side_effect=RuntimeError("temporary parser error"))
        pdf = _pdf(tmp_path / filename, ["A document that will fail once, then succeed."])
        ctx = pipeline.run_job(pdf, None, env["config"].destination.work_dir / "_processing")
        pipeline.extractor.extract = original_extract
        return ctx.job_id, original_extract

    def test_single_retry_returns_before_extraction_finishes(self, env, tmp_path, monkeypatch):
        job_id, original_extract = self._failed_job(env, tmp_path)
        entered = threading.Event()
        release = threading.Event()

        def slow_extract(*args, **kwargs):
            entered.set()
            release.wait(timeout=5)
            return original_extract(*args, **kwargs)

        monkeypatch.setattr(env["pipeline"].extractor, "extract", slow_extract)

        client = env["client"]
        _login(client, "admin1")
        page = client.get("/failed")
        token = _csrf_token(page.text)

        # If this were still synchronous, this call would hang here until
        # release.set() below — nothing else in this test unblocks it. The
        # response coming back at all, with extraction still parked on
        # release.wait(), is the proof this no longer blocks the request.
        resp = client.post(
            f"/failed/failed/{job_id}/retry",
            data={"reason": "transient parser error, retrying", "csrf_token": token},
            follow_redirects=False,
        )
        assert resp.status_code == 303

        flash_page = client.get("/failed")
        assert "queued" in flash_page.text.lower()
        assert entered.wait(timeout=5), "extraction never started at all"
        assert (env["config"].destination.work_dir / "failed" / job_id).is_dir()  # not yet resolved

        release.set()
        client.app.state.background.shutdown(wait=True)

        assert not (env["config"].destination.work_dir / "failed" / job_id).exists()
        assert job_id[:12] in client.get("/jobs").text

    def test_check_retryable_fails_fast_without_touching_the_background(self, env, tmp_path):
        job_id, _ = self._failed_job(env, tmp_path)
        client = env["client"]
        _login(client, "admin1")
        page = client.get("/failed")
        token = _csrf_token(page.text)

        resp = client.post(
            f"/failed/failed/{job_id}/retry",
            data={"reason": "   ", "csrf_token": token},  # blank after stripping
            follow_redirects=False,
        )

        assert resp.status_code == 303
        assert "reason is required" in client.get("/failed").text.lower()
        # Never queued: the item is exactly as it was, no receipt minted.
        assert (env["config"].destination.work_dir / "failed" / job_id).is_dir()

    def test_bulk_retry_queues_without_waiting_for_any_of_them(self, env, tmp_path, monkeypatch):
        job_ids = [self._failed_job(env, tmp_path, filename=f"scan{i}.pdf")[0] for i in range(3)]
        original_extract = env["pipeline"].extractor.extract
        release = threading.Event()

        def slow_extract(*args, **kwargs):
            release.wait(timeout=5)
            return original_extract(*args, **kwargs)

        monkeypatch.setattr(env["pipeline"].extractor, "extract", slow_extract)

        client = env["client"]
        _login(client, "admin1")
        page = client.get("/failed")
        token = _csrf_token(page.text)

        resp = client.post(
            "/failed/bulk-retry",
            data={
                "items": [f"failed:{jid}" for jid in job_ids],
                "reason": "batch retry after parser fix",
                "csrf_token": token,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303  # returned without waiting on any of the three

        release.set()
        client.app.state.background.shutdown(wait=True)

        jobs_text = client.get("/jobs").text
        for jid in job_ids:
            assert jid[:12] in jobs_text


class TestJobsListPermissions:
    def test_viewer_can_list_jobs(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/jobs")
        assert resp.status_code == 200
        assert env["clean_job"][:12] in resp.text
        assert env["sensitive_job"][:12] in resp.text

    def test_investigator_can_list_jobs_too(self, env):
        client = env["client"]
        _login(client, "inv1")
        assert client.get("/jobs").status_code == 200

    def test_filter_by_disposition(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/jobs", params={"disposition": "quarantine"})
        assert env["sensitive_job"][:12] in resp.text
        assert env["clean_job"][:12] not in resp.text


class TestJobDetailPermissions:
    def test_unknown_job_id_is_404(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/jobs/does-not-exist")
        assert resp.status_code == 404

    def test_viewer_sees_metadata_but_not_hit_details(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get(f"/jobs/{env['sensitive_job']}")
        assert resp.status_code == 200
        assert "quarantine" in resp.text
        assert "dlp.hits.read" in resp.text  # the denial message
        assert "4111 1111 1111 1111" not in resp.text  # never the raw value
        # pan.generic keeps a 4-digit tail (mask_keep: 4) for a role that
        # *can* see hits — computed via mask() over the exact regex match,
        # not hardcoded, so this pins the actual masked form rather than a
        # bare "1111" substring, which a content-derived job_id can
        # coincidentally also contain (this page legitimately shows it in
        # "Technical details") and occasionally did, flaking the suite on
        # an unrelated hex digest.
        assert mask("4111 1111 1111 1111", keep=4) not in resp.text

    def test_investigator_sees_masked_hit_details(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get(f"/jobs/{env['sensitive_job']}")
        assert resp.status_code == 200
        assert "pan.generic" in resp.text or "Payment card number" in resp.text
        assert "•" in resp.text  # masked value shown
        assert "4111 1111 1111 1111" not in resp.text  # never the raw value

    def test_viewer_does_not_see_audit_timeline(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get(f"/jobs/{env['clean_job']}")
        assert "audit.read" in resp.text  # the denial message

    def test_auditor_sees_both_the_audit_timeline_and_masked_hits(self, env):
        # Auditor legitimately holds
        # dlp.hits.read — they need to see masked hits to audit what
        # happened. What they don't get is full_text/PDF access or reveal.
        client = env["client"]
        _login(client, "aud1")
        resp = client.get(f"/jobs/{env['sensitive_job']}")
        assert resp.status_code == 200
        assert "job.completed" in resp.text  # audit event visible
        assert "•" in resp.text  # masked hit visible
        assert "4111 1111 1111 1111" not in resp.text  # never the raw value

    def test_clean_job_shows_no_hits_message(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get(f"/jobs/{env['clean_job']}")
        assert "No hits" in resp.text


class TestPdfAccess:
    def test_unknown_job_pdf_is_404(self, env):
        client = env["client"]
        _login(client, "admin1")
        resp = client.get("/jobs/does-not-exist/pdf")
        assert resp.status_code == 404

    def test_investigator_can_open_an_archived_pdf(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get(f"/jobs/{env['clean_job']}/pdf")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"

    def test_investigator_cannot_open_a_quarantined_pdf(self, env):
        # jobs.pdf.read.quarantined is a separate, tighter permission —
        # same split as quarantine.release.
        client = env["client"]
        _login(client, "inv1")
        resp = client.get(f"/jobs/{env['sensitive_job']}/pdf")
        assert resp.status_code == 403
        assert "jobs.pdf.read.quarantined" in resp.text

    def test_dlp_admin_can_open_both_archived_and_quarantined_pdfs(self, env):
        client = env["client"]
        _login(client, "admin1")
        assert client.get(f"/jobs/{env['clean_job']}/pdf").status_code == 200
        assert client.get(f"/jobs/{env['sensitive_job']}/pdf").status_code == 200

    def test_preview_is_inline_and_download_is_an_attachment(self, env):
        client = env["client"]
        _login(client, "inv1")
        preview = client.get(f"/jobs/{env['clean_job']}/pdf")
        download = client.get(f"/jobs/{env['clean_job']}/pdf/download")
        assert "inline" in preview.headers["content-disposition"]
        assert "attachment" in download.headers["content-disposition"]

    def test_download_route_enforces_the_same_permission_as_preview(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get(f"/jobs/{env['sensitive_job']}/pdf/download")
        assert resp.status_code == 403
        assert "jobs.pdf.read.quarantined" in resp.text

    def test_viewer_cannot_open_any_pdf_and_the_denial_names_the_permission(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get(f"/jobs/{env['clean_job']}/pdf")
        assert resp.status_code == 403
        assert "jobs.pdf.read" in resp.text

    def test_auditor_cannot_open_the_pdf(self, env):
        # Auditor sees masked hits and the audit trail, never raw content
        # or the original document — the same "seeing THAT vs seeing
        # WHAT" split as dlp.reveal.
        client = env["client"]
        _login(client, "aud1")
        resp = client.get(f"/jobs/{env['clean_job']}/pdf")
        assert resp.status_code == 403

    def test_job_detail_page_links_to_the_pdf_only_when_permitted(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get(f"/jobs/{env['clean_job']}")
        assert f"/jobs/{env['clean_job']}/pdf" in resp.text

        _login(client, "viewer1")
        resp = client.get(f"/jobs/{env['clean_job']}")
        assert f"/jobs/{env['clean_job']}/pdf" not in resp.text
        assert "the original PDF is hidden" in resp.text

    def test_viewing_and_downloading_the_pdf_are_audited_as_separate_events(self, env):
        client = env["client"]
        _login(client, "inv1")
        client.get(f"/jobs/{env['clean_job']}/pdf")
        client.get(f"/jobs/{env['clean_job']}/pdf/download")

        import json

        events = []
        for path in (env["pipeline"].audit.root).glob("dt=*/events.jsonl"):
            events += [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]
        viewed = [e for e in events if e["event"] == "pdf.viewed"]
        downloaded = [e for e in events if e["event"] == "pdf.downloaded"]
        assert len(viewed) == 1
        assert len(downloaded) == 1
        assert viewed[0]["actor"] == downloaded[0]["actor"] == "inv1"
        assert viewed[0]["job_id"] == downloaded[0]["job_id"] == env["clean_job"]


class TestAuditDetailView:
    def test_search_event_detail_shows_query_range_and_severity(self, env):
        from dlpduck.search import audit_terms

        client = env["client"]
        _login(client, "inv1")
        client.get("/search", params={"q": "4111", "severity": "HIGH", "start": "2020-01-01"})

        # The exact digest this term hashes to, computed the same way the
        # audit event itself does — a precise stand-in for "the raw term
        # never appears in the audit trail". A blanket "4111 not anywhere
        # on the page" check is flaky: the page also renders several
        # genuinely random hex values per event (receipt_id, the chain's
        # own hash/prev), any of which can coincidentally contain "4111"
        # by pure chance and fail the test for a reason having nothing to
        # do with the search term.
        expected_hmac = audit_terms("4111", "hashed", env["config"].hmac_key())["terms_hmac"]

        [search_event] = [e for e in env["pipeline"].audit.events(limit=100) if e["event"] == "ui.search"]
        assert search_event["terms_hmac"] == expected_hmac
        assert "query" not in search_event  # never the plaintext term, in the "hashed" default

        _login(client, "aud1")
        resp = client.get("/audit")
        assert resp.status_code == 200
        assert "ui.search" in resp.text
        assert expected_hmac in resp.text
        assert "HIGH" in resp.text
        assert "2020-01-01" in resp.text

    def test_job_detail_audit_timeline_also_has_expandable_detail(self, env):
        client = env["client"]
        _login(client, "aud1")
        resp = client.get(f"/jobs/{env['sensitive_job']}")
        assert resp.status_code == 200
        assert "<details>" in resp.text
        assert "hit_count" in resp.text  # a job.completed field not in a dedicated column


class TestSessionIsolation:
    def test_two_separate_clients_do_not_share_a_session(self, env):
        client_a = TestClient(env["client"].app)
        client_b = TestClient(env["client"].app)
        _login(client_a, "viewer1")

        assert client_a.get("/jobs").status_code == 200
        assert client_b.get("/jobs", follow_redirects=False).status_code == 303


class TestCsrfProtection:
    def test_missing_csrf_token_is_rejected(self, env):
        client = env["client"]
        _login(client, "admin1")
        resp = client.post(
            f"/jobs/{env['sensitive_job']}/purge",
            data={"reason": "test", "confirm_text": "purge"},
        )
        assert resp.status_code == 422  # required Form field absent

    def test_wrong_csrf_token_is_rejected(self, env):
        client = env["client"]
        _login(client, "admin1")
        client.get(f"/jobs/{env['sensitive_job']}")  # issues a real token into the session
        resp = client.post(
            f"/jobs/{env['sensitive_job']}/purge",
            data={"reason": "test", "confirm_text": "purge", "csrf_token": "not-the-real-token"},
        )
        assert resp.status_code == 403

    def test_correct_csrf_token_is_accepted(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)
        resp = client.post(
            f"/jobs/{env['sensitive_job']}/purge",
            data={"reason": "test", "confirm_text": "purge", "csrf_token": token},
        )
        assert resp.status_code == 200


class TestRevealAction:
    def test_dlp_admin_can_reveal_a_hit(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)

        resp = client.post(
            f"/jobs/{env['sensitive_job']}/reveal",
            data={"hit_index": 0, "csrf_token": token},
        )
        assert resp.status_code == 200
        assert "4111 1111 1111 1111" in resp.text or "4111111111111111" in resp.text

    def test_investigator_cannot_reveal(self, env):
        client = env["client"]
        _login(client, "inv1")
        # can_reveal is False for investigator, so the Reveal form (and
        # its token) never renders on their page in the first place — the
        # permission Depends denies this before the CSRF check runs.
        resp = client.post(
            f"/jobs/{env['sensitive_job']}/reveal",
            data={"hit_index": 0, "csrf_token": "irrelevant"},
        )
        assert resp.status_code == 403

    def test_reveal_is_audited(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)

        client.post(
            f"/jobs/{env['sensitive_job']}/reveal",
            data={"hit_index": 0, "csrf_token": token},
        )

        events = env["pipeline"].audit.events_for_job(env["sensitive_job"])
        reveal_events = [e for e in events if e["event"] == "dlp.revealed"]
        assert len(reveal_events) == 1
        assert reveal_events[0]["actor"] == "admin1"

    def test_invalid_hit_index_is_rejected(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)

        resp = client.post(
            f"/jobs/{env['sensitive_job']}/reveal",
            data={"hit_index": 999, "csrf_token": token},
        )
        assert resp.status_code == 400


class TestReleaseAction:
    def _deescalate(self, env):
        # Reprocess with a narrower ruleset so the sensitive job's
        # quarantine de-escalates and becomes release_pending.
        narrow_config = Config.model_validate(
            {
                **env["config"].model_dump(mode="json"),
                "dlp": {"rules": [{"id": "never_matches", "name": "x", "pattern": "ZZZ_NEVER_ZZZ"}]},
            }
        )
        Reprocessor(Pipeline(narrow_config)).commit()

    def test_dlp_admin_can_release_a_pending_job(self, env):
        self._deescalate(env)
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)

        resp = client.post(
            f"/jobs/{env['sensitive_job']}/release",
            data={"reason": "confirmed false positive", "csrf_token": token},
        )
        assert resp.status_code == 200
        assert "Released" in resp.text

        rows = latest_index_rows(env["pipeline"].index_root, job_ids=[env["sensitive_job"]])
        assert rows[0]["release_pending"] is False

    def test_viewer_cannot_release(self, env):
        self._deescalate(env)
        client = env["client"]
        _login(client, "viewer1")
        # The permission Depends runs before the CSRF check in the route
        # body, so a viewer is denied regardless of what token they send —
        # the release form doesn't even render for them in the first place.
        resp = client.post(
            f"/jobs/{env['sensitive_job']}/release",
            data={"reason": "test", "csrf_token": "irrelevant"},
        )
        assert resp.status_code == 403


class TestPurgeAction:
    def test_purge_modal_is_present_but_not_auto_opened(self, env):
        client = env["client"]
        _login(client, "admin1")
        resp = client.get(f"/jobs/{env['sensitive_job']}")
        assert resp.status_code == 200
        assert 'id="purge-modal"' in resp.text
        assert "<script>document.getElementById('purge-modal').showModal();</script>" not in resp.text

    def test_wrong_confirm_text_reopens_the_modal_with_the_error(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)
        resp = client.post(
            f"/jobs/{env['sensitive_job']}/purge",
            data={"reason": "wrong document", "confirm_text": "nope", "csrf_token": token},
        )
        assert "<script>document.getElementById('purge-modal').showModal();</script>" in resp.text
        assert "wrong document" in resp.text  # reason preserved

    def test_wrong_confirm_text_does_not_purge(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)

        resp = client.post(
            f"/jobs/{env['sensitive_job']}/purge",
            data={
                "reason": "wrong document",
                "confirm_text": "yes please",
                "csrf_token": token,
            },
        )
        assert resp.status_code == 200
        assert "nothing was deleted" in resp.text
        assert list(env["config"].destination.quarantine.glob(f"dt=*/{env['sensitive_job']}.pdf"))

    def test_soft_purge_removes_content_not_pdf(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)

        resp = client.post(
            f"/jobs/{env['sensitive_job']}/purge",
            data={"reason": "wrong document", "confirm_text": "purge", "csrf_token": token},
        )
        assert resp.status_code == 200
        assert "Extracted text deleted. Original PDF retained." in resp.text

        assert list(env["config"].destination.quarantine.glob(f"dt=*/{env['sensitive_job']}.pdf"))

    def test_hard_purge_removes_the_pdf_too(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)

        resp = client.post(
            f"/jobs/{env['sensitive_job']}/purge",
            data={
                "reason": "erasure request",
                "hard": "true",
                "confirm_text": "purge",
                "csrf_token": token,
            },
        )
        assert resp.status_code == 200
        assert "Extracted text deleted. Original PDF deleted." in resp.text
        assert not list(env["config"].destination.quarantine.glob(f"dt=*/{env['sensitive_job']}.pdf"))

    def test_investigator_cannot_purge(self, env):
        client = env["client"]
        _login(client, "inv1")
        # can_purge is False for investigator — same reasoning as reveal.
        resp = client.post(
            f"/jobs/{env['sensitive_job']}/purge",
            data={"reason": "test", "confirm_text": "purge", "csrf_token": "irrelevant"},
        )
        assert resp.status_code == 403


class TestPurgeStatus:
    """Purge never touches the index row, so whether a job was
    purged has to be derived from what's actually on disk — this covers
    that the job detail page surfaces it plainly instead of only in the
    audit trail, and stops offering PDF actions that would just 404.
    """

    def _purge(self, client, job_id, token, hard=False):
        data = {"reason": "test purge", "confirm_text": "purge", "csrf_token": token}
        if hard:
            data["hard"] = "true"
        return client.post(f"/jobs/{job_id}/purge", data=data)

    def test_unpurged_job_shows_no_purge_status(self, env):
        client = env["client"]
        _login(client, "admin1")
        resp = client.get(f"/jobs/{env['clean_job']}")
        assert 'class="pill purged-hard"' not in resp.text
        assert 'class="pill purged-soft"' not in resp.text

    def test_soft_purge_shows_content_purged_status_but_pdf_still_works(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)
        self._purge(client, env["sensitive_job"], token)

        resp = client.get(f"/jobs/{env['sensitive_job']}")
        assert "content purged" in resp.text.lower()
        assert "purged &middot; hard" not in resp.text
        assert f"/jobs/{env['sensitive_job']}/pdf" in resp.text  # preview/download still linked
        assert client.get(f"/jobs/{env['sensitive_job']}/pdf").status_code == 200

    def test_hard_purge_shows_purged_status_and_disables_pdf_links(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)
        self._purge(client, env["sensitive_job"], token, hard=True)

        resp = client.get(f"/jobs/{env['sensitive_job']}")
        assert "purged" in resp.text.lower()
        assert "hard-purged" in resp.text.lower()
        assert f'href="/jobs/{env["sensitive_job"]}/pdf"' not in resp.text
        assert f'href="/jobs/{env["sensitive_job"]}/pdf/download"' not in resp.text
        assert client.get(f"/jobs/{env['sensitive_job']}/pdf").status_code == 404


class TestPurgedJobsDisableFurtherActions:
    def _purge(self, client, job_id, token, hard=False):
        data = {"reason": "test purge", "confirm_text": "purge", "csrf_token": token}
        if hard:
            data["hard"] = "true"
        return client.post(f"/jobs/{job_id}/purge", data=data)

    def test_hard_purged_job_offers_neither_purge_nor_reprocess(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)
        self._purge(client, env["sensitive_job"], token, hard=True)

        resp = client.get(f"/jobs/{env['sensitive_job']}")
        assert "nothing left to purge" in resp.text
        assert "can't reprocess" in resp.text
        assert "Purge content" not in resp.text
        assert 'value="preview"' not in resp.text

    def test_soft_purged_job_still_offers_a_hard_purge_and_extract_reprocess(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)
        self._purge(client, env["sensitive_job"], token)

        resp = client.get(f"/jobs/{env['sensitive_job']}")
        assert "Purge content" in resp.text  # the PDF is still there to delete
        assert "content already purged" in resp.text
        assert 'value="preview"' in resp.text
        assert "rules</span> mode has nothing to re-scan" in resp.text


class TestDocumentMetadataScreen:
    def test_allowlisted_metadata_is_shown(self, env_with_metadata):
        client = env_with_metadata["client"]
        _login(client, "admin1")
        resp = client.get(f"/jobs/{env_with_metadata['job_id']}")
        assert "device_id" in resp.text
        assert "MFP-3F-04" in resp.text

    def test_empty_allowlist_says_why_nothing_was_kept(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get(f"/jobs/{env['clean_job']}")
        assert "source.metadata_fields" in resp.text
        assert "dropped at ingest" in resp.text


class TestReprocessAction:
    def test_investigator_can_preview(self, env):
        client = env["client"]
        _login(client, "inv1")
        page = client.get(f"/jobs/{env['clean_job']}")
        token = _csrf_token(page.text)
        resp = client.post(
            f"/jobs/{env['clean_job']}/reprocess",
            data={"mode": "rules", "reprocess_action": "preview", "csrf_token": token},
        )
        assert resp.status_code == 200
        assert "Preview" in resp.text
        assert "unchanged" in resp.text  # same ruleset, same content -> no change

    def test_investigator_cannot_commit(self, env):
        client = env["client"]
        _login(client, "inv1")
        page = client.get(f"/jobs/{env['clean_job']}")
        token = _csrf_token(page.text)
        resp = client.post(
            f"/jobs/{env['clean_job']}/reprocess",
            data={"mode": "rules", "reprocess_action": "commit", "csrf_token": token},
        )
        assert resp.status_code == 403
        assert "jobs.reprocess.commit" in resp.text

    def test_dlp_admin_can_commit(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['clean_job']}")
        token = _csrf_token(page.text)
        resp = client.post(
            f"/jobs/{env['clean_job']}/reprocess",
            data={"mode": "rules", "reprocess_action": "commit", "csrf_token": token},
        )
        assert resp.status_code == 200
        assert "queued" in resp.text.lower()

        # The commit itself now runs in the background so the operator's
        # own request isn't the one waiting on it — wait for it here, then
        # check it really ran rather than anything this response shows.
        client.app.state.background.shutdown(wait=True)
        completed = [e for e in env["pipeline"].audit.events(limit=100) if e["event"] == "reprocess.completed"]
        assert len(completed) == 1

    def test_preview_writes_no_new_assessment(self, env):
        client = env["client"]
        _login(client, "inv1")
        page = client.get(f"/jobs/{env['clean_job']}")
        token = _csrf_token(page.text)
        client.post(
            f"/jobs/{env['clean_job']}/reprocess",
            data={"mode": "rules", "reprocess_action": "preview", "csrf_token": token},
        )
        rows = latest_index_rows(env["pipeline"].index_root, job_ids=[env["clean_job"]])
        assert rows[0]["assessment_seq"] == 1

    def test_viewer_cannot_preview_or_commit(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.post(
            f"/jobs/{env['clean_job']}/reprocess",
            data={"mode": "rules", "reprocess_action": "preview", "csrf_token": "irrelevant"},
        )
        assert resp.status_code == 403


class TestSearchScreen:
    def test_investigator_can_search_and_finds_the_sensitive_job(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get("/search", params={"q": "4111"})
        assert resp.status_code == 200
        assert env["sensitive_job"][:12] in resp.text

    def test_no_query_renders_the_empty_form_without_erroring(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get("/search")
        assert resp.status_code == 200
        assert "No results" not in resp.text  # no search ran at all yet

    def test_no_match_shows_no_results(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get("/search", params={"q": "nonexistent_term_xyz"})
        assert "No results" in resp.text

    def test_viewer_cannot_search(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/search", params={"q": "anything"})
        assert resp.status_code == 403

    def test_auditor_cannot_search(self, env):
        # Auditor holds dlp.hits.read but not jobs.text.read — a search
        # snippet is a slice of raw full_text, a different boundary.
        client = env["client"]
        _login(client, "aud1")
        resp = client.get("/search", params={"q": "anything"})
        assert resp.status_code == 403

    def test_dlp_admin_can_search(self, env):
        client = env["client"]
        _login(client, "admin1")
        resp = client.get("/search", params={"q": "4111"})
        assert resp.status_code == 200

    def test_search_is_audited(self, env):
        client = env["client"]
        _login(client, "inv1")
        client.get("/search", params={"q": "4111", "severity": "HIGH"})

        events = []
        for path in (env["pipeline"].audit.root).glob("dt=*/events.jsonl"):
            import json

            events += [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]
        search_events = [e for e in events if e["event"] == "ui.search"]
        assert len(search_events) == 1
        assert search_events[0]["actor"] == "inv1"
        # The default preserves correlation without permanently copying a
        # potentially sensitive search term into the audit chain.
        assert "query" not in search_events[0]
        assert len(search_events[0]["terms_hmac"]) == 32
        assert search_events[0]["severity"] == "HIGH"

    def test_invalid_severity_shows_an_inline_error_not_a_500(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get("/search", params={"q": "test", "severity": "NOT_REAL"})
        assert resp.status_code == 200
        assert "unknown severity" in resp.text.lower()


class TestRulesScreen:
    def test_every_role_can_read_rules(self, env):
        for username in ("viewer1", "inv1", "aud1", "admin1"):
            client = TestClient(env["client"].app)
            _login(client, username)
            resp = client.get("/rules")
            assert resp.status_code == 200, username

    def test_default_ruleset_rules_are_listed(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/rules")
        assert "pan.generic" in resp.text
        assert "mark.banner_header" in resp.text

    def test_ruleset_version_is_shown(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/rules")
        assert env["pipeline"].ruleset_version in resp.text

    def test_disabled_default_rule_is_not_listed(self, env):
        # mark.itar ships enabled: false in builtin:default.yaml.
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/rules")
        assert "mark.itar" not in resp.text

    def test_rule_pattern_is_shown(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/rules")
        # pan.generic's actual regex, not just its name/id.
        assert r"\d[ -]?" in resp.text

    def test_no_literal_html_entity_text_leaks_into_the_page(self, env):
        # A bug: a Python string default of "&mdash;" got double-escaped
        # by Jinja's autoescaping into the literal text "&mdash;" on the
        # page, instead of rendering as an em dash.
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/rules")
        assert "&mdash;" not in resp.text
        assert "&amp;mdash;" not in resp.text


class TestOverviewScreen:
    def test_every_role_can_see_the_overview(self, env):
        for username in ("viewer1", "inv1", "aud1", "admin1"):
            client = TestClient(env["client"].app)
            _login(client, username)
            resp = client.get("/")
            assert resp.status_code == 200, username

    def test_stats_reflect_real_data(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/")
        # 2 jobs seeded: one clean (archive), one quarantined.
        assert resp.status_code == 200
        # Both stat tiles render with real counts, not placeholders.
        assert ">2<" in resp.text  # total jobs indexed
        assert ">1<" in resp.text  # quarantined count

    def test_auditor_sees_the_audit_chain_card(self, env):
        client = env["client"]
        _login(client, "aud1")
        resp = client.get("/")
        assert "Audit chain" in resp.text

    def test_dlp_admin_also_sees_the_audit_chain_card(self, env):
        # DLP Admin is a superuser role and holds audit.verify too.
        client = env["client"]
        _login(client, "admin1")
        resp = client.get("/")
        assert "Audit chain" in resp.text

    def test_recent_jobs_are_listed(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/")
        assert env["clean_job"][:12] in resp.text
        assert env["sensitive_job"][:12] in resp.text


class TestAuditScreen:
    def test_auditor_can_view_the_audit_trail(self, env):
        client = env["client"]
        _login(client, "aud1")
        resp = client.get("/audit")
        assert resp.status_code == 200
        assert "job.completed" in resp.text

    def test_viewer_cannot_view_the_audit_trail(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/audit")
        assert resp.status_code == 403

    def test_dlp_admin_can_also_view_the_audit_trail(self, env):
        # DLP Admin is a superuser role by default (see rbac.py).
        client = env["client"]
        _login(client, "admin1")
        resp = client.get("/audit")
        assert resp.status_code == 200

    def test_investigator_cannot_view_the_audit_trail(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get("/audit")
        assert resp.status_code == 403

    def test_events_link_to_their_job(self, env):
        client = env["client"]
        _login(client, "aud1")
        resp = client.get("/audit")
        assert f"/jobs/{env['sensitive_job']}" in resp.text

    def test_date_filter_narrows_results(self, env):
        client = env["client"]
        _login(client, "aud1")
        from datetime import date, timedelta

        tomorrow = (date.today() + timedelta(days=1)).isoformat()
        resp = client.get("/audit", params={"start": tomorrow})
        assert "No events in this range" in resp.text

    def test_verify_control_present_for_auditor(self, env):
        client = env["client"]
        _login(client, "aud1")
        resp = client.get("/audit")
        assert "Verify chain" in resp.text

    def test_verify_action_reports_chain_intact(self, env):
        client = env["client"]
        _login(client, "aud1")
        page = client.get("/audit")
        token = _csrf_token(page.text)

        resp = client.post("/audit/verify", data={"csrf_token": token})
        assert resp.status_code == 200
        assert "Chain intact" in resp.text

    def test_verify_action_surfaces_redactions_alongside_intact(self, env):
        """The console must not answer "Chain intact." and stop when
        content has been deliberately emptied out of it — that reads as
        "nothing was ever removed", which is a different claim."""
        audit = env["pipeline"].audit
        seq = audit.events(limit=1)[0]["seq"]
        audit.redact(seq, ["disposition"], reason="erasure request 41", actor="admin")

        client = env["client"]
        _login(client, "aud1")
        page = client.get("/audit")
        resp = client.post("/audit/verify", data={"csrf_token": _csrf_token(page.text)})

        assert "Chain intact" in resp.text
        assert "1 event(s) redacted" in resp.text
        assert f"seq {seq}" in resp.text

    def test_verify_action_requires_csrf(self, env):
        client = env["client"]
        _login(client, "aud1")
        resp = client.post("/audit/verify", data={"csrf_token": "wrong"})
        assert resp.status_code == 403

    def test_non_auditor_cannot_verify(self, env):
        client = env["client"]
        _login(client, "admin1")
        resp = client.post("/audit/verify", data={"csrf_token": "irrelevant"})
        assert resp.status_code == 403


class TestAccessScreen:
    def test_dlp_admin_can_view_access(self, env):
        client = env["client"]
        _login(client, "admin1")
        resp = client.get("/access")
        assert resp.status_code == 200
        assert "viewer1" in resp.text
        assert "admin1" in resp.text

    def test_viewer_cannot_view_access(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/access")
        assert resp.status_code == 403

    def test_investigator_cannot_view_access(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get("/access")
        assert resp.status_code == 403

    def test_auditor_cannot_view_access(self, env):
        # Separation of duties: Auditor watches, DLP Admin manages
        # access — neither role does both.
        client = env["client"]
        _login(client, "aud1")
        resp = client.get("/access")
        assert resp.status_code == 403

    def test_roles_are_shown_for_each_user(self, env):
        client = env["client"]
        _login(client, "admin1")
        resp = client.get("/access")
        assert "investigator" in resp.text
        assert "auditor" in resp.text
        assert "dlp_admin" in resp.text

    def test_no_password_hash_appears_anywhere_in_the_page(self, env):
        client = env["client"]
        _login(client, "admin1")
        resp = client.get("/access")
        assert "$argon2id$" not in resp.text


class TestNavVisibility:
    """The nav only offers links a role can actually use — so following
    it never leads to a 403 in the first place. Direct navigation to a
    hidden URL is covered separately in TestForbiddenPage.
    """

    def test_viewer_nav_hides_search_audit_and_access(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/jobs")
        assert 'href="/search"' not in resp.text
        assert 'href="/audit"' not in resp.text
        assert 'href="/access"' not in resp.text
        assert 'href="/rules"' in resp.text  # rules.read is granted to everyone

    def test_investigator_nav_shows_search_hides_audit_and_access(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get("/jobs")
        assert 'href="/search"' in resp.text
        assert 'href="/audit"' not in resp.text
        assert 'href="/access"' not in resp.text

    def test_auditor_nav_shows_audit_hides_search_and_access(self, env):
        client = env["client"]
        _login(client, "aud1")
        resp = client.get("/jobs")
        assert 'href="/audit"' in resp.text
        assert 'href="/search"' not in resp.text
        assert 'href="/access"' not in resp.text

    def test_dlp_admin_nav_shows_everything(self, env):
        client = env["client"]
        _login(client, "admin1")
        resp = client.get("/jobs")
        assert 'href="/search"' in resp.text
        assert 'href="/audit"' in resp.text
        assert 'href="/access"' in resp.text


class TestForbiddenPage:
    """A hidden nav link doesn't stop a bookmarked or typed URL — that
    still needs to land somewhere better than a bare unstyled error.
    """

    def test_403_renders_a_styled_page_not_a_bare_error_string(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/audit")
        assert resp.status_code == 403
        assert "<html" in resp.text.lower()  # a real page, not a raw string
        assert "DLPDuck" in resp.text  # still has the app chrome/nav
        assert "Not available to your role" in resp.text

    def test_403_page_explains_which_permission_was_missing(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/audit")
        assert "audit.read" in resp.text

    def test_403_page_shows_the_current_user_and_their_roles(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/audit")
        assert "viewer1" in resp.text
        assert "viewer" in resp.text

    def test_403_page_still_offers_navigation_back_out(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/audit")
        assert 'href="/jobs"' in resp.text

    def test_404_also_renders_the_styled_error_page(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/jobs/does-not-exist")
        assert resp.status_code == 404
        assert "Not found" in resp.text
        assert "<html" in resp.text.lower()


class TestRevealIsVerifiedAgainstTheRecordedMask:
    """Reveal re-derives cleartext from a stored position rather than from
    a stored value. That means a stale position must not be allowed to
    display some unrelated slice of the document under an audit entry that
    says a legitimate reveal happened.
    """

    def _reveal(self, client, job_id):
        page = client.get(f"/jobs/{job_id}")
        token = _csrf_token(page.text)
        return client.post(
            f"/jobs/{job_id}/reveal", data={"hit_index": 0, "csrf_token": token}
        )

    def test_a_document_scope_hit_reveals_its_actual_value(self, tmp_path, monkeypatch):
        # This is what used to come back empty: document-scope offsets were
        # document-global while reveal sliced the line.
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        monkeypatch.setenv("DLPDUCK_SESSION_SECRET", "test-session-secret-not-for-production")
        src = tmp_path / "drops"
        src.mkdir()
        rules = [
            {
                "id": "doc.secret", "name": "Doc-scope secret",
                "pattern": r"SECRET-\d+", "scope": "document",
                "severity": "HIGH", "action": "quarantine",
            }
        ]
        config = Config.model_validate(
            {
                "source": {"name": "t", "path": str(src), "metadata_format": "none"},
                "destination": {
                    "archive": str(tmp_path / "archive"),
                    "quarantine": str(tmp_path / "quarantine"),
                    "work_dir": str(tmp_path / "work"),
                },
                "dlp": {"rules": rules},
                "console": {
                    "auth": {
                        "users": [
                            {
                                "username": "admin1",
                                "password_hash": PASSWORD_HASH,
                                "role": "dlp_admin",
                            }
                        ]
                    }
                },
            }
        )
        pipeline = Pipeline(config)
        pdf = _pdf(
            tmp_path / "doc.pdf",
            ["filler line one", "filler line two", "ACCOUNT SECRET-9876 here"],
        )
        ctx = pipeline.run_job(pdf, None, config.destination.work_dir / "_processing")
        assert ctx.hits, "the document-scope rule should have matched"

        client = TestClient(create_app(config, pipeline))
        _login(client, "admin1")
        resp = self._reveal(client, ctx.job_id)

        assert resp.status_code == 200
        assert "SECRET-9876" in resp.text

    def test_content_that_no_longer_matches_the_recorded_hit_reveals_nothing(self, env):
        """If the content store is rewritten so the stored offsets point
        somewhere else, reveal must decline rather than show that slice."""
        client = env["client"]
        _login(client, "admin1")
        job_id = env["sensitive_job"]

        # Rewrite the content store row with different text at the same
        # line number, as an extract-mode reprocess against changed input
        # would. The offsets survive; the text under them does not.
        from dlpduck.content import write_content_row
        from dlpduck.types import DocumentText, TextLine

        replacement = DocumentText(page_count=1)
        replacement.add_line(
            TextLine(
                line_number=0, page_number=1, line_on_page=0, lines_on_page=1,
                text="completely different content now occupies this line",
                source="native",
            )
        )
        row_ctx = type("Ctx", (), {})()
        row_ctx.job_id = job_id
        row_ctx.text = replacement
        row_ctx.received_at = latest_index_rows(env["pipeline"].index_root, job_ids=[job_id])[0][
            "received_at"
        ]
        for stale in env["pipeline"].content_root.glob(f"dt=*/{job_id}.parquet"):
            stale.unlink()
        write_content_row(env["pipeline"].content_root, row_ctx)

        resp = self._reveal(client, job_id)

        assert resp.status_code == 200
        assert "unable to re-derive" in resp.text
        assert "completely different content" not in resp.text


class TestMalformedDateFiltersAreHandled:
    """Date filters arrive as raw query strings. A bookmarked, truncated or
    hand-edited URL is ordinary traffic, and every one of these used to
    reach `date.fromisoformat` unguarded and return a 500 — from any role,
    including viewer.
    """

    @pytest.mark.parametrize("bad", ["garbage", "13-45-99", "2026-02-30", "2026-1", "../etc"])
    def test_jobs_rejects_a_bad_date_with_400_not_500(self, env, bad):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/jobs", params={"start": bad})
        assert resp.status_code == 400
        assert "YYYY-MM-DD" in resp.text

    def test_audit_rejects_a_bad_date_with_400_not_500(self, env):
        client = env["client"]
        _login(client, "admin1")
        resp = client.get("/audit", params={"end": "not-a-date"})
        assert resp.status_code == 400

    def test_search_reports_a_bad_date_inline_and_still_renders(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get("/search", params={"q": "memo", "start": "nonsense"})
        assert resp.status_code == 200
        assert "YYYY-MM-DD" in resp.text
        assert 'name="q"' in resp.text  # the form is still there to correct

    def test_valid_dates_are_unaffected(self, env):
        client = env["client"]
        _login(client, "viewer1")
        assert client.get("/jobs", params={"start": "2026-01-01"}).status_code == 200


class TestPendingReleaseStillCountsAsQuarantined:
    """A de-escalation records the new disposition immediately but
    deliberately leaves the PDF in quarantine until someone with
    quarantine.release approves the move. Gating PDF access on disposition
    alone handed that window to Investigator — the exact thing
    release_pending exists to prevent.
    """

    @pytest.fixture
    def deescalated(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        monkeypatch.setenv("DLPDUCK_SESSION_SECRET", "test-session-secret-not-for-production")
        src = tmp_path / "drops"
        src.mkdir()

        def _cfg(rules):
            return Config.model_validate(
                {
                    "source": {"name": "t", "path": str(src), "metadata_format": "none"},
                    "destination": {
                        "archive": str(tmp_path / "archive"),
                        "quarantine": str(tmp_path / "quarantine"),
                        "work_dir": str(tmp_path / "work"),
                    },
                    "dlp": {"rules": rules},
                    "console": {
                        "auth": {
                            "users": [
                                {"username": "inv1", "password_hash": PASSWORD_HASH,
                                 "role": "investigator"},
                                {"username": "admin1", "password_hash": PASSWORD_HASH,
                                 "role": "dlp_admin"},
                            ]
                        }
                    },
                }
            )

        # Quarantined under the shipped ruleset...
        first = _cfg([{"include": str(DEFAULT_RULES_PATH)}])
        ctx = Pipeline(first).run_job(
            _pdf(tmp_path / "card.pdf", ["Card 4111 1111 1111 1111 on file"]),
            None,
            first.destination.work_dir / "_processing",
        )
        assert ctx.disposition == "quarantine"

        # ...then the rule is retired, so a reprocess de-escalates it.
        second = _cfg([{"id": "x.none", "name": "Nothing", "pattern": r"zzzznomatch"}])
        pipeline = Pipeline(second)
        Reprocessor(pipeline).commit(job_ids=[ctx.job_id], mode="rules")
        row = latest_index_rows(pipeline.index_root, job_ids=[ctx.job_id])[0]
        assert row["disposition"] == "archive" and row["release_pending"] is True

        return {"config": second, "pipeline": pipeline, "job_id": ctx.job_id, "row": row}

    def test_the_pdf_is_still_physically_in_quarantine(self, deescalated):
        assert "quarantine" in deescalated["row"]["archive_path"]
        assert Path(deescalated["row"]["archive_path"]).is_file()

    def test_investigator_cannot_download_it_while_release_is_pending(self, deescalated):
        client = TestClient(create_app(deescalated["config"], deescalated["pipeline"]))
        _login(client, "inv1")
        job_id = deescalated["job_id"]

        assert client.get(f"/jobs/{job_id}/pdf").status_code == 403
        assert client.get(f"/jobs/{job_id}/pdf/download").status_code == 403

    def test_the_job_page_names_the_stricter_permission(self, deescalated):
        client = TestClient(create_app(deescalated["config"], deescalated["pipeline"]))
        _login(client, "inv1")
        resp = client.get(f"/jobs/{deescalated['job_id']}")
        assert "jobs.pdf.read.quarantined" in resp.text

    def test_dlp_admin_can_still_reach_it(self, deescalated):
        client = TestClient(create_app(deescalated["config"], deescalated["pipeline"]))
        _login(client, "admin1")
        assert client.get(f"/jobs/{deescalated['job_id']}/pdf").status_code == 200

    def test_after_a_real_release_the_investigator_may_read_it(self, deescalated):
        # The human gate is what opens access — not the reassessment.
        Reprocessor(deescalated["pipeline"]).release(
            deescalated["job_id"], reason="reviewed and cleared", actor="admin1"
        )
        client = TestClient(create_app(deescalated["config"], deescalated["pipeline"]))
        _login(client, "inv1")
        assert client.get(f"/jobs/{deescalated['job_id']}/pdf").status_code == 200

    def test_a_file_sitting_under_quarantine_is_gated_whatever_the_row_says(self, env):
        """Defence in depth: if a crash leaves the row and the file
        disagreeing, the file's actual location decides."""
        client = env["client"]
        job_id = env["clean_job"]  # archived, disposition == "archive"
        row = latest_index_rows(env["pipeline"].index_root, job_ids=[job_id])[0]
        moved = env["config"].destination.quarantine / "dt=2026-01-01"
        moved.mkdir(parents=True, exist_ok=True)
        shutil.move(row["archive_path"], str(moved / f"{job_id}.pdf"))

        import pyarrow.parquet as pq

        [index_file] = env["pipeline"].index_root.glob(f"dt=*/{job_id}_*.parquet")
        table = pq.read_table(index_file).to_pylist()
        table[0]["archive_path"] = str(moved / f"{job_id}.pdf")
        import pyarrow as pa

        from dlpduck.schema import INDEX_SCHEMA

        pq.write_table(pa.Table.from_pylist(table, schema=INDEX_SCHEMA), index_file)

        _login(client, "inv1")
        assert client.get(f"/jobs/{job_id}/pdf").status_code == 403


class TestQuarantinedTextIsNotLeakedBySearch:
    """A search snippet is a raw slice of the document, so it belongs
    behind the same gate as opening that document. Otherwise a quarantined
    document's PDF was admin-only while its text was searchable by any
    investigator — and because the snippet is centred on the match,
    searching a word near a hit returned the very value that the
    quarantine, the masking, and the admin-only dlp.reveal exist to
    protect. That made the reveal gate optional.
    """

    def test_an_investigator_gets_the_result_but_not_the_excerpt(self, env):
        client = env["client"]
        _login(client, "inv1")
        resp = client.get("/search", params={"q": "Card"})

        assert resp.status_code == 200
        assert env["sensitive_job"][:12] in resp.text  # still findable
        assert "4111 1111 1111 1111" not in resp.text  # but not readable
        assert "jobs.pdf.read.quarantined" in resp.text  # and told why

    def test_a_dlp_admin_still_sees_the_excerpt(self, env):
        client = env["client"]
        _login(client, "admin1")
        resp = client.get("/search", params={"q": "Card"})

        assert resp.status_code == 200
        assert "4111" in resp.text

    def test_archived_documents_are_unaffected(self, env):
        """jobs.text.read means what it says for a document the holder
        could open anyway — only contained documents are withheld."""
        client = env["client"]
        _login(client, "inv1")
        resp = client.get("/search", params={"q": "office party"})

        assert resp.status_code == 200
        assert env["clean_job"][:12] in resp.text
        assert "office party" in resp.text  # the excerpt is shown

    def test_the_snippet_matches_what_the_pdf_gate_would_allow(self, env):
        """One rule decides both: if the PDF is denied, so is the excerpt."""
        client = env["client"]
        _login(client, "inv1")
        pdf_denied = client.get(f"/jobs/{env['sensitive_job']}/pdf").status_code == 403
        resp = client.get("/search", params={"q": "Card"})

        assert pdf_denied
        assert "4111 1111 1111 1111" not in resp.text


class TestConcurrentReassessmentIsRefusedInTheConsole:
    """The library refuses to overwrite an assessment someone else wrote
    (test_reprocess); this is the console actually handling that refusal
    rather than turning it into a 500."""

    def test_a_losing_writer_is_told_rather_than_getting_a_500(self, env, monkeypatch):
        from dlpduck.index import AssessmentExists

        client = env["client"]
        _login(client, "admin1")
        job_id = env["sensitive_job"]
        page = client.get(f"/jobs/{job_id}")
        token = _csrf_token(page.text)

        # Stand in for the race the exclusive write exists to catch: by the
        # time this commit reaches the index, someone else has already
        # recorded that sequence number.
        def _someone_got_there_first(*_args, **_kwargs):
            raise AssessmentExists(Path("index/dt=2026-01-01/job_0002.parquet"))

        monkeypatch.setattr(Reprocessor, "commit", _someone_got_there_first)

        resp = client.post(
            f"/jobs/{job_id}/reprocess",
            data={"mode": "rules", "reprocess_action": "commit", "csrf_token": token},
        )

        assert resp.status_code == 200  # not a 500
        assert "queued" in resp.text.lower()

        # The commit (and so the race) now happens in the background —
        # wait for it, then check the conflict was recorded rather than
        # silently dropped. The job's own audit timeline is where an
        # operator would actually see this on a later visit.
        client.app.state.background.shutdown(wait=True)
        events = env["pipeline"].audit.events_for_job(job_id)
        [conflict] = [e for e in events if e["event"] == "reprocess.conflict"]
        assert conflict["actor"] == "admin1"

    def test_a_preview_is_unaffected_by_the_guard(self, env):
        client = env["client"]
        _login(client, "admin1")
        page = client.get(f"/jobs/{env['sensitive_job']}")
        token = _csrf_token(page.text)

        resp = client.post(
            f"/jobs/{env['sensitive_job']}/reprocess",
            data={"mode": "rules", "reprocess_action": "preview", "csrf_token": token},
        )

        assert resp.status_code == 200
        assert "reassessed by someone else" not in resp.text


class TestAuthenticationIsAuditedAndThrottled:
    """Who got in, who failed to, and who was stopped from trying. The
    trail records everything a session does with a document but, until
    these events, nothing about how the session came to exist.
    """

    def _auth_events(self, env, kind: str) -> list[dict]:
        return [
            e for e in env["pipeline"].audit.events(limit=200)
            if e["event"] == kind
        ]

    def test_a_successful_login_is_recorded_with_the_roles_granted(self, env):
        _login(env["client"], "aud1")

        [event] = self._auth_events(env, "auth.succeeded")
        assert event["actor"] == "aud1"
        assert event["method"] == "local"
        assert event["roles"] == ["auditor"]

    def test_a_failed_login_is_recorded(self, env):
        env["client"].post("/login", data={"username": "aud1", "password": "wrong"})

        [event] = self._auth_events(env, "auth.failed")
        assert event["actor"] == "aud1"
        assert event["method"] == "local"

    def test_a_failed_login_never_records_the_password_tried(self, env):
        """A near-miss password is somebody's real password somewhere
        else, and the trail is readable by every Auditor."""
        env["client"].post(
            "/login", data={"username": "aud1", "password": "hunter2-almost-right"}
        )

        [event] = self._auth_events(env, "auth.failed")
        assert "hunter2" not in json.dumps(event)

    def test_logging_out_is_recorded(self, env):
        client = env["client"]
        _login(client, "aud1")
        client.post("/logout")

        [event] = self._auth_events(env, "auth.logout")
        assert event["actor"] == "aud1"

    def test_repeated_failures_are_refused_before_any_password_check(self, env):
        """The ceiling has to come before argon2, not after: the cost of
        verifying is exactly what a flood of unauthenticated POSTs is
        trying to spend."""
        client = env["client"]
        limit = env["config"].console.auth.max_failed_logins
        for _ in range(limit):
            client.post("/login", data={"username": "aud1", "password": "wrong"})

        resp = client.post("/login", data={"username": "aud1", "password": "wrong"})

        assert resp.status_code == 429
        assert len(self._auth_events(env, "auth.throttled")) == 1

    def test_the_lockout_message_does_not_confirm_the_account_exists(self, env):
        """"That account is locked" would hand an anonymous caller the
        username enumeration the equal-time hashing path avoids."""
        client = env["client"]
        for _ in range(env["config"].console.auth.max_failed_logins):
            client.post("/login", data={"username": "aud1", "password": "wrong"})

        locked_real = client.post("/login", data={"username": "aud1", "password": "x"})
        locked_fake = client.post("/login", data={"username": "nobody", "password": "x"})

        assert "aud1" not in locked_real.text
        assert locked_real.status_code == locked_fake.status_code

    def test_a_correct_password_still_works_below_the_limit(self, env):
        client = env["client"]
        for _ in range(env["config"].console.auth.max_failed_logins - 1):
            client.post("/login", data={"username": "aud1", "password": "wrong"})

        resp = client.post(
            "/login", data={"username": "aud1", "password": PASSWORD}, follow_redirects=False
        )

        assert resp.status_code == 303
        assert self._auth_events(env, "auth.succeeded")


class TestSecurityHeaders:
    """The console renders text lifted out of untrusted documents and
    serves the untrusted documents themselves. Autoescaping and confined
    paths are what stop the mistake; these headers are what stop the
    mistake becoming an account takeover.
    """

    def test_pages_refuse_to_be_framed(self, env):
        """Purge is one click behind a confirmation, which is exactly what
        clickjacking turns into an irreversible deletion."""
        client = env["client"]
        _login(client, "admin1")
        resp = client.get(f"/jobs/{env['sensitive_job']}")

        assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
        assert resp.headers["x-frame-options"] == "DENY"

    def test_content_types_are_never_sniffed(self, env):
        client = env["client"]
        _login(client, "admin1")
        resp = client.get(f"/jobs/{env['sensitive_job']}/pdf")

        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["content-type"] == "application/pdf"

    def test_job_ids_do_not_leak_through_the_referer_header(self, env):
        client = env["client"]
        _login(client, "viewer1")
        resp = client.get("/jobs")

        assert resp.headers["referrer-policy"] == "no-referrer"

    def test_the_login_page_carries_the_headers_too(self, env):
        """Unauthenticated pages are the ones an attacker can reach."""
        resp = env["client"].get("/login")
        assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]

    def test_the_policy_permits_no_off_origin_loads(self, env):
        """A DLP console must render identically with no route to the
        internet, and must not tell a third party who is looking at it."""
        client = env["client"]
        _login(client, "viewer1")
        csp = client.get("/jobs").headers["content-security-policy"]

        for directive in csp.split(";"):
            assert "http://" not in directive and "https://" not in directive, directive

    def test_no_template_reaches_off_origin_for_an_asset(self, env):
        """The stylesheet, fonts and images all have to be same-origin or
        the CSP above silently breaks the page in an air-gapped install."""
        client = env["client"]
        _login(client, "admin1")
        for path in ("/", "/jobs", f"/jobs/{env['sensitive_job']}", "/search", "/rules"):
            html = client.get(path).text
            assert "https://fonts." not in html, path
            assert not re.search(r'(?:href|src)="https?://', html), path

    def test_every_declared_font_face_is_actually_on_disk(self, env):
        """A missing woff2 fails silently — the browser just falls back —
        so nothing else in the suite would notice the design degrading."""
        client = env["client"]
        css = client.get("/static/fonts.css")
        assert css.status_code == 200

        faces = re.findall(r"url\('([^']+)'\)", css.text)
        assert faces, "no @font-face src found — the stylesheet is empty"
        missing = [url for url in faces if client.get(url).status_code != 200]
        assert missing == []


HOSTILE_VALUES = [
    "", " ", "café", "💥", "-1", "0", "99999999999999999999", "1e400", "NaN",
    "../../etc/passwd", "%00", "*", "'", '"', "\\", "2026-13-45", "not-a-date",
    "0" * 300, "<script>alert(1)</script>", "%25%25", "\t\n",
]


class TestMalformedInputIsRefusedNotCrashed:
    """Every console parameter, given values a browser would never send.

    A 5xx here is always a bug: the answer to malformed input is a
    refusal, and an unhandled exception on a security check is the worst
    version of it — `secrets.compare_digest` raising TypeError on a
    non-ASCII CSRF token turned the CSRF guard itself into a 500, where
    the only correct answer is "no".
    """

    def _probe(self, client, method, url, **kwargs):
        try:
            resp = client.request(method, url, follow_redirects=False, **kwargs)
        except Exception as exc:
            # The HTTP client refused to build the request at all (a NUL
            # in a URL, say). A real client could not send it either.
            if exc.__class__.__name__ in ("InvalidURL", "LocalProtocolError"):
                return None
            raise
        assert resp.status_code < 500, (
            f"{method} {url} {kwargs} returned {resp.status_code}"
        )
        return resp

    def test_no_parameter_can_produce_a_server_error(self, env):
        client = env["client"]
        _login(client, "admin1")
        job = env["sensitive_job"]
        token = _csrf_token(client.get(f"/jobs/{job}").text)

        for value in HOSTILE_VALUES:
            self._probe(client, "GET", "/jobs", params={"disposition": value})
            self._probe(client, "GET", "/jobs", params={"start": value, "end": value})
            self._probe(client, "GET", "/search", params={"q": value})
            self._probe(client, "GET", "/search", params={"q": "memo", "severity": value})
            self._probe(
                client, "GET", "/search", params={"q": "memo", "start": value, "end": value}
            )
            self._probe(client, "GET", "/audit", params={"start": value, "end": value})
            self._probe(client, "GET", f"/jobs/{value}")
            self._probe(client, "GET", f"/jobs/{value}/pdf")
            self._probe(client, "GET", f"/jobs/{value}/pdf/download")
            self._probe(
                client, "POST", f"/jobs/{job}/reveal",
                data={"hit_index": value, "csrf_token": token},
            )
            self._probe(
                client, "POST", f"/jobs/{job}/purge",
                data={"reason": value, "confirm_text": value, "csrf_token": token},
            )
            self._probe(
                client, "POST", f"/jobs/{job}/reprocess",
                data={"mode": value, "reprocess_action": value, "csrf_token": token},
            )
            self._probe(
                client, "POST", f"/jobs/{job}/release",
                data={"reason": value, "csrf_token": token},
            )

    def test_a_non_ascii_csrf_token_is_a_refusal_not_a_crash(self, env):
        """The specific hole this class was written for: compare_digest
        raises TypeError on any non-ASCII str, and the submitted token is
        attacker-controlled."""
        client = env["client"]
        _login(client, "aud1")
        client.get("/audit")  # issue a token, so the check gets past "missing"

        for token in ("café", "ééé", "💥", "tokén"):
            resp = client.post("/audit/verify", data={"csrf_token": token})
            assert resp.status_code == 403, f"{token!r} gave {resp.status_code}"

    def test_unauthenticated_hostile_input_is_refused_too(self, env):
        """The endpoints an attacker can actually reach without a session."""
        client = env["client"]
        for value in HOSTILE_VALUES:
            self._probe(
                client, "POST", "/login", data={"username": value, "password": value}
            )
            self._probe(client, "GET", "/login", params={"auth": value})
            self._probe(client, "GET", f"/jobs/{value}")
