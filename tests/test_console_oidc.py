"""§10.4: OIDC is the primary auth path, local accounts are the
break-glass fallback. The token exchange itself (authlib talking to a
real IdP) is proven against an actual running Keycloak as a live smoke
test, not here — these tests stub `authorize_access_token` at the
boundary authlib provides for exactly this, and check OUR logic: role
mapping, noise-role filtering, denial when no recognised role comes back,
and that the local fallback still works when OIDC is also configured.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dlpduck.config import Config
from dlpduck.console.app import create_app
from dlpduck.console.auth import hash_password
from dlpduck.pipeline import Pipeline

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"
PASSWORD = "correct horse battery staple"
PASSWORD_HASH = hash_password(PASSWORD)
LOCAL_PASSWORD_HASH = hash_password("x")


def _base_config(tmp_path: Path, auth: dict) -> dict:
    src = tmp_path / "drops"
    src.mkdir(exist_ok=True)
    return {
        "source": {"name": "test", "path": str(src), "metadata_format": "none"},
        "destination": {
            "archive": str(tmp_path / "archive"),
            "quarantine": str(tmp_path / "quarantine"),
            "work_dir": str(tmp_path / "work"),
        },
        "extraction": {"isolate_worker": False, "native_min_chars": 0},
        "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
        "console": {"auth": auth},
    }


def _stub_token(claims: dict):
    async def _fake(request, **kwargs):
        return {"userinfo": claims}

    return _fake


def _stub_error(message: str):
    async def _fake(request, **kwargs):
        raise RuntimeError(message)

    return _fake


@pytest.fixture
def oidc_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
    monkeypatch.setenv("DLPDUCK_SESSION_SECRET", "test-session-secret-not-for-production")
    monkeypatch.setenv("DLPDUCK_OIDC_CLIENT_SECRET", "test-oidc-client-secret")
    config = Config.model_validate(
        _base_config(
            tmp_path,
            {
                "oidc": {
                    # Never actually contacted — registration is lazy and
                    # every test below stubs the token exchange itself.
                    "issuer": "http://127.0.0.1:1/unreachable-by-design",
                    "client_id": "dlpduck-console",
                },
                "users": [
                    {"username": "breakglass", "password_hash": PASSWORD_HASH, "role": "dlp_admin"}
                ],
            },
        )
    )
    pipeline = Pipeline(config)
    app = create_app(config, pipeline)
    client = TestClient(app)
    return {"client": client, "config": config, "pipeline": pipeline}


class TestLoginPageOffersSso:
    def test_login_redirects_straight_to_sso_when_oidc_configured(self, oidc_env):
        # SSO is the default way in — no menu to pick it off first.
        resp = oidc_env["client"].get("/login", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login/oidc"

    def test_auth_local_query_param_reaches_the_break_glass_form(self, oidc_env):
        resp = oidc_env["client"].get("/login?auth=local")
        assert resp.status_code == 200
        assert 'name="password"' in resp.text
        assert "Log in with SSO" in resp.text  # still offered as the primary path

    def test_logout_does_not_bounce_back_into_sso(self, oidc_env):
        # The IdP session usually outlives ours; auto-redirecting after a
        # logout would sign the user straight back in.
        client = oidc_env["client"]
        client.app.state.oauth.oidc.authorize_access_token = _stub_token(
            {"preferred_username": "sso.user", "roles": ["viewer"]}
        )
        client.get("/auth/callback")
        resp = client.post("/logout", follow_redirects=False)
        assert resp.headers["location"] == "/login?loggedout=1"
        landed = client.get("/login?loggedout=1", follow_redirects=False)
        assert landed.status_code == 200
        assert "signed out" in landed.text.lower()

    def test_sso_link_hidden_when_oidc_not_configured(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        monkeypatch.setenv("DLPDUCK_SESSION_SECRET", "test-session-secret-not-for-production")
        config = Config.model_validate(
            _base_config(tmp_path, {"users": [{"username": "a", "password_hash": LOCAL_PASSWORD_HASH, "role": "viewer"}]})
        )
        client = TestClient(create_app(config, Pipeline(config)))
        resp = client.get("/login")
        assert "Log in with SSO" not in resp.text

    def test_oidc_routes_do_not_exist_when_not_configured(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        monkeypatch.setenv("DLPDUCK_SESSION_SECRET", "test-session-secret-not-for-production")
        config = Config.model_validate(
            _base_config(tmp_path, {"users": [{"username": "a", "password_hash": LOCAL_PASSWORD_HASH, "role": "viewer"}]})
        )
        client = TestClient(create_app(config, Pipeline(config)))
        assert client.get("/login/oidc", follow_redirects=False).status_code == 404


class TestOidcCallback:
    def test_successful_callback_establishes_a_session(self, oidc_env):
        client = oidc_env["client"]
        client.app.state.oauth.oidc.authorize_access_token = _stub_token(
            {"preferred_username": "alice", "roles": ["dlp_admin"]}
        )
        resp = client.get("/auth/callback", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/jobs"

        # The session now genuinely carries dlp_admin — reaches an
        # admin-only screen without a second login.
        assert client.get("/access").status_code == 200

    def test_username_comes_from_preferred_username_claim(self, oidc_env):
        client = oidc_env["client"]
        client.app.state.oauth.oidc.authorize_access_token = _stub_token(
            {"preferred_username": "specific.user", "roles": ["viewer"]}
        )
        client.get("/auth/callback")
        resp = client.get("/jobs")
        assert "specific.user" in resp.text  # shown in the header once logged in

    def test_noise_roles_from_the_idp_are_filtered_out(self, oidc_env):
        # Keycloak (and most IdPs) include default/composite roles like
        # "offline_access" alongside the ones that actually matter —
        # these must not accidentally satisfy a permission check.
        client = oidc_env["client"]
        client.app.state.oauth.oidc.authorize_access_token = _stub_token(
            {
                "preferred_username": "alice",
                "roles": ["default-roles-dlpduck", "offline_access", "uma_authorization", "viewer"],
            }
        )
        client.get("/auth/callback")
        assert client.get("/jobs").status_code == 200  # viewer grants this
        assert client.get("/access").status_code == 403  # but not this

    def test_role_map_translates_external_names_that_differ(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        monkeypatch.setenv("DLPDUCK_SESSION_SECRET", "test-session-secret-not-for-production")
        monkeypatch.setenv("DLPDUCK_OIDC_CLIENT_SECRET", "test-oidc-client-secret")
        config = Config.model_validate(
            _base_config(
                tmp_path,
                {
                    "oidc": {
                        "issuer": "http://127.0.0.1:1/unreachable-by-design",
                        "client_id": "dlpduck-console",
                        "role_map": {"corp-dlp-team": "dlp_admin"},
                    }
                },
            )
        )
        client = TestClient(create_app(config, Pipeline(config)))
        client.app.state.oauth.oidc.authorize_access_token = _stub_token(
            {"preferred_username": "bob", "roles": ["corp-dlp-team"]}
        )
        client.get("/auth/callback")
        assert client.get("/access").status_code == 200  # mapped to dlp_admin

    def test_no_recognised_role_is_denied(self, oidc_env):
        client = oidc_env["client"]
        client.app.state.oauth.oidc.authorize_access_token = _stub_token(
            {"preferred_username": "alice", "roles": ["totally-unrelated-role"]}
        )
        resp = client.get("/auth/callback")
        assert resp.status_code == 403

    def test_missing_username_claim_is_denied(self, oidc_env):
        # A failed SSO login lands on the LOCAL form, not a bare /login:
        # /login auto-redirects into SSO, so bouncing there would put a
        # browser in a redirect loop whenever the IdP is misbehaving.
        client = oidc_env["client"]
        client.app.state.oauth.oidc.authorize_access_token = _stub_token({"roles": ["viewer"]})
        resp = client.get("/auth/callback", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?auth=local"

    def test_token_exchange_failure_is_a_clean_error_not_a_500(self, oidc_env):
        client = oidc_env["client"]
        client.app.state.oauth.oidc.authorize_access_token = _stub_error("state mismatch")
        resp = client.get("/auth/callback", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?auth=local"

    def test_sso_failure_does_not_leak_internal_detail_to_the_page(self, oidc_env):
        client = oidc_env["client"]
        client.app.state.oauth.oidc.authorize_access_token = _stub_error(
            "mismatching_state: CSRF Warning! State not equal in request and response."
        )
        resp = client.get("/auth/callback")  # follow the redirect to the form
        assert "mismatching_state" not in resp.text
        assert "Single sign-on failed" in resp.text

    def test_no_roles_claim_at_all_is_denied_not_a_crash(self, oidc_env):
        client = oidc_env["client"]
        client.app.state.oauth.oidc.authorize_access_token = _stub_token(
            {"preferred_username": "alice"}  # roles claim entirely absent
        )
        resp = client.get("/auth/callback")
        assert resp.status_code == 403


class TestLocalFallbackCoexistsWithOidc:
    def test_local_breakglass_account_still_logs_in(self, oidc_env):
        client = oidc_env["client"]
        resp = client.post(
            "/login", data={"username": "breakglass", "password": PASSWORD}, follow_redirects=False
        )
        assert resp.status_code == 303
        assert client.get("/access").status_code == 200  # dlp_admin, granted locally

    def test_local_and_oidc_sessions_are_indistinguishable_to_rbac(self, oidc_env):
        # Same permission check, same result, regardless of how the
        # session was established — RBAC doesn't know or care.
        local_client = TestClient(oidc_env["client"].app)
        local_client.post("/login", data={"username": "breakglass", "password": PASSWORD})

        oidc_client = TestClient(oidc_env["client"].app)
        oidc_client.app.state.oauth.oidc.authorize_access_token = _stub_token(
            {"preferred_username": "sso.admin", "roles": ["dlp_admin"]}
        )
        oidc_client.get("/auth/callback")

        assert local_client.get("/access").status_code == oidc_client.get("/access").status_code == 200
