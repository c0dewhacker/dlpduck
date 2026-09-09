import time
from pathlib import Path

from dlpduck.config import Config
from dlpduck.console.auth import (
    LocalAccount,
    LocalUserStore,
    LoginThrottle,
    hash_password,
)

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


def _store(**overrides) -> LocalUserStore:
    user = {
        "username": "alice",
        "password_hash": hash_password("correct horse battery staple"),
        "roles": ["investigator"],
    }
    user.update(overrides)
    return LocalUserStore([user])


class TestHashPassword:
    def test_hash_is_not_the_plaintext(self):
        h = hash_password("hunter2")
        assert "hunter2" not in h

    def test_hash_is_argon2(self):
        assert hash_password("hunter2").startswith("$argon2id$")

    def test_same_password_hashes_differently_each_time(self):
        # argon2 salts automatically — two hashes of the same password
        # must not be byte-identical.
        assert hash_password("hunter2") != hash_password("hunter2")


class TestAuthenticate:
    def test_correct_password_succeeds(self):
        store = _store()
        user = store.authenticate("alice", "correct horse battery staple")
        assert user is not None
        assert user.username == "alice"
        assert "investigator" in user.roles

    def test_wrong_password_fails(self):
        store = _store()
        assert store.authenticate("alice", "wrong password") is None

    def test_unknown_username_fails(self):
        store = _store()
        assert store.authenticate("bob", "anything") is None

    def test_get_returns_none_for_unknown_user(self):
        store = _store()
        assert store.get("bob") is None

    def test_get_returns_the_account_for_a_known_user(self):
        store = _store()
        assert store.get("alice").username == "alice"

    def test_multiple_roles_are_preserved(self):
        store = _store(roles=["investigator", "auditor"])
        user = store.authenticate("alice", "correct horse battery staple")
        assert user.roles == frozenset({"investigator", "auditor"})

    def test_single_role_key_still_works(self):
        store = LocalUserStore(
            [{"username": "bob", "password_hash": hash_password("pw"), "role": "viewer"}]
        )
        user = store.authenticate("bob", "pw")
        assert user.roles == frozenset({"viewer"})


class TestTimingResistance:
    def test_unknown_username_does_not_return_dramatically_faster(self):
        # Not a precise timing-attack test (too flaky for CI), just a
        # sanity check that the "unknown user" path does real work
        # instead of returning immediately — the mitigation is exercised,
        # not proven airtight.
        store = _store()
        start = time.perf_counter()
        store.authenticate("nobody", "whatever")
        unknown_elapsed = time.perf_counter() - start

        start = time.perf_counter()
        store.authenticate("alice", "wrong password")
        known_elapsed = time.perf_counter() - start

        # Both should take real argon2 work — order of tens of
        # milliseconds, not microseconds — rather than the unknown-user
        # path short-circuiting.
        assert unknown_elapsed > 0.001
        assert known_elapsed > 0.001


class TestSessionIsRotatedAtTheAuthBoundary:
    """Authentication is a privilege boundary: nothing chosen while the
    session was anonymous should survive across it."""

    def test_pre_login_session_contents_do_not_survive_login(self):
        from starlette.requests import Request

        from dlpduck.console.auth import establish_session

        scope = {"type": "http", "headers": [], "session": {}}
        request = Request(scope)
        request.session["csrf_token"] = "token-issued-while-anonymous"
        request.session["attacker_planted"] = "value"

        establish_session(request, "alice", frozenset({"viewer"}))

        assert request.session["username"] == "alice"
        assert "attacker_planted" not in request.session
        assert "csrf_token" not in request.session  # reissued on next render

    def test_a_second_login_does_not_inherit_the_first_users_state(self):
        from starlette.requests import Request

        from dlpduck.console.auth import establish_session

        request = Request({"type": "http", "headers": [], "session": {}})
        establish_session(request, "alice", frozenset({"dlp_admin"}))
        request.session["something_alice_did"] = "x"

        establish_session(request, "bob", frozenset({"viewer"}))

        assert request.session["username"] == "bob"
        assert request.session["roles"] == ["viewer"]
        assert "something_alice_did" not in request.session


class TestUnusablePasswordHashIsCaughtEarly:
    """Pasting the password itself into password_hash is the commonest way
    to misconfigure a local account. It used to surface as an
    InvalidHashError escaping the login handler — a 500 for an anonymous
    caller — and, worse, meant a credential sitting in cleartext in config.
    """

    def test_config_with_a_plaintext_password_is_rejected_at_load(self):
        import pytest
        from pydantic import ValidationError

        from dlpduck.config import ConsoleUserConfig

        with pytest.raises(ValidationError, match="argon2"):
            ConsoleUserConfig(username="oops", password_hash="hunter2", role="viewer")

    def test_a_real_hash_is_accepted(self):
        from dlpduck.config import ConsoleUserConfig

        account = ConsoleUserConfig(
            username="fine", password_hash=hash_password("hunter2"), role="viewer"
        )
        assert account.roles == ["viewer"]

    def test_an_unusable_hash_reaching_the_store_refuses_rather_than_raising(self, caplog):
        """Defence in depth: config validation is the gate, but the store
        must not turn a bad value into an exception either."""
        store = LocalUserStore(
            [{"username": "oops", "password_hash": "not-a-hash", "roles": ["viewer"]}]
        )
        assert store.authenticate("oops", "not-a-hash") is None
        assert store.authenticate("oops", "anything-else") is None

    def test_login_with_such_an_account_is_a_401_not_a_500(self, tmp_path, monkeypatch):
        """The whole point: an anonymous caller gets a clean rejection, not
        a stack trace."""
        from fastapi.testclient import TestClient

        from dlpduck.console.app import create_app
        from dlpduck.pipeline import Pipeline

        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        monkeypatch.setenv("DLPDUCK_SESSION_SECRET", "test-session-secret-not-for-production")
        src = tmp_path / "drops"
        src.mkdir()
        config = Config.model_validate(
            {
                "source": {"name": "t", "path": str(src), "metadata_format": "none"},
                "destination": {
                    "archive": str(tmp_path / "archive"),
                    "quarantine": str(tmp_path / "quarantine"),
                    "work_dir": str(tmp_path / "work"),
                },
                "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
                "console": {
                    "auth": {
                        "users": [
                            {
                                "username": "ok",
                                "password_hash": hash_password("right"),
                                "role": "viewer",
                            }
                        ]
                    }
                },
            }
        )
        # Corrupt the stored hash after validation, as an operator editing
        # the file by hand between restarts effectively would.
        app = create_app(config, Pipeline(config))
        app.state.user_store._by_username["ok"] = LocalAccount(
            username="ok", password_hash="plaintext-oops", roles=frozenset({"viewer"})
        )

        resp = TestClient(app).post("/login", data={"username": "ok", "password": "right"})

        assert resp.status_code == 401
        assert "Invalid username or password" in resp.text


class TestLoginThrottle:
    """Verifying a password is deliberately expensive. That cost is the
    defence against guessing and, on an unauthenticated endpoint, the
    weapon against the server — so the ceiling has to come before the
    hashing, not after it.
    """

    def test_allows_attempts_up_to_the_limit(self):
        throttle = LoginThrottle(max_failures=3, lockout_seconds=300)
        for _ in range(2):
            throttle.record_failure("alice", "10.0.0.1")
        assert throttle.is_locked("alice", "10.0.0.1") is False

    def test_locks_out_at_the_limit(self):
        throttle = LoginThrottle(max_failures=3, lockout_seconds=300)
        for _ in range(3):
            throttle.record_failure("alice", "10.0.0.1")
        assert throttle.is_locked("alice", "10.0.0.1") is True

    def test_one_host_cannot_spray_many_accounts(self):
        """Per-username counters alone would let a single host try every
        account in the config once each, indefinitely."""
        throttle = LoginThrottle(max_failures=3, lockout_seconds=300)
        for name in ("alice", "bob", "carol"):
            throttle.record_failure(name, "10.0.0.1")

        assert throttle.is_locked("dave", "10.0.0.1") is True

    def test_a_botnet_cannot_grind_one_account(self):
        """Per-address counters alone would let many hosts share the work
        of guessing a single password."""
        throttle = LoginThrottle(max_failures=3, lockout_seconds=300)
        for host in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            throttle.record_failure("alice", host)

        assert throttle.is_locked("alice", "10.0.0.9") is True

    def test_the_lockout_expires(self):
        throttle = LoginThrottle(max_failures=2, lockout_seconds=0.05)
        throttle.record_failure("alice", "10.0.0.1")
        throttle.record_failure("alice", "10.0.0.1")
        assert throttle.is_locked("alice", "10.0.0.1") is True

        time.sleep(0.06)

        assert throttle.is_locked("alice", "10.0.0.1") is False

    def test_success_clears_the_count(self):
        """An operator who mistypes twice and then gets it right should
        not be one slip away from locking themselves out."""
        throttle = LoginThrottle(max_failures=3, lockout_seconds=300)
        throttle.record_failure("alice", "10.0.0.1")
        throttle.record_failure("alice", "10.0.0.1")
        throttle.record_success("alice", "10.0.0.1")

        for _ in range(2):
            throttle.record_failure("alice", "10.0.0.1")
        assert throttle.is_locked("alice", "10.0.0.1") is False

    def test_the_tracking_table_stays_bounded(self):
        """Spraying distinct usernames must not grow this without limit —
        that is the memory exhaustion it exists to prevent, by another
        road. Expired entries carry no state worth keeping."""
        throttle = LoginThrottle(max_failures=3, lockout_seconds=0.01)
        for i in range(LoginThrottle._MAX_TRACKED + 500):
            throttle.record_failure(f"user{i}", "")

        assert len(throttle._failures) <= LoginThrottle._MAX_TRACKED + 1

    def test_empty_keys_are_ignored(self):
        """request.client is None for some ASGI transports; an empty host
        must not become a shared bucket every caller locks each other out
        of."""
        throttle = LoginThrottle(max_failures=1, lockout_seconds=300)
        throttle.record_failure("alice", "")
        assert throttle.is_locked("bob", "") is False
