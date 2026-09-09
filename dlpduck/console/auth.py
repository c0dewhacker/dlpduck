"""Authentication. Two paths converge on the same session shape —
`username` + `roles`, established at login and read directly from the
session on every later request, never re-derived from a store:

- Local accounts (the air-gapped fallback and break-glass path):
  argon2id-hashed passwords, configured in `console.auth.users`. Never a
  plaintext password in config — hash one with `dlpduck console
  hash-password`.
- OIDC (the primary path, implemented in dlpduck.console.oidc): an external IdP
  authenticates the person; the roles come from an ID token claim.

Because both write the same two session keys, RBAC (`require_permission`)
and everything downstream of it don't know or care which path a session
came from.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import HTTPException, Request

from dlpduck.console.rbac import Role, has_permission

logger = logging.getLogger("dlpduck.console.auth")

_hasher = PasswordHasher()


def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


@dataclass(frozen=True)
class UserAccount:
    username: str
    roles: frozenset[Role]


@dataclass(frozen=True)
class LocalAccount:
    """A configured local account, distinct from UserAccount: this one
    carries the password hash, which only LocalUserStore.authenticate
    ever needs to see. A logged-in session's UserAccount never does.
    """

    username: str
    password_hash: str
    roles: frozenset[Role]


class LocalUserStore:
    def __init__(self, users: list[dict]):
        self._by_username: dict[str, LocalAccount] = {}
        for entry in users:
            username = entry["username"]
            roles = frozenset(entry["roles"] if "roles" in entry else [entry["role"]])
            self._by_username[username] = LocalAccount(
                username=username, password_hash=entry["password_hash"], roles=roles
            )

    def authenticate(self, username: str, password: str) -> LocalAccount | None:
        user = self._by_username.get(username)
        if user is None:
            # Burn roughly the same argon2 work an existing user's failed
            # check would, so a missing username isn't measurably faster.
            _hasher.hash(password)
            return None
        try:
            _hasher.verify(user.password_hash, password)
        except VerifyMismatchError:
            return None
        except InvalidHashError:
            # The stored value isn't an argon2 hash at all — most often a
            # plaintext password pasted into password_hash. `dlpduck
            # validate-config` rejects that at boot; if one reaches here
            # anyway, refuse the login rather than letting the exception
            # become a 500 that leaks a stack trace to an anonymous caller.
            logger.error(
                "account %r has an unusable password_hash — refusing the login. "
                "Generate one with `dlpduck console hash-password`.",
                username,
            )
            return None
        return user

    def get(self, username: str) -> LocalAccount | None:
        return self._by_username.get(username)

    def all_users(self) -> list[LocalAccount]:
        """Return accounts for the read-only Access screen, since
        accounts live in config, not a store this could write back to.
        """
        return sorted(self._by_username.values(), key=lambda u: u.username)


class LoginThrottle:
    """Refuses further login attempts for a key that has failed too often
    in the recent past.

    Two things this protects. Password guessing is the obvious one, and
    argon2id already makes each guess slow. The slowness is exactly the
    problem, though: every attempt — including the equal-time path for a
    username that doesn't exist — allocates argon2's memory cost and holds
    a worker for tens of milliseconds. A few hundred concurrent POSTs to
    an *unauthenticated* endpoint therefore exhaust memory and CPU with no
    valid credential anywhere in sight. The check runs before any hashing,
    so a locked-out caller costs nothing.

    Keyed on both the username and the client address, because either
    alone leaves a hole: per-username only lets one host spray many
    accounts, per-address only lets a botnet grind one account.

    In-process and per-process, matching the single-daemon design. It
    is not a substitute for a WAF in front of an internet-facing console,
    and it isn't shared across replicas.
    """

    _MAX_TRACKED = 10_000

    def __init__(self, max_failures: int, lockout_seconds: int):
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> deque[float]:
        window = self._failures.setdefault(key, deque())
        cutoff = now - self.lockout_seconds
        while window and window[0] < cutoff:
            window.popleft()
        return window

    def is_locked(self, *keys: str) -> bool:
        now = time.monotonic()
        with self._lock:
            return any(len(self._recent(k, now)) >= self.max_failures for k in keys if k)

    def record_failure(self, *keys: str) -> None:
        now = time.monotonic()
        with self._lock:
            for key in keys:
                if key:
                    self._recent(key, now).append(now)
            # Bounded here rather than on success, because the case that
            # grows this table is a spray of usernames that never succeed:
            # the memory exhaustion this class exists to prevent, arriving
            # by another road. Expired entries hold no state worth keeping
            # — is_locked() would have discarded them anyway.
            if len(self._failures) > self._MAX_TRACKED:
                for key in [k for k in list(self._failures) if not self._recent(k, now)]:
                    del self._failures[key]

    def record_success(self, *keys: str) -> None:
        """Clears the counters, so an operator who mistypes a password four
        times and then gets it right isn't one slip from a lockout."""
        with self._lock:
            for key in keys:
                self._failures.pop(key, None)


def establish_session(request: Request, username: str, roles: frozenset[Role], method: str = "local") -> None:
    """The one place a session becomes authenticated — called by the
    local login form and the OIDC callback alike.

    Everything the session was carrying beforehand is discarded first.
    Authentication is a privilege boundary, and anything that survived
    across it would have been chosen while the session was anonymous: a
    pre-login cookie someone else planted (session fixation), or the CSRF
    token an unauthenticated visitor was handed. Both are rotated here by
    starting the authenticated session empty.
    """
    request.session.clear()
    request.session["username"] = username
    request.session["roles"] = sorted(roles)
    request.session["method"] = method
    token = secrets.token_urlsafe(32)
    request.session["token"] = token
    # Small unit-level callers may construct a Request without an ASGI app.
    # Production requests always have the operational store; keeping this
    # fallback also makes the session-rotation primitive useful on its own.
    app = request.scope.get("app")
    store = getattr(getattr(app, "state", None), "operations", None)
    config = getattr(getattr(app, "state", None), "config", None)
    if store is not None and config is not None:
        expires = (
            datetime.now(UTC).timestamp()
            + config.console.session_max_age_seconds
        )
        store.create_session(token, username, expires)
    if method == "local":
        user_store = getattr(getattr(app, "state", None), "user_store", None)
        account = user_store.get(username) if user_store is not None else None
        request.session["credential"] = hashlib.sha256(account.password_hash.encode()).hexdigest() if account else ""



def get_current_user(request: Request) -> UserAccount | None:
    username = request.session.get("username")
    roles = request.session.get("roles")
    if not username or roles is None:
        return None
    token = request.session.get("token")
    app = request.scope.get("app")
    operations = getattr(getattr(app, "state", None), "operations", None)
    if operations is not None and (
        not token or not operations.session_active(token, username)
    ):
        request.session.clear()
        return None
    if request.session.get("method") == "local":
        user_store = getattr(getattr(app, "state", None), "user_store", None)
        account = user_store.get(username) if user_store is not None else None
        if account is None or request.session.get("credential") != hashlib.sha256(account.password_hash.encode()).hexdigest():
            if operations is not None:
                operations.revoke(token=token)
            request.session.clear()
            return None
        roles = account.roles
    return UserAccount(username=username, roles=frozenset(roles))


def require_login(request: Request) -> UserAccount:
    user = get_current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="login required")
    return user


def require_permission(permission: str):
    """FastAPI dependency factory: `Depends(require_permission("jobs.list"))`.
    401 if not logged in, 403 if logged in but lacking the permission —
    a real ADR001-style choice, not laziness: a 401 tells an operator
    "log in", a 403 tells them "log in as someone else".
    """

    def _dependency(request: Request) -> UserAccount:
        user = require_login(request)
        if not has_permission(set(user.roles), permission):
            raise HTTPException(
                status_code=403,
                detail=f"This page needs the '{permission}' permission, which your role doesn't grant.",
            )
        return user

    return _dependency
