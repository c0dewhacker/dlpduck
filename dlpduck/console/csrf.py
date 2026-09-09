"""A minimal CSRF guard for the console's mutating forms (reveal, release,
purge). Token lives in the signed session cookie SessionMiddleware already
manages — issued on first render of a page with a form, checked on the
matching POST. Login itself is exempt: it's the authentication boundary,
not a state change a logged-in session needs protecting.
"""

from __future__ import annotations

import secrets

from fastapi import HTTPException, Request


def get_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def verify_csrf(request: Request, submitted: str) -> None:
    expected = request.session.get("csrf_token")
    if not expected or not _matches(expected, submitted):
        raise HTTPException(status_code=403, detail="missing or invalid CSRF token")


def _matches(expected: str, submitted: str) -> bool:
    """Constant-time compare that tolerates whatever was actually posted.

    `secrets.compare_digest` raises TypeError on a str containing any
    non-ASCII character, and `submitted` is attacker-controlled form
    input. Left to escape, one accented byte in the token field turned
    the CSRF check itself into a 500 — an unhandled error on the guard,
    where the only correct answer is "no". Comparing the UTF-8 bytes
    keeps the timing property and has an answer for every input.
    """
    if not isinstance(submitted, str):
        return False
    return secrets.compare_digest(expected.encode("utf-8"), submitted.encode("utf-8"))
