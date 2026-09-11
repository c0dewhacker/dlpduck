"""Emit-phase plugins: forward a job's outcome to syslog or a generic
webhook. Both are best-effort — a delivery failure spools the event and
raises, so a down endpoint never blocks the pipeline, but a
`critical: true` plugin still stops the job for an operator to look at.

The local JSONL audit log (dlpduck.audit.AuditLog) is the always-on,
synchronous record of truth and is not implemented as a plugin — it runs
inside Pipeline.commit() itself, before these ever see the job.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from dlpduck.plugins.base import Plugin
from dlpduck.plugins.spool import Spool
from dlpduck.types import JobContext


class SpoolingSink(Plugin):
    """Shared build -> deliver contract: `run()` builds a payload and
    delivers it; on failure the same payload is spooled and `run()`
    re-raises. `replay()` re-delivers whatever's pending later, using the
    identical `deliver()` — a replayed event takes the exact path a live
    one would have.
    """

    phase = "emit"
    default_name = "sink"

    def __init__(
        self,
        name: str | None = None,
        critical: bool = False,
        spool_root: Path | None = None,
        timeout: float = 5.0,
    ):
        self.name = name or self.default_name
        self.critical = critical
        self.timeout = timeout
        self.spool = Spool(spool_root, self.name) if spool_root is not None else None

    def build(self, ctx: JobContext) -> dict[str, Any]:
        raise NotImplementedError

    def deliver(self, payload: dict[str, Any]) -> None:
        raise NotImplementedError

    def run(self, ctx: JobContext) -> None:
        payload = self.build(ctx)
        try:
            self.deliver(payload)
        except Exception:
            if self.spool is not None:
                self.spool.append(ctx.job_id, payload)
            raise

    def replay(self) -> tuple[int, int]:
        """Drain the spool in order. Returns (delivered, still_pending)."""
        if self.spool is None:
            return (0, 0)
        return self.spool.drain(self.deliver)


def _job_payload(ctx: JobContext) -> dict[str, Any]:
    """The one shape both sinks send. Everything here is already masked
    or allowlisted well before it reaches a plugin — `metadata` is the
    same allowlisted subset that lands in the permanent index row, and
    DLPHit has no field to put a raw matched value in even if a plugin
    wanted one — so there's nothing new to guard by leaving a field out;
    leaving one out just means a SIEM can't see it.
    """
    text = ctx.text
    return {
        "event": "job.completed",
        "job_id": ctx.job_id,
        "received_at": ctx.received_at.isoformat(),
        "disposition": ctx.disposition,
        "reason": ctx.reason,
        "page_count": text.page_count if text else None,
        "ocr_page_count": text.ocr_page_count if text else None,
        "failed_page_count": text.failed_page_count if text else None,
        "degraded": text.degraded if text else None,
        "highest_severity": ctx.highest_severity.value if ctx.highest_severity else None,
        "hit_count": len(ctx.hits),
        "hits": [
            {
                "rule_id": h.rule_id,
                "rule_name": h.rule_name,
                "severity": h.severity.value,
                "action": h.action,
                "page_number": h.page_number,
                "line_number": h.line_number,
                "masked_text": h.masked_text,
                # Keyed digest for correlating the same sensitive value
                # across documents without ever exposing it — the whole
                # reason match_hmac exists.
                "match_hmac": h.match_hmac,
                "validator": h.validator,
            }
            for h in ctx.hits
        ],
        "metadata": ctx.metadata,
        "audit_fields": ctx.audit_fields,
    }


class SyslogSink(SpoolingSink):
    default_name = "syslog"

    def __init__(self, host: str, port: int = 514, protocol: str = "udp", **kwargs):
        super().__init__(**kwargs)
        if protocol not in ("udp", "tcp"):
            raise ValueError(f"syslog protocol must be 'udp' or 'tcp', got {protocol!r}")
        self.host = host
        self.port = port
        self.protocol = protocol

    def build(self, ctx: JobContext) -> dict[str, Any]:
        return {"message": self._format(ctx)}

    def deliver(self, payload: dict[str, Any]) -> None:
        data = payload["message"].encode("utf-8")
        if self.protocol == "udp":
            # Resolved rather than assumed AF_INET: a syslog collector
            # reachable only over IPv6 is ordinary in a modern network,
            # and hardcoding the family made every event to one of those
            # spool forever with a resolution error nobody would connect
            # to the address family. TCP gets this free from
            # create_connection, which is why only this branch needed it.
            family, socktype, proto, _, sockaddr = socket.getaddrinfo(
                self.host, self.port, type=socket.SOCK_DGRAM
            )[0]
            with socket.socket(family, socktype, proto) as s:
                s.settimeout(self.timeout)
                s.sendto(data, sockaddr)
        else:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                s.sendall(data + b"\n")

    def _format(self, ctx: JobContext) -> str:
        # RFC 5424 header (facility=1 user-level, severity=6 informational
        # -> pri=14) with no structured-data and the full payload as MSG —
        # a collector that only wants the header still gets a real
        # timestamp/MSGID to route on; one that parses MSG as JSON gets
        # everything build()/WebhookSink also send.
        payload = json.dumps(_job_payload(ctx), sort_keys=True)
        return f"<14>1 {ctx.received_at.isoformat()} dlpduck dlpduck - job.completed - {payload}"


_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Turns a redirect into an error instead of following it.

    urllib followed 301 and 302 by default, and carried custom headers
    across them to a *different host* — so a webhook endpoint answering
    `302 Location: http://attacker/` handed `X-DLPDuck-Signature` to
    whatever host it named. (307/308 with a body it already refused.)

    The leaked signature is over one exact body, so it is not a reusable
    credential. The sharper problem is what came back: a 200 from the
    redirect target was read as a successful delivery, so the configured
    SIEM received nothing, nothing was spooled, and the pipeline recorded
    the event as delivered. A misconfigured or compromised endpoint could
    make DLP alerts disappear silently — the one failure mode a sink must
    not have.

    A webhook POST now goes where the config says or it fails and spools.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class WebhookSink(SpoolingSink):
    default_name = "webhook"

    def __init__(self, url: str, secret_env: str | None = None, **kwargs):
        super().__init__(**kwargs)
        # urllib will happily open file:// and ftp:// too. A webhook URL
        # comes from config rather than a request, but "the config was
        # wrong" shouldn't be able to turn an outbound POST into a local
        # file operation, so the scheme is an allowlist.
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError(f"webhook url must be http:// or https://, got {url!r}")
        self.url = url
        self.secret = os.environ.get(secret_env, "") if secret_env else ""
        self._opener = urllib.request.build_opener(_NoRedirects)

    def build(self, ctx: JobContext) -> dict[str, Any]:
        return _job_payload(ctx)

    def deliver(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.secret:
            sig = hmac.new(self.secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-DLPDuck-Signature"] = sig
        # S310: the scheme is allowlisted to http/https in __init__, so
        # this can never reach file:// or a custom handler.
        request = urllib.request.Request(self.url, data=body, headers=headers, method="POST")  # noqa: S310
        try:
            with self._opener.open(request, timeout=self.timeout) as resp:
                if resp.status >= 300:
                    raise RuntimeError(f"webhook {self.url} returned HTTP {resp.status}")
        except urllib.error.HTTPError as exc:
            if exc.code in _REDIRECT_CODES:
                raise RuntimeError(
                    f"webhook {self.url} redirected (HTTP {exc.code}) to "
                    f"{exc.headers.get('Location')!r} — refusing to follow"
                ) from exc
            raise RuntimeError(f"webhook {self.url} returned HTTP {exc.code}") from exc
