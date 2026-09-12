"""One plugin protocol supports two phases. A non-critical failure is logged
and swallowed; a critical one stops the job. Sinks spool on delivery
failure so a down endpoint never blocks the pipeline.
"""

import json
import socket
from datetime import UTC, datetime

import pytest

from dlpduck.audit import AuditLog
from dlpduck.plugins.base import Plugin, PluginError, PluginRunner
from dlpduck.plugins.enrich import StaticEnrich
from dlpduck.plugins.loader import BUILTIN_PLUGINS, PluginConfigError, load_plugins
from dlpduck.plugins.sinks import SpoolingSink, SyslogSink, WebhookSink
from dlpduck.plugins.spool import Spool
from dlpduck.types import DocumentText, JobContext

# Fixed, not now(): a payload embeds received_at at microsecond precision,
# so any "this value does not appear" assertion below would otherwise race
# the clock — a 4-digit needle turns up in the timestamp digits roughly
# once in 3000 runs, which is exactly the kind of flake that erodes trust
# in a suite.
_FIXED_RECEIVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _ctx(job_id="a1b2", hits=None, metadata=None):
    return JobContext(
        job_id=job_id,
        received_at=_FIXED_RECEIVED_AT,
        source_name="test",
        staging_dir=None,
        pdf_path=None,
        pdf_sha256="x",
        metadata=metadata or {},
        text=DocumentText(page_count=1),
        hits=hits or [],
    )


class _Recording(Plugin):
    def __init__(self, phase="enrich", critical=False, name="rec", raises=False):
        self.phase = phase
        self.critical = critical
        self.name = name
        self.raises = raises
        self.calls = 0

    def run(self, ctx):
        self.calls += 1
        if self.raises:
            raise RuntimeError("boom")


class TestPluginRunner:
    def test_only_plugins_matching_the_phase_run(self, tmp_path):
        audit = AuditLog(tmp_path)
        enrich = _Recording(phase="enrich")
        emit = _Recording(phase="emit")
        runner = PluginRunner([enrich, emit], audit)

        runner.run(_ctx(), phase="enrich")

        assert enrich.calls == 1
        assert emit.calls == 0

    def test_non_critical_failure_is_logged_and_swallowed(self, tmp_path):
        audit = AuditLog(tmp_path)
        plugin = _Recording(phase="enrich", critical=False, raises=True)
        runner = PluginRunner([plugin], audit)

        runner.run(_ctx(), phase="enrich")  # must not raise

        ok, breaks = audit.verify()
        assert ok
        # Glob rather than assume today's local date — the audit log
        # partitions by UTC date, which can differ from local near midnight.
        [log_file] = tmp_path.glob("dt=*/events.jsonl")
        events = log_file.read_text().splitlines()
        assert any('"event":"plugin.failed"' in e for e in events)

    def test_critical_failure_raises_pluginerror(self, tmp_path):
        audit = AuditLog(tmp_path)
        plugin = _Recording(phase="enrich", critical=True, raises=True, name="critical_one")
        runner = PluginRunner([plugin], audit)

        with pytest.raises(PluginError) as exc_info:
            runner.run(_ctx(), phase="enrich")
        assert exc_info.value.plugin_name == "critical_one"

    def test_a_failure_does_not_stop_other_plugins_in_the_same_phase(self, tmp_path):
        audit = AuditLog(tmp_path)
        failing = _Recording(phase="enrich", critical=False, raises=True, name="first")
        healthy = _Recording(phase="enrich", critical=False, name="second")
        runner = PluginRunner([failing, healthy], audit)

        runner.run(_ctx(), phase="enrich")

        assert healthy.calls == 1


class TestSpool:
    def test_append_and_drain_on_success(self, tmp_path):
        spool = Spool(tmp_path, "test_sink")
        spool.append("job1", {"x": 1})
        spool.append("job2", {"x": 2})

        delivered_payloads = []
        ok, pending = spool.drain(lambda p: delivered_payloads.append(p))

        assert ok == 2
        assert pending == 0
        assert spool.pending() == []
        assert [p["x"] for p in delivered_payloads] == [1, 2]

    def test_drain_stops_at_first_failure_preserving_order(self, tmp_path):
        spool = Spool(tmp_path, "test_sink")
        spool.append("job1", {"x": 1})
        spool.append("job2", {"x": 2})

        def flaky(payload):
            if payload["x"] == 2:
                raise RuntimeError("still down")

        ok, pending = spool.drain(flaky)

        assert ok == 1
        assert pending == 1
        remaining = [__import__("json").loads(p.read_text()) for p in spool.pending()]
        assert remaining == [{"x": 2}]


class _FakeSpoolingSink(SpoolingSink):
    default_name = "fake"

    def __init__(self, fail: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.fail = fail
        self.delivered = []

    def build(self, ctx):
        return {"job_id": ctx.job_id}

    def deliver(self, payload):
        if self.fail:
            raise RuntimeError("endpoint down")
        self.delivered.append(payload)


class TestSpoolingSinkContract:
    def test_successful_delivery_does_not_spool(self, tmp_path):
        sink = _FakeSpoolingSink(fail=False, spool_root=tmp_path)
        sink.run(_ctx(job_id="j1"))
        assert sink.spool.pending() == []
        assert sink.delivered == [{"job_id": "j1"}]

    def test_failed_delivery_spools_and_reraises(self, tmp_path):
        sink = _FakeSpoolingSink(fail=True, spool_root=tmp_path)
        with pytest.raises(RuntimeError):
            sink.run(_ctx(job_id="j1"))
        assert len(sink.spool.pending()) == 1

    def test_replay_uses_the_same_deliver_path(self, tmp_path):
        sink = _FakeSpoolingSink(fail=True, spool_root=tmp_path)
        with pytest.raises(RuntimeError):
            sink.run(_ctx(job_id="j1"))

        sink.fail = False  # endpoint recovers
        delivered, pending = sink.replay()

        assert delivered == 1
        assert pending == 0
        assert sink.delivered == [{"job_id": "j1"}]

    def test_no_spool_root_means_no_spooling_just_reraise(self):
        sink = _FakeSpoolingSink(fail=True, spool_root=None)
        with pytest.raises(RuntimeError):
            sink.run(_ctx())
        assert sink.spool is None
        assert sink.replay() == (0, 0)


class TestSyslogSink:
    def test_format_contains_disposition_and_severity(self):
        from dlpduck.types import DLPHit, Severity

        ctx = _ctx(
            hits=[
                DLPHit(
                    rule_id="r", rule_name="R", severity=Severity.CRITICAL, action="quarantine",
                    page_number=1, line_number=0, line_on_page=0, start=0, end=1,
                    masked_text="•", match_hmac="h",
                )
            ]
        )
        ctx.disposition = "quarantine"
        sink = SyslogSink(host="127.0.0.1")
        message = sink.build(ctx)["message"]
        assert "quarantine" in message
        assert "CRITICAL" in message
        assert ctx.job_id in message

    def test_message_is_a_real_rfc5424_header_with_a_json_body(self):
        from dlpduck.types import DLPHit, Severity

        ctx = _ctx(
            hits=[
                DLPHit(
                    rule_id="us_ssn", rule_name="US SSN", severity=Severity.HIGH,
                    action="quarantine", page_number=1, line_number=14, line_on_page=0,
                    start=0, end=11, masked_text="***-**-6789", match_hmac="a3f9e1c2",
                    validator="luhn_ssn",
                )
            ],
            metadata={"device_id": "MFP-3F-04", "department": "Finance"},
        )
        sink = SyslogSink(host="127.0.0.1")
        message = sink.build(ctx)["message"]

        header, _, body = message.partition(" - job.completed - ")
        assert header.startswith("<14>1 ")
        payload = json.loads(body)
        # This must carry everything WebhookSink does — same builder.
        assert payload["job_id"] == ctx.job_id
        assert payload["metadata"] == {"device_id": "MFP-3F-04", "department": "Finance"}
        assert payload["hits"][0]["match_hmac"] == "a3f9e1c2"
        assert payload["hits"][0]["validator"] == "luhn_ssn"

    def test_tcp_connection_refused_spools_and_raises(self, tmp_path):
        # Port 1 is refused without root on any normal system — a reliable
        # stand-in for "the SIEM endpoint is down" without mocking sockets.
        sink = SyslogSink(host="127.0.0.1", port=1, protocol="tcp", spool_root=tmp_path, timeout=1)
        with pytest.raises(OSError):
            sink.run(_ctx())
        assert len(sink.spool.pending()) == 1

    def test_invalid_protocol_rejected_at_construction(self):
        with pytest.raises(ValueError):
            SyslogSink(host="127.0.0.1", protocol="carrier-pigeon")

    def _hit(self, n: int):
        from dlpduck.types import DLPHit, Severity

        return DLPHit(
            rule_id=f"rule.{n}", rule_name=f"Rule {n}", severity=Severity.HIGH, action="quarantine",
            page_number=1, line_number=n, line_on_page=n, start=0, end=10,
            masked_text=f"****-{n:06d}", match_hmac=f"hmac{n:028x}",
        )

    def test_a_document_with_many_hits_drops_hit_detail_but_keeps_the_count(self):
        ctx = _ctx(hits=[self._hit(n) for n in range(500)])
        sink = SyslogSink(host="127.0.0.1")

        message = sink.build(ctx)["message"]

        assert len(message.encode("utf-8")) <= sink.max_message_bytes
        _, _, body = message.partition(" - job.completed - ")
        payload = json.loads(body)  # still valid, parseable JSON
        assert payload["hits"] == []
        assert payload["hits_truncated"] is True
        assert payload["hit_count"] == 500  # the real total survives the truncation

    def test_a_small_document_is_never_truncated(self):
        ctx = _ctx(hits=[self._hit(0)])
        sink = SyslogSink(host="127.0.0.1")

        message = sink.build(ctx)["message"]

        _, _, body = message.partition(" - job.completed - ")
        payload = json.loads(body)
        assert "hits_truncated" not in payload
        assert len(payload["hits"]) == 1

    def test_oversized_metadata_falls_back_to_a_minimal_valid_message(self):
        ctx = _ctx(hits=[self._hit(n) for n in range(500)], metadata={"note": "x" * 20000})
        sink = SyslogSink(host="127.0.0.1")

        message = sink.build(ctx)["message"]

        _, _, body = message.partition(" - job.completed - ")
        payload = json.loads(body)  # valid JSON even in the worst case
        assert payload["job_id"] == ctx.job_id
        assert payload["hits_truncated"] is True
        assert payload["metadata_truncated"] is True
        assert "metadata" not in payload


class TestWebhookSink:
    def test_build_includes_document_metadata_and_extraction_stats(self):
        ctx = _ctx(metadata={"device_id": "MFP-3F-04", "department": "Finance"})
        ctx.disposition = "archive"
        sink = WebhookSink(url="https://example.invalid/hook")
        payload = sink.build(ctx)

        assert payload["metadata"] == {"device_id": "MFP-3F-04", "department": "Finance"}
        assert payload["page_count"] == 1
        assert payload["event"] == "job.completed"

    def test_build_never_includes_a_raw_matched_value(self):
        from dlpduck.types import DLPHit, Severity

        ctx = _ctx(
            hits=[
                DLPHit(
                    rule_id="pan.generic", rule_name="Card", severity=Severity.HIGH,
                    action="quarantine", page_number=1, line_number=0, line_on_page=0,
                    start=0, end=16, masked_text="••••••••••••1234", match_hmac="deadbeef",
                )
            ]
        )
        sink = WebhookSink(url="https://example.invalid/hook")
        payload = sink.build(ctx)

        assert payload["hits"][0]["masked_text"] == "••••••••••••1234"
        # A hit forwarded to a SIEM carries the masked form and the keyed
        # digest, never the value itself — and DLPHit has nowhere to put
        # one, which is the actual guarantee being pinned here. start/end
        # (character offsets into extracted text, meaningless without the
        # text itself) are the only DLPHit fields deliberately left out;
        # everything else it carries is safe to forward and now is.
        assert set(payload["hits"][0]) == {
            "rule_id", "rule_name", "severity", "action", "page_number",
            "line_number", "masked_text", "match_hmac", "validator",
        }
        assert "4111111111111234" not in str(payload)

    def test_unreachable_host_spools_and_raises(self, tmp_path):
        # A closed local port: bind then release it so nothing is
        # listening when the sink tries to connect — a reliable,
        # network-free way to simulate an unreachable webhook.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        sink = WebhookSink(url=f"http://127.0.0.1:{port}/hook", spool_root=tmp_path, timeout=1)
        with pytest.raises(Exception):
            sink.run(_ctx())
        assert len(sink.spool.pending()) == 1

    def test_signature_header_added_when_secret_present(self, monkeypatch):
        monkeypatch.setenv("TEST_WEBHOOK_SECRET", "s3cret")
        sink = WebhookSink(url="https://example.invalid", secret_env="TEST_WEBHOOK_SECRET")
        assert sink.secret == "s3cret"

    def test_no_secret_env_means_no_secret(self):
        sink = WebhookSink(url="https://example.invalid")
        assert sink.secret == ""


class TestStaticEnrich:
    def test_matching_key_merges_into_audit_fields(self):
        plugin = StaticEnrich(mapping={"MFP-3F-04": {"department": "Legal"}})
        ctx = _ctx(metadata={"device_id": "MFP-3F-04"})
        plugin.run(ctx)
        assert ctx.audit_fields["department"] == "Legal"

    def test_unmatched_key_is_not_an_error(self):
        plugin = StaticEnrich(mapping={"MFP-3F-04": {"department": "Legal"}})
        ctx = _ctx(metadata={"device_id": "MFP-UNKNOWN"})
        plugin.run(ctx)  # must not raise
        assert ctx.audit_fields == {}

    def test_missing_key_field_is_not_an_error(self):
        plugin = StaticEnrich(mapping={"MFP-3F-04": {"department": "Legal"}})
        ctx = _ctx(metadata={})
        plugin.run(ctx)
        assert ctx.audit_fields == {}


class TestLoader:
    def test_builtin_name_resolves_without_a_path(self, tmp_path):
        plugins = load_plugins(
            [{"name": "syslog", "args": {"host": "127.0.0.1"}}], spool_root=tmp_path
        )
        assert len(plugins) == 1
        assert isinstance(plugins[0], SyslogSink)
        assert plugins[0].name == "syslog"

    def test_disabled_entry_is_skipped(self, tmp_path):
        plugins = load_plugins(
            [{"name": "syslog", "enabled": False, "args": {"host": "x"}}], spool_root=tmp_path
        )
        assert plugins == []

    def test_custom_path_overrides_builtin_lookup(self, tmp_path):
        plugins = load_plugins(
            [
                {
                    "name": "custom_enrich",
                    "path": "dlpduck.plugins.enrich.StaticEnrich",
                    "args": {"mapping": {}},
                }
            ],
            spool_root=tmp_path,
        )
        assert isinstance(plugins[0], StaticEnrich)

    def test_unknown_name_without_path_raises(self, tmp_path):
        with pytest.raises(PluginConfigError, match="known builtin"):
            load_plugins([{"name": "not_a_real_plugin"}], spool_root=tmp_path)

    def test_bad_import_path_raises(self, tmp_path):
        with pytest.raises(PluginConfigError, match="cannot load"):
            load_plugins([{"path": "dlpduck.nope.Nothing"}], spool_root=tmp_path)

    def test_critical_and_spool_root_are_auto_injected(self, tmp_path):
        plugins = load_plugins(
            [{"name": "syslog", "critical": True, "args": {"host": "127.0.0.1"}}],
            spool_root=tmp_path,
        )
        assert plugins[0].critical is True
        assert plugins[0].spool is not None

    def test_explicit_args_are_not_overridden_by_auto_injection(self, tmp_path):
        other_root = tmp_path / "elsewhere"
        plugins = load_plugins(
            [
                {
                    "name": "syslog",
                    "args": {"host": "127.0.0.1", "spool_root": other_root},
                }
            ],
            spool_root=tmp_path,
        )
        assert plugins[0].spool.dir.parent == other_root

    def test_all_builtins_are_actually_importable(self, tmp_path):
        for dotted in BUILTIN_PLUGINS.values():
            module_name, class_name = dotted.rsplit(".", 1)
            import importlib

            cls = getattr(importlib.import_module(module_name), class_name)
            assert cls is not None


class TestSyslogDeliveryOverRealSockets:
    """The failure path is covered above; this is the path that actually
    has to work. Both transports are exercised against a real listener on
    localhost, because "it built the string" is not the same claim as "the
    SIEM received it".
    """

    def test_udp_datagram_actually_arrives(self, tmp_path):
        import socket

        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        listener.settimeout(5)
        port = listener.getsockname()[1]
        try:
            ctx = _ctx()
            ctx.disposition = "quarantine"
            sink = SyslogSink(host="127.0.0.1", port=port, protocol="udp", spool_root=tmp_path)
            sink.run(ctx)

            payload = listener.recv(4096).decode("utf-8")
        finally:
            listener.close()

        assert ctx.job_id in payload
        assert "quarantine" in payload
        assert payload.startswith("<14>1 ")  # RFC 5424-ish priority
        assert not sink.spool.pending()  # delivered, so nothing spooled

    def test_tcp_stream_actually_arrives_newline_terminated(self, tmp_path):
        import socket
        import threading

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        received: list[bytes] = []

        def _accept():
            conn, _ = listener.accept()
            with conn:
                received.append(conn.recv(4096))

        server = threading.Thread(target=_accept, daemon=True)
        server.start()
        try:
            sink = SyslogSink(host="127.0.0.1", port=port, protocol="tcp", spool_root=tmp_path)
            sink.run(_ctx())
            server.join(timeout=5)
        finally:
            listener.close()

        assert received, "the TCP listener never received anything"
        assert received[0].endswith(b"\n")  # framing matters for stream syslog

    def test_a_spooled_event_is_replayed_down_the_same_path(self, tmp_path):
        import socket

        # First delivery fails (nothing listening on port 1) and spools.
        sink = SyslogSink(host="127.0.0.1", port=1, protocol="udp", spool_root=tmp_path, timeout=1)
        ctx = _ctx()
        try:
            sink.run(ctx)
        except OSError:
            pass
        # UDP to a closed port often succeeds locally; force the spool if so.
        if not sink.spool.pending():
            sink.spool.append(ctx.job_id, sink.build(ctx))
        assert sink.spool.pending()

        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        listener.settimeout(5)
        port = listener.getsockname()[1]
        try:
            sink.host, sink.port = "127.0.0.1", port  # the endpoint came back up
            delivered, pending = sink.replay()
            payload = listener.recv(4096).decode("utf-8")
        finally:
            listener.close()

        assert (delivered, pending) == (1, 0)
        assert ctx.job_id in payload
        assert not sink.spool.pending()


class TestSpoolSurvivesACorruptEntry:
    """The spool exists for when delivery is already going wrong, so it has
    to tolerate a crash mid-write. A half-written entry used to raise out
    of drain() — stranding every undelivered event queued behind it,
    permanently, because each replay died on the same file.
    """

    def test_a_corrupt_entry_does_not_strand_the_queue(self, tmp_path):
        from dlpduck.plugins.spool import Spool

        spool = Spool(tmp_path, "sink")
        spool.append("a" * 32, {"n": 1})
        (spool.dir / "9999999999.000000_bad.json").write_text('{"truncated": ')
        spool.append("b" * 32, {"n": 2})

        got: list[dict] = []
        delivered, pending = spool.drain(got.append)

        assert (delivered, pending) == (2, 0)
        assert [p["n"] for p in got] == [1, 2]  # both real events got through

    def test_the_corrupt_entry_is_kept_for_inspection_not_deleted(self, tmp_path):
        from dlpduck.plugins.spool import Spool

        spool = Spool(tmp_path, "sink")
        (spool.dir / "9999999999.000000_bad.json").write_text("{not json")
        spool.drain(lambda _payload: None)

        assert not spool.pending()
        assert [p.name for p in spool.dir.glob("*.corrupt")]  # evidence retained

    def test_entries_are_written_atomically(self, tmp_path):
        """A reader must see a whole entry or none — never a partial one."""
        from dlpduck.plugins.spool import Spool

        spool = Spool(tmp_path, "sink")
        spool.append("a" * 32, {"n": 1})

        assert not list(spool.dir.glob("*.partial"))
        for path in spool.pending():
            json.loads(path.read_text())  # every visible entry parses


class TestWebhookDeliveryAgainstARealServer:
    """The failure paths are covered above; this is the path that has to
    work, plus the HMAC signature a receiver is expected to verify."""

    def _server(self, status=200):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        received: dict = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                received["body"] = self.rfile.read(length)
                received["signature"] = self.headers.get("X-DLPDuck-Signature")
                self.send_response(status)
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.handle_request, daemon=True).start()
        return server, received

    def test_a_payload_actually_arrives(self, tmp_path):
        server, received = self._server()
        port = server.server_address[1]
        sink = WebhookSink(url=f"http://127.0.0.1:{port}/hook", spool_root=tmp_path)

        sink.run(_ctx(job_id="c" * 32))
        server.server_close()

        assert json.loads(received["body"])["job_id"] == "c" * 32
        assert not sink.spool.pending()  # delivered, nothing spooled

    def test_the_signature_is_an_hmac_of_the_exact_body(self, tmp_path, monkeypatch):
        import hashlib
        import hmac as hmac_mod

        monkeypatch.setenv("DLPDUCK_WEBHOOK_SECRET", "shared-secret")
        server, received = self._server()
        port = server.server_address[1]
        sink = WebhookSink(
            url=f"http://127.0.0.1:{port}/hook",
            secret_env="DLPDUCK_WEBHOOK_SECRET",
            spool_root=tmp_path,
        )

        sink.run(_ctx())
        server.server_close()

        expected = hmac_mod.new(
            b"shared-secret", received["body"], hashlib.sha256
        ).hexdigest()
        assert received["signature"] == expected

    def test_an_error_status_spools_and_raises(self, tmp_path):
        server, _ = self._server(status=500)
        port = server.server_address[1]
        sink = WebhookSink(url=f"http://127.0.0.1:{port}/hook", spool_root=tmp_path)

        with pytest.raises(RuntimeError, match="HTTP 500"):
            sink.run(_ctx())
        server.server_close()

        assert len(sink.spool.pending()) == 1  # kept for replay

    def test_a_non_http_url_is_refused_at_construction(self, tmp_path):
        for url in ("file:///etc/passwd", "ftp://host/x", "gopher://host"):
            with pytest.raises(ValueError, match="http"):
                WebhookSink(url=url, spool_root=tmp_path)


class TestPluginConfigErrors:
    def test_a_plugin_that_rejects_its_config_fails_at_load(self, tmp_path):
        with pytest.raises(PluginConfigError, match="rejected its config"):
            load_plugins(
                [{"name": "webhook", "args": {"nonexistent_option": 1}}], spool_root=tmp_path
            )

    def test_a_plugin_whose_constructor_validates_surfaces_that_message(self, tmp_path):
        with pytest.raises(PluginConfigError, match="rejected its config|http"):
            load_plugins(
                [{"name": "webhook", "args": {}}], spool_root=tmp_path  # url is required
            )


class TestWebhookRefusesRedirects:
    """A sink delivers where the operator configured, or it fails.

    urllib followed 301/302 by default and carried custom headers to the
    new host, so the signature leaked. Worse, a 200 from that host read
    as a successful delivery: the configured SIEM got nothing, nothing
    spooled, and the pipeline recorded the event as delivered. Alerts
    disappearing silently is the one failure mode a sink must not have.
    """

    def _server(self, handler_cls):
        import threading
        from http.server import HTTPServer

        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def _redirecting_handler(self, code: int, target: str):
        from http.server import BaseHTTPRequestHandler

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(code)
                self.send_header("Location", target)
                self.end_headers()

            def log_message(self, *args):
                pass

        return Handler

    @pytest.mark.parametrize("code", [301, 302, 307, 308])
    def test_a_redirect_is_an_error_not_a_second_request(self, tmp_path, code):
        received = []
        from http.server import BaseHTTPRequestHandler

        class Elsewhere(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(dict(self.headers))
                self.send_response(200)
                self.end_headers()

            do_GET = do_POST

            def log_message(self, *args):
                pass

        elsewhere = self._server(Elsewhere)
        target = f"http://127.0.0.1:{elsewhere.server_port}/collect"
        origin = self._server(self._redirecting_handler(code, target))
        try:
            sink = WebhookSink(
                url=f"http://127.0.0.1:{origin.server_port}/hook",
                spool_root=tmp_path,
            )
            with pytest.raises(RuntimeError, match="refusing to follow"):
                sink.deliver({"job_id": "a" * 32})

            assert received == [], "the payload reached a host nobody configured"
        finally:
            origin.shutdown()
            elsewhere.shutdown()

    def test_the_signing_secret_never_reaches_the_redirect_target(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("WEBHOOK_SECRET", "s3cret-shared-with-one-endpoint")
        seen = []
        from http.server import BaseHTTPRequestHandler

        class Elsewhere(BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append(self.headers.get("X-DLPDuck-Signature"))
                self.send_response(200)
                self.end_headers()

            do_GET = do_POST

            def log_message(self, *args):
                pass

        elsewhere = self._server(Elsewhere)
        origin = self._server(
            self._redirecting_handler(307, f"http://127.0.0.1:{elsewhere.server_port}/x")
        )
        try:
            sink = WebhookSink(
                url=f"http://127.0.0.1:{origin.server_port}/hook",
                secret_env="WEBHOOK_SECRET",
                spool_root=tmp_path,
            )
            with pytest.raises(RuntimeError):
                sink.deliver({"job_id": "a" * 32})

            assert seen == []
        finally:
            origin.shutdown()
            elsewhere.shutdown()

    def test_a_normal_delivery_still_succeeds(self, tmp_path):
        """The handler must not break the ordinary path it wraps."""
        from http.server import BaseHTTPRequestHandler

        bodies = []

        class Ok(BaseHTTPRequestHandler):
            def do_POST(self):
                bodies.append(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = self._server(Ok)
        try:
            sink = WebhookSink(url=f"http://127.0.0.1:{server.server_port}/hook")
            sink.deliver({"job_id": "b" * 32})
            assert json.loads(bodies[0])["job_id"] == "b" * 32
        finally:
            server.shutdown()

    def test_a_redirect_is_never_read_as_a_successful_delivery(self, tmp_path):
        """The failure that matters: the real endpoint gets nothing, and
        the pipeline believes the event was delivered."""
        from http.server import BaseHTTPRequestHandler

        class AlwaysOk(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(200)
                self.end_headers()

            do_GET = do_POST

            def log_message(self, *args):
                pass

        elsewhere = self._server(AlwaysOk)
        origin = self._server(
            self._redirecting_handler(302, f"http://127.0.0.1:{elsewhere.server_port}/x")
        )
        try:
            sink = WebhookSink(
                url=f"http://127.0.0.1:{origin.server_port}/hook", spool_root=tmp_path
            )
            ctx = _ctx()
            with pytest.raises(Exception):
                sink.run(ctx)

            assert sink.spool.pending(), "an undelivered event must be spooled, not lost"
        finally:
            origin.shutdown()
            elsewhere.shutdown()
