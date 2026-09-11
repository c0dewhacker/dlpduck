"""The logging level is meant to be safe to turn up in production; content
tracing is not, and exists specifically as the exception. These tests pin
the one property that makes that exception safe: DLPDUCK_TRACE_CONTENT_OUTPUT
does nothing unless the logger is *actually* at DEBUG, and DEBUG does
nothing to content tracing unless the flag is *also* explicitly set. Either
one alone must stay inert.
"""

from __future__ import annotations

import logging

import pytest

from dlpduck.tracing import configure_logging, content_trace_enabled


@pytest.fixture(autouse=True)
def _restore_dlpduck_logger_level():
    """content_trace_enabled() reads the live level of the "dlpduck"
    logger — restore it so one test's level doesn't leak into the next.
    """
    logger = logging.getLogger("dlpduck")
    original = logger.level
    yield
    logger.setLevel(original)


class TestContentTraceIsDoubleGated:
    def test_off_by_default(self, monkeypatch):
        monkeypatch.delenv("DLPDUCK_TRACE_CONTENT_OUTPUT", raising=False)
        logging.getLogger("dlpduck").setLevel(logging.INFO)
        assert content_trace_enabled() is False

    def test_debug_level_alone_is_not_enough(self, monkeypatch):
        """The scenario the double gate exists for: an operator turns on
        DEBUG to see what a stuck job is doing. That must never, by
        itself, start writing document text into logs.
        """
        monkeypatch.delenv("DLPDUCK_TRACE_CONTENT_OUTPUT", raising=False)
        logging.getLogger("dlpduck").setLevel(logging.DEBUG)
        assert content_trace_enabled() is False

    def test_flag_alone_is_not_enough(self, monkeypatch):
        """The other half: setting the flag must not override a
        production log level that's above DEBUG."""
        monkeypatch.setenv("DLPDUCK_TRACE_CONTENT_OUTPUT", "true")
        logging.getLogger("dlpduck").setLevel(logging.INFO)
        assert content_trace_enabled() is False

    def test_both_together_enable_it(self, monkeypatch):
        monkeypatch.setenv("DLPDUCK_TRACE_CONTENT_OUTPUT", "true")
        logging.getLogger("dlpduck").setLevel(logging.DEBUG)
        assert content_trace_enabled() is True

    @pytest.mark.parametrize("value", ["1", "true", "True", "TRUE", "yes", "on"])
    def test_recognised_truthy_spellings(self, monkeypatch, value):
        monkeypatch.setenv("DLPDUCK_TRACE_CONTENT_OUTPUT", value)
        logging.getLogger("dlpduck").setLevel(logging.DEBUG)
        assert content_trace_enabled() is True

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "banana"])
    def test_unrecognised_or_falsy_values_stay_off(self, monkeypatch, value):
        monkeypatch.setenv("DLPDUCK_TRACE_CONTENT_OUTPUT", value)
        logging.getLogger("dlpduck").setLevel(logging.DEBUG)
        assert content_trace_enabled() is False

    def test_a_more_verbose_level_than_debug_still_counts(self, monkeypatch):
        """isEnabledFor(DEBUG) is true for anything at or below DEBUG, not
        only an exact match — a level someone configured more verbosely
        must still permit content tracing when the flag is set."""
        monkeypatch.setenv("DLPDUCK_TRACE_CONTENT_OUTPUT", "true")
        logging.getLogger("dlpduck").setLevel(5)
        assert content_trace_enabled() is True


class TestConfigureLogging:
    def test_default_level_is_info(self, monkeypatch):
        monkeypatch.delenv("DLPDUCK_LOG_LEVEL", raising=False)
        root = logging.getLogger()
        original_handlers, original_level = list(root.handlers), root.level
        try:
            root.handlers.clear()
            configure_logging()
            assert root.level == logging.INFO
        finally:
            root.handlers.clear()
            root.handlers.extend(original_handlers)
            root.setLevel(original_level)

    def test_debug_level_is_honoured(self, monkeypatch):
        monkeypatch.setenv("DLPDUCK_LOG_LEVEL", "debug")  # case-insensitive
        root = logging.getLogger()
        original_handlers, original_level = list(root.handlers), root.level
        try:
            root.handlers.clear()
            configure_logging()
            assert root.level == logging.DEBUG
        finally:
            root.handlers.clear()
            root.handlers.extend(original_handlers)
            root.setLevel(original_level)

    def test_unrecognised_level_fails_closed(self, monkeypatch):
        monkeypatch.setenv("DLPDUCK_LOG_LEVEL", "not-a-real-level")
        with pytest.raises(SystemExit, match="NOT-A-REAL-LEVEL"):
            configure_logging()
