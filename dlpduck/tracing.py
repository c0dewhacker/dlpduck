"""Runtime log level, and a deliberately double-gated switch for logging
actual document content.

DEBUG is meant to be safe to turn on in production to see what a stuck
job is doing — masked hit values, page/rule/timing detail, never a raw
document. Document content is exactly what masking.py, DLPHit (no raw
match field), and "Rules for plugin authors" #1 in the README all exist
to keep out of anywhere less access-controlled than the purgeable content
store — and a log stream is usually the *least* access-controlled, longest
-retained thing in a deployment (container logs routinely get shipped to
a central aggregator nobody scoped for this).

So content tracing needs two independent switches, not one:
DLPDUCK_LOG_LEVEL=DEBUG alone must never start writing document text into
logs, and DLPDUCK_TRACE_CONTENT_OUTPUT=true alone must not override a
production log level. Both have to be set, deliberately, at the same time.
"""

from __future__ import annotations

import logging
import os

_TRUTHY = {"1", "true", "yes", "on"}


def configure_logging() -> None:
    """Call once, at process startup. Refuses an unrecognised level rather
    than silently falling back to a default — the same fail-closed stance
    as everywhere else config gets read.
    """
    level_name = os.environ.get("DLPDUCK_LOG_LEVEL", "INFO").strip().upper()
    level = logging.getLevelName(level_name)
    if not isinstance(level, int):
        raise SystemExit(
            f"DLPDUCK_LOG_LEVEL={level_name!r} is not a recognised level — "
            "use DEBUG, INFO, WARNING, ERROR, or CRITICAL"
        )
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def content_trace_enabled() -> bool:
    """True only when BOTH hold: the root "dlpduck" logger is actually at
    DEBUG (or more verbose) — checked live, not just "was DLPDUCK_LOG_LEVEL
    set to DEBUG", so a handler-level filter still wins — and
    DLPDUCK_TRACE_CONTENT_OUTPUT is explicitly truthy. A caller gated on
    this is expected to also guard the (often expensive) formatting of
    whatever it's about to log, not just the log call itself.
    """
    if not logging.getLogger("dlpduck").isEnabledFor(logging.DEBUG):
        return False
    return os.environ.get("DLPDUCK_TRACE_CONTENT_OUTPUT", "").strip().lower() in _TRUTHY
