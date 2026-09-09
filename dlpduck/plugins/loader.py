"""Turn `plugins:` config entries into Plugin instances. A built-in is
selected by `name`; anything else needs an explicit `path` (dotted
module.Class), matching v1's PluginPipelineRunner import mechanism.
"""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path
from typing import Any

from dlpduck.plugins.base import Plugin

BUILTIN_PLUGINS: dict[str, str] = {
    "syslog": "dlpduck.plugins.sinks.SyslogSink",
    "webhook": "dlpduck.plugins.sinks.WebhookSink",
    "static_enrich": "dlpduck.plugins.enrich.StaticEnrich",
}


class PluginConfigError(ValueError):
    pass


def load_plugins(entries: list[dict[str, Any]], spool_root: Path) -> list[Plugin]:
    plugins: list[Plugin] = []
    for entry in entries:
        if not entry.get("enabled", True):
            continue

        plugin_key = entry.get("name")
        dotted = entry.get("path") or BUILTIN_PLUGINS.get(plugin_key or "")
        if not dotted:
            raise PluginConfigError(
                f"plugin entry {entry!r} needs a known builtin 'name' "
                f"({sorted(BUILTIN_PLUGINS)}) or an explicit 'path'"
            )

        try:
            module_name, class_name = dotted.rsplit(".", 1)
            cls = getattr(importlib.import_module(module_name), class_name)
        except (ImportError, AttributeError, ValueError) as exc:
            raise PluginConfigError(f"cannot load plugin {dotted!r}: {exc}") from exc

        kwargs = dict(entry.get("args", {}))
        params = inspect.signature(cls.__init__).parameters
        # A subclass that forwards **kwargs to a base __init__ (every
        # built-in sink does, to reach SpoolingSink) won't list "critical"
        # or "spool_root" by name in its own signature — accept either a
        # named parameter or a **kwargs catch-all as "this class wants it".
        accepts_anything = any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
        )
        # Bound as arguments rather than closed over: this runs inside the
        # loop over entries, and a closure over the loop's variables is a
        # bug waiting for the first person who defers the call.
        def _wants(key: str, _params=params, _any=accepts_anything) -> bool:
            return key in _params or _any

        if _wants("name") and "name" not in kwargs:
            kwargs["name"] = plugin_key
        if _wants("critical") and "critical" not in kwargs:
            kwargs["critical"] = entry.get("critical", False)
        if _wants("spool_root") and "spool_root" not in kwargs:
            kwargs["spool_root"] = spool_root

        try:
            plugin = cls(**kwargs)
        except TypeError as exc:
            raise PluginConfigError(f"plugin {dotted!r} rejected its config: {exc}") from exc
        plugins.append(plugin)
    return plugins
