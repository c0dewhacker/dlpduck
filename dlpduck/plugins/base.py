"""One plugin protocol, two phases — enrich runs before disposition so it
can inform routing, emit runs after commit. Deliberately not two separate
class hierarchies for "plugins" and "audit sinks": a sink is just an
emit-phase plugin.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Literal

from dlpduck.types import JobContext

logger = logging.getLogger("dlpduck.plugins")


class Plugin(ABC):
    phase: Literal["enrich", "emit"]
    critical: bool = False
    name: str = "plugin"

    @abstractmethod
    def run(self, ctx: JobContext) -> None:
        """Mutate ctx or trigger a side effect."""


class PluginError(Exception):
    def __init__(self, plugin_name: str, phase: str, original: Exception):
        super().__init__(f"{plugin_name} ({phase}): {original}")
        self.plugin_name = plugin_name
        self.phase = phase
        self.original = original


class PluginRunner:
    def __init__(self, plugins: list[Plugin], audit):
        self.by_phase: dict[str, list[Plugin]] = {"enrich": [], "emit": []}
        for p in plugins:
            self.by_phase[p.phase].append(p)
        self.audit = audit

    def run(self, ctx: JobContext, phase: str) -> None:
        for plugin in self.by_phase.get(phase, []):
            try:
                plugin.run(ctx)
            except Exception as exc:
                # A failure here is itself an audited fact — a gap in a
                # forwarded sink is provable from the local record, not
                # merely suspected.
                self.audit.append(
                    "plugin.failed",
                    job_id=ctx.job_id,
                    plugin=plugin.name,
                    phase=phase,
                    error=str(exc),
                )
                ctx.errors.append(f"{plugin.name}: {exc}")
                if plugin.critical:
                    raise PluginError(plugin.name, phase, exc) from exc
                logger.warning("non-critical plugin %s failed: %s", plugin.name, exc)
