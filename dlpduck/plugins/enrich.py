"""Enrich-phase plugins run before disposition, so they can attach context
that shapes routing — a real deployment would look this up in LDAP/AD; this
is a static stand-in with the same shape, useful on its own for a small
site and as a template for a directory-backed one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dlpduck.plugins.base import Plugin
from dlpduck.types import JobContext


class StaticEnrich(Plugin):
    """Look `ctx.metadata[key_field]` up in a static mapping and merge the
    result into `ctx.audit_fields`. Unmatched keys are left alone — a
    missing directory entry is not itself an error.
    """

    phase = "enrich"
    name = "static_enrich"

    def __init__(
        self,
        mapping: dict[str, dict[str, Any]],
        key_field: str = "device_id",
        name: str | None = None,
        critical: bool = False,
        spool_root: Path | None = None,  # accepted for loader uniformity, unused
    ):
        self.mapping = mapping
        self.key_field = key_field
        self.critical = critical
        if name:
            self.name = name

    def run(self, ctx: JobContext) -> None:
        key = ctx.metadata.get(self.key_field)
        if key is None:
            return
        fields = self.mapping.get(key)
        if fields:
            ctx.audit_fields.update(fields)
