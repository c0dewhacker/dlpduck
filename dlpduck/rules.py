"""Rule definitions and the loader that turns config into compiled Rule
objects.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import regex
import yaml

from dlpduck.types import Severity, TextLine
from dlpduck.validators import get_validator

_VALID_ACTIONS = {"quarantine", "flag", "ignore"}
_VALID_SCOPES = {"line", "document"}
_VALID_LINE_SCOPES = {"page", "document"}


_VALID_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class RuleConfigError(ValueError):
    pass


class Rule:
    def __init__(self, cfg: dict[str, Any]):
        try:
            self.id: str = cfg["id"]
        except KeyError:
            raise RuleConfigError(f"rule is missing required field 'id': {cfg!r}") from None

        # Rule ids are reference keys, not free text: they end up in audit
        # events, in log lines, and in console markup. A shared ruleset is
        # exactly the kind of thing an operator copies in from someone
        # else, so the id is treated as untrusted input and constrained
        # here rather than escaped correctly at each of those points.
        if not isinstance(self.id, str) or not _VALID_RULE_ID.match(self.id):
            raise RuleConfigError(
                f"rule id {self.id!r} must be 1-64 characters of letters, digits, "
                "'.', '_' or '-', starting with a letter or digit"
            )

        try:
            self.name: str = cfg["name"]
            pattern: str = cfg["pattern"]
        except KeyError as exc:
            raise RuleConfigError(f"rule {self.id!r} is missing required field {exc}") from None

        try:
            # `regex`, not `re`: a superset of the same syntax, and the
            # only one that can enforce a match timeout on any thread
            # (see engine._Budget). No implicit flags.
            self.regex = regex.compile(pattern)
        except regex.error as exc:
            raise RuleConfigError(f"rule {self.id!r} has an invalid pattern: {exc}") from None

        self.severity = Severity(cfg.get("severity", "MEDIUM"))

        action = cfg.get("action", "flag")
        if action not in _VALID_ACTIONS:
            raise RuleConfigError(
                f"rule {self.id!r} has action={action!r}, must be one of {sorted(_VALID_ACTIONS)}"
            )
        self.action = action

        scope = cfg.get("scope", "line")
        if scope not in _VALID_SCOPES:
            raise RuleConfigError(
                f"rule {self.id!r} has scope={scope!r}, must be one of {sorted(_VALID_SCOPES)}"
            )
        self.scope = scope

        line_scope = cfg.get("line_scope", "document")
        if line_scope not in _VALID_LINE_SCOPES:
            raise RuleConfigError(
                f"rule {self.id!r} has line_scope={line_scope!r}, "
                f"must be one of {sorted(_VALID_LINE_SCOPES)}"
            )
        self.line_scope = line_scope
        self.from_end = bool(cfg.get("from_end", False))
        self.min_line = cfg.get("min_line")
        self.max_line = cfg.get("max_line")

        validator_name = cfg.get("validator", "none")
        try:
            self.validator = get_validator(validator_name)
        except ValueError as exc:
            raise RuleConfigError(f"rule {self.id!r}: {exc}") from None
        self.validator_name = validator_name if validator_name != "none" else None

        self.mask_keep: int = int(cfg.get("mask_keep", 0))  # masking is opt in

        ctx = cfg.get("requires_context")
        if ctx:
            try:
                self.ctx_regex: regex.Pattern | None = regex.compile(ctx["pattern"])
            except regex.error as exc:
                raise RuleConfigError(
                    f"rule {self.id!r} has an invalid requires_context pattern: {exc}"
                ) from None
            self.ctx_window = int(ctx.get("within_lines", 2))
        else:
            self.ctx_regex = None
            self.ctx_window = 0

        self.enabled = bool(cfg.get("enabled", True))

    def in_range(self, line: TextLine) -> bool:
        if self.min_line is None and self.max_line is None:
            return True
        if self.line_scope == "page":
            pos = (
                line.lines_on_page - 1 - line.line_on_page
                if self.from_end
                else line.line_on_page
            )
        else:
            pos = line.line_number
        if self.min_line is not None and pos < self.min_line:
            return False
        if self.max_line is not None and pos > self.max_line:
            return False
        return True

    def __repr__(self) -> str:
        return f"Rule(id={self.id!r}, severity={self.severity.value}, action={self.action!r})"


BUILTIN_RULES_DIR = Path(__file__).parent / "builtin_rules"
BUILTIN_PREFIX = "builtin:"


def _resolve_include(include: str, relative_to: Path) -> Path:
    """Turn an `include:` value into a path.

    `builtin:default.yaml` names a ruleset that ships inside the package.
    That indirection exists because the baseline ruleset has to be
    reachable from an installed wheel, where there is no repository
    checkout and so no `rules/default.yaml` beside the config — the
    shape the quick start used to hand people, which worked only if they
    had cloned. Anything else is a path relative to the file doing the
    including, as before.
    """
    if include.startswith(BUILTIN_PREFIX):
        name = include[len(BUILTIN_PREFIX) :]
        # A config is trusted input, but an operator pasting a path into
        # one shouldn't be able to reach outside the packaged directory by
        # accident — and a rule file read from somewhere unexpected is a
        # rule file someone else may control.
        candidate = (BUILTIN_RULES_DIR / name).resolve()
        if not candidate.is_relative_to(BUILTIN_RULES_DIR.resolve()):
            raise RuleConfigError(
                f"builtin ruleset {name!r} resolves outside the packaged rules directory"
            )
        return candidate
    return (relative_to / include).resolve()


def builtin_rulesets() -> list[str]:
    """The `builtin:` names this install ships, for error messages and
    `dlpduck test-rules`."""
    if not BUILTIN_RULES_DIR.is_dir():
        return []
    return sorted(p.name for p in BUILTIN_RULES_DIR.glob("*.yaml"))


def load_ruleset(entries: list[dict[str, Any]], base_dir: Path) -> list[Rule]:
    """Flatten `include:` directives and apply by-id overrides, last write wins,
    preserving first-seen order: "include this file
    from your own and redefine by id".
    """
    collected: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    def process(items: list[dict[str, Any]], relative_to: Path) -> None:
        for item in items:
            if "include" in item:
                include_path = _resolve_include(str(item["include"]), relative_to)
                if not include_path.is_file():
                    hint = ""
                    if str(item["include"]).startswith(BUILTIN_PREFIX):
                        hint = f" — this install ships {', '.join(builtin_rulesets()) or 'none'}"
                    raise RuleConfigError(f"rule include not found: {include_path}{hint}")
                with open(include_path, encoding="utf-8") as f:
                    doc = yaml.safe_load(f) or {}
                process(doc.get("rules", []), include_path.parent)
            else:
                rid = item.get("id")
                if not rid:
                    raise RuleConfigError(f"rule entry is missing 'id': {item!r}")
                if rid not in collected:
                    order.append(rid)
                collected[rid] = item

    process(entries, base_dir)

    rules: list[Rule] = []
    for rid in order:
        rule = Rule(collected[rid])
        if rule.enabled:
            rules.append(rule)
    return rules


def ruleset_version(rules: list[Rule]) -> str:
    """A stable identifier for exactly this compiled ruleset. Two runs
    with the same effective rules (same ids, patterns, scopes, actions —
    disabled rules already excluded) get the same version regardless of
    process or file ordering; any real change gets a different one. Used
    to stamp every assessment with what produced it, and to decide
    whether reprocessing a job actually changes anything worth writing.
    """
    fingerprint = sorted(
        (
            r.id,
            r.regex.pattern,
            r.severity.value,
            r.action,
            r.scope,
            r.line_scope,
            r.from_end,
            r.min_line,
            r.max_line,
            r.validator_name,
            r.mask_keep,
            r.ctx_regex.pattern if r.ctx_regex else None,
            r.ctx_window,
        )
        for r in rules
    )
    canonical = json.dumps(fingerprint, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
