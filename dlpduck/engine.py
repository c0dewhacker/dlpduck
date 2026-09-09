"""The DLP engine: run every rule against every line (or, for document-scope
rules, the joined text), collect every match, and mask before anything is
stored.
"""

from __future__ import annotations

import time

from dlpduck.masking import correlate, mask
from dlpduck.rules import Rule
from dlpduck.types import DLPHit, DocumentText, RuleBudgetExceeded, TextLine


class _Budget:
    """A per-rule, per-document wall-clock guard against catastrophic
    backtracking (ReDoS).

    This used to be SIGALRM, which CPython only permits from the main
    thread — so it silently did nothing for the console, which runs sync
    route handlers, including reprocessing, in a worker thread, leaving
    exactly the path that re-scans stored text with no guard at all. The
    `regex` module takes a `timeout` on each call and enforces it itself,
    on any thread, so the guard now holds everywhere.

    The budget spans the whole rule, not each call: a rule gets one
    deadline per document and every subsequent line's match must finish
    within what's left of it — otherwise a document with 10,000 lines
    would be allowed 10,000 times the configured budget.
    """

    __slots__ = ("deadline", "enabled")

    def __init__(self, seconds: float):
        self.enabled = seconds > 0
        self.deadline = time.monotonic() + seconds if self.enabled else 0.0

    def remaining(self) -> float | None:
        """Seconds left, or None when the budget is disabled. Raises once
        the deadline has already passed."""
        if not self.enabled:
            return None
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("rule budget exhausted")
        return left


class DLPEngine:
    def __init__(self, rules: list[Rule], hmac_key: bytes, rule_budget_seconds: float = 2.0):
        self.rules = rules
        self.key = hmac_key
        self.rule_budget_seconds = rule_budget_seconds

    def scan(self, text: DocumentText) -> list[DLPHit]:
        hits: list[DLPHit] = []
        for rule in self.rules:
            budget = _Budget(self.rule_budget_seconds)
            try:
                if rule.scope == "line":
                    hits.extend(self._scan_lines(rule, text, budget))
                else:
                    hits.extend(self._scan_document(rule, text, budget))
            except TimeoutError:
                raise RuleBudgetExceeded(rule.id) from None
        return hits

    def _scan_lines(self, rule: Rule, text: DocumentText, budget: _Budget) -> list[DLPHit]:
        out: list[DLPHit] = []
        for line in text.lines:
            if not rule.in_range(line):
                continue
            # finditer + group(0): capture groups no longer corrupt the
            # match the way v1's findall()-based extraction did.
            for m in rule.regex.finditer(line.text, timeout=budget.remaining()):
                raw = m.group(0)
                if not rule.validator(raw):
                    continue
                if rule.ctx_regex and not self._context_near(rule, text, line, budget):
                    continue
                out.append(self._hit(rule, line, m.start(), m.end(), raw))
        return out

    def _scan_document(self, rule: Rule, text: DocumentText, budget: _Budget) -> list[DLPHit]:
        # Line-scoped rules cannot see a value the OCR wrapped across a
        # line break. Document-scope rules run against the joined text and
        # map the offset back to a line, so the hit still has a position.
        out: list[DLPHit] = []
        for m in rule.regex.finditer(text.full_text, timeout=budget.remaining()):
            raw = m.group(0)
            if not rule.validator(raw):
                continue
            line = text.line_at(m.start())
            if rule.ctx_regex and not self._context_near(rule, text, line, budget):
                continue
            # Rebase onto the line the hit is recorded against. These
            # offsets are read back much later (the console's reveal) with
            # only line_number for context, so a document-global offset
            # would slice the wrong text — or nothing at all. An end past
            # the line's own length is fine and meaningful: it says the
            # value continued across the line break, which is exactly what
            # document scope exists to catch.
            base = text.offset_of(line.line_number)
            out.append(self._hit(rule, line, m.start() - base, m.end() - base, raw))
        return out

    def _context_near(
        self, rule: Rule, text: DocumentText, line: TextLine, budget: _Budget
    ) -> bool:
        lo = line.line_number - rule.ctx_window
        hi = line.line_number + rule.ctx_window
        for other in text.lines:
            if lo <= other.line_number <= hi and rule.ctx_regex.search(
                other.text, timeout=budget.remaining()
            ):
                return True
        return False

    def _hit(self, rule: Rule, line: TextLine, start: int, end: int, raw: str) -> DLPHit:
        return DLPHit(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            action=rule.action,
            page_number=line.page_number,
            line_number=line.line_number,
            line_on_page=line.line_on_page,
            start=start,
            end=end,
            masked_text=mask(raw, rule.mask_keep),
            match_hmac=correlate(raw, self.key),
            validator=rule.validator_name,
        )
