import threading
import time

import pytest

from dlpduck.engine import DLPEngine
from dlpduck.rules import Rule
from dlpduck.types import DocumentText, RuleBudgetExceeded, TextLine


def _line(n, page, on_page, on_page_total, text):
    return TextLine(
        line_number=n,
        page_number=page,
        line_on_page=on_page,
        lines_on_page=on_page_total,
        text=text,
        source="native",
    )


def _doc(pages: list[list[str]]) -> DocumentText:
    """pages = [["line0", "line1", ...], ["line0", ...], ...]"""
    doc = DocumentText(page_count=len(pages))
    n = 0
    for page_no, lines in enumerate(pages, start=1):
        total = len(lines)
        for on_page, text in enumerate(lines):
            doc.add_line(_line(n, page_no, on_page, total, text))
            n += 1
    return doc


def _rule(**overrides):
    cfg = {
        "id": "test.marker",
        "name": "Test marker",
        "pattern": r"MARK",
        "severity": "CRITICAL",
        "action": "quarantine",
    }
    cfg.update(overrides)
    return Rule(cfg)


class TestPositionalScope:
    """This is the exact bug the rebuild exists to fix: v1 tested line
    ranges against the document-global line_number, so a "header, lines
    0-5" rule only ever examined the first five lines of page 1. A banner
    repeated on every page's header was invisible past page 1.
    """

    def test_document_scope_only_matches_near_the_very_start(self):
        # Page 1 has 10 lines, so a page-2 header (global line ~11) is
        # outside a document-global 0-5 window — this is the OLD, buggy
        # behaviour, kept here as a control to contrast with the fix below.
        doc = _doc(
            [
                ["MARK header"] + [f"body {i}" for i in range(9)],
                ["MARK header page 2", "body"],
            ]
        )
        rule = _rule(line_scope="document", min_line=0, max_line=5)
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert len(hits) == 1
        assert hits[0].page_number == 1

    def test_page_scope_matches_the_header_on_every_page(self):
        doc = _doc(
            [
                ["MARK header"] + [f"body {i}" for i in range(9)],
                ["MARK header page 2", "body"],
            ]
        )
        rule = _rule(line_scope="page", min_line=0, max_line=2)
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        pages_hit = sorted(h.page_number for h in hits)
        assert pages_hit == [1, 2]

    def test_from_end_addresses_the_footer(self):
        doc = _doc([["body a", "body b", "body c", "MARK footer"]])
        rule = _rule(line_scope="page", from_end=True, min_line=0, max_line=0)
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert len(hits) == 1
        assert hits[0].line_on_page == 3

    def test_from_end_does_not_match_the_header(self):
        doc = _doc([["MARK header", "body b", "body c", "body d"]])
        rule = _rule(line_scope="page", from_end=True, min_line=0, max_line=0)
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert hits == []

    def test_no_range_matches_anywhere(self):
        doc = _doc([["far away"] + ["filler"] * 20 + ["MARK deep in the body"]])
        rule = _rule()  # no min_line/max_line at all
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert len(hits) == 1


class TestMatchExtraction:
    def test_capture_group_does_not_corrupt_the_match(self):
        # v1 used findall() + `match if isinstance(match, str) else match[0]`,
        # which returns the captured GROUP, not the full match, whenever the
        # pattern has one. finditer()+group(0) must return the whole match.
        doc = _doc([["Reference: ABC-1234 in file"]])
        rule = _rule(pattern=r"Reference: (ABC-\d+)")
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert len(hits) == 1
        # v1's bug returned the captured GROUP ("ABC-1234", 8 chars) instead
        # of the full match. Check the span directly rather than through
        # mask() (which drops punctuation/spaces from its bullet count).
        assert hits[0].end - hits[0].start == len("Reference: ABC-1234")

    def test_no_implicit_case_insensitivity(self):
        doc = _doc([["classified lowercase should not match"]])
        rule = _rule(pattern=r"CLASSIFIED")
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert hits == []

    def test_explicit_inline_flag_still_works(self):
        doc = _doc([["classified lowercase DOES match with inline flag"]])
        rule = _rule(pattern=r"(?i)CLASSIFIED")
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert len(hits) == 1


class TestValidatorsAndContext:
    def test_validator_suppresses_non_conforming_matches(self):
        doc = _doc([["card 4111111111111112 is invalid luhn"]])  # bad check digit
        rule = _rule(pattern=r"\b(?:\d[ -]?){12,18}\d\b", validator="luhn")
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert hits == []

    def test_requires_context_suppresses_without_nearby_label(self):
        doc = _doc([["12-34-56 appears with no label nearby"]])
        rule = _rule(
            pattern=r"\b\d{2}-\d{2}-\d{2}\b",
            requires_context={"pattern": r"(?i)account", "within_lines": 2},
        )
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert hits == []

    def test_requires_context_matches_when_label_is_within_window(self):
        doc = _doc([["Account number:", "12-34-56 here"]])
        rule = _rule(
            pattern=r"\b\d{2}-\d{2}-\d{2}\b",
            requires_context={"pattern": r"(?i)account", "within_lines": 2},
        )
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert len(hits) == 1


class TestDocumentScope:
    def test_document_scope_matches_across_a_line_break(self):
        # A value an OCR pass wrapped mid-token is invisible to a
        # line-scoped rule; document scope joins the text first.
        doc = _doc([["4111 1111", "1111 1111 wrapped across the line break"]])
        # \s (not just a literal space) so the pattern tolerates the "\n"
        # DocumentText.full_text joins lines with — the whole point of
        # scope="document" is bridging exactly that join.
        rule = _rule(pattern=r"\b(?:\d[\s-]?){12,18}\d\b", scope="document", validator="luhn")
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert len(hits) == 1

    def test_document_scope_hit_maps_back_to_the_correct_line(self):
        doc = _doc([["first line", "MARK is here", "third line"]])
        rule = _rule(scope="document")
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert len(hits) == 1
        assert hits[0].line_number == 1


class TestMaskingIntegration:
    def test_hit_never_carries_the_raw_value(self):
        doc = _doc([["MARK sensitive value"]])
        rule = _rule()
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert "MARK" not in hits[0].masked_text
        assert hits[0].masked_text == "•" * len("MARK")

    def test_mask_keep_is_per_rule(self):
        doc = _doc([["4111111111111111"]])
        rule = _rule(pattern=r"\d{16}", mask_keep=4)
        hits = DLPEngine([rule], hmac_key=b"k").scan(doc)
        assert hits[0].masked_text.endswith("1111")
        assert hits[0].masked_text.startswith("•")


class TestRuleBudget:
    """The budget guards against catastrophic backtracking. It used to be
    SIGALRM, which CPython only allows on the main thread — so it silently
    did nothing for the console, whose sync route handlers (reprocess,
    §8.4) run in a worker thread. It is now enforced by the regex module
    itself, on whatever thread the scan happens on.
    """

    CATASTROPHIC = r"(a+)+$"

    def _run_in_thread(self, fn):
        result: dict = {}

        def _target():
            try:
                result["value"] = fn()
            except Exception as exc:
                result["error"] = exc

        t = threading.Thread(target=_target)
        t.start()
        t.join(timeout=30)
        assert not t.is_alive(), "scan never returned — the budget did not fire"
        return result

    def test_scan_works_when_called_from_a_worker_thread(self):
        doc = _doc([["MARK sensitive value"]])
        engine = DLPEngine([_rule()], hmac_key=b"k", rule_budget_seconds=2.0)

        result = self._run_in_thread(lambda: engine.scan(doc))

        assert "error" not in result, result.get("error")
        assert len(result["value"]) == 1

    def test_catastrophic_pattern_is_stopped_on_the_main_thread(self):
        doc = _doc([["a" * 5000 + "b"]])
        engine = DLPEngine(
            [_rule(pattern=self.CATASTROPHIC)], hmac_key=b"k", rule_budget_seconds=0.5
        )
        with pytest.raises(RuleBudgetExceeded) as exc:
            engine.scan(doc)
        assert exc.value.rule_id == "test.marker"

    def test_catastrophic_pattern_is_stopped_in_a_worker_thread_too(self):
        # The case the old SIGALRM guard could not cover at all.
        doc = _doc([["a" * 5000 + "b"]])
        engine = DLPEngine(
            [_rule(pattern=self.CATASTROPHIC)], hmac_key=b"k", rule_budget_seconds=0.5
        )

        result = self._run_in_thread(lambda: engine.scan(doc))

        assert isinstance(result.get("error"), RuleBudgetExceeded)

    def test_budget_spans_the_document_not_each_line(self):
        # 40 lines that each backtrack: with a per-call timeout this would
        # be allowed 40 x the budget. The whole scan must fail well inside
        # a small multiple of one budget instead.
        doc = _doc([["a" * 3000 + "b"] * 40])
        engine = DLPEngine(
            [_rule(pattern=self.CATASTROPHIC)], hmac_key=b"k", rule_budget_seconds=0.5
        )
        started = time.monotonic()
        with pytest.raises(RuleBudgetExceeded):
            engine.scan(doc)
        assert time.monotonic() - started < 5

    def test_a_zero_budget_disables_the_guard(self):
        doc = _doc([["MARK here"]])
        engine = DLPEngine([_rule()], hmac_key=b"k", rule_budget_seconds=0)
        assert len(engine.scan(doc)) == 1


class TestHitOffsetsAreLineRelative:
    """A hit's start/end are read back much later — by the console's
    reveal — with only line_number for context. If they were offsets into
    the joined document text, that lookup would slice the wrong span of
    the wrong line, which is how reveal used to return empty (or worse,
    unrelated) text for every document-scope rule.
    """

    def test_line_scope_offsets_index_their_own_line(self):
        doc = _doc([["filler", "filler", "value MARK here"]])
        [hit] = DLPEngine([_rule()], hmac_key=b"k").scan(doc)
        line = doc.lines[hit.line_number]
        assert line.text[hit.start : hit.end] == "MARK"

    def test_document_scope_offsets_also_index_their_own_line(self):
        doc = _doc([["filler line one", "filler line two", "ACCOUNT SECRET-9876 here"]])
        rule = _rule(pattern=r"SECRET-\d+", scope="document")
        [hit] = DLPEngine([rule], hmac_key=b"k").scan(doc)

        line = doc.lines[hit.line_number]
        assert line.text[hit.start : hit.end] == "SECRET-9876"

    def test_a_value_wrapped_across_a_line_break_is_recoverable_whole(self):
        # The reason document scope exists. The end offset runs past this
        # line's length on purpose — slicing full_text from the line's own
        # offset recovers the value including the join.
        doc = _doc([["card 4111 1111", "1111 1111 trailing"]])
        rule = _rule(pattern=r"\b(?:\d[\s-]?){12,18}\d\b", scope="document", validator="luhn")
        [hit] = DLPEngine([rule], hmac_key=b"k").scan(doc)

        base = doc.offset_of(hit.line_number)
        recovered = doc.full_text[base + hit.start : base + hit.end]
        assert recovered.replace("\n", " ").replace(" ", "") == "4111111111111111"

    def test_offset_of_rejects_a_line_that_does_not_exist(self):
        doc = _doc([["only one line"]])
        with pytest.raises(IndexError):
            doc.offset_of(5)
