"""Property-based tests for the invariants the whole design rests on.

The example-based suite proves these hold for the cases someone thought
of. That is the weakness: "never store the raw value" and "a hit's
offsets point at what it matched" are claims about *all* inputs, and the
inputs here are documents an organisation did not write and an attacker
may have. Hypothesis generates the cases nobody thought of — unicode
digits, combining marks, zero-width joiners, values that are almost long
enough to reveal a tail, offsets at the exact end of a line.

Each test states a property in its name. A failure here is a
counter-example, and Hypothesis will have shrunk it to the smallest input
that still breaks it.
"""

from __future__ import annotations

import string

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from dlpduck.engine import DLPEngine
from dlpduck.masking import _normalize, correlate, mask
from dlpduck.rules import Rule
from dlpduck.types import DocumentText, Severity, TextLine

# Deliberately wider than "text a scanner produces": the point is to find
# the input nobody wrote a test for.
TEXT = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),  # surrogates aren't valid in a str payload
    ),
    max_size=200,
)
ALNUM_ISH = st.text(alphabet=string.ascii_letters + string.digits + " -._/", max_size=80)
# Generated directly rather than filtered out of TEXT: `assume(no alnum)`
# discards almost everything the wide strategy produces, which Hypothesis
# rightly flags as distorting the domain — and made the test flaky.
NON_ALNUM = st.text(alphabet=" \t\n-_.,:;!?/\\|@#$%^&*()[]{}<>\"'`~+=", max_size=40)
KEYS = st.binary(min_size=1, max_size=64)


def _doc(lines: list[str]) -> DocumentText:
    doc = DocumentText()
    for i, text in enumerate(lines):
        doc.add_line(
            TextLine(
                line_number=i,
                page_number=1,
                line_on_page=i,
                lines_on_page=len(lines),
                text=text,
                source="native",
                confidence=None,
            )
        )
    doc.page_count = 1
    return doc


class TestMaskingNeverLeaks:
    """Verify masking never exposes the original value."""

    @given(raw=TEXT, keep=st.integers(min_value=-5, max_value=50))
    def test_the_mask_never_contains_the_whole_value(self, raw, keep):
        alnum = [c for c in raw if c.isalnum()]
        assume(len(alnum) >= 1)
        masked = mask(raw, keep)
        # The claim is about what a reader could recover: the alphanumeric
        # run is the value, and the mask must never reproduce all of it.
        assert "".join(alnum) != masked

    @given(raw=TEXT, keep=st.integers(min_value=-5, max_value=50))
    def test_the_mask_reveals_at_most_the_requested_tail(self, raw, keep):
        masked = mask(raw, keep)
        revealed = [c for c in masked if c != "•"]
        assert len(revealed) <= max(keep, 0)

    @given(
        value=st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=12),
        slack=st.integers(min_value=0, max_value=6),
    )
    def test_a_short_value_never_reveals_a_tail(self, value, slack):
        """A 5-character value with keep=4 would be 80% cleartext. Rules
        opt into a tail; short matches still don't get one. Constructed so
        `keep` is always large enough relative to the value that a tail
        would be reckless — filtering for that discards most inputs."""
        keep = max(1, len(value) - 3 + slack)
        assert set(mask(value, keep)) <= {"•"}

    @given(raw=TEXT, keep=st.integers(min_value=0, max_value=50))
    def test_the_mask_length_matches_the_value_length(self, raw, keep):
        """A mask that changed length would leak how long the value was
        relative to what it padded to — and worse, would not line up with
        the re-derivation check that reveal uses."""
        alnum = [c for c in raw if c.isalnum()]
        assume(alnum)
        assert len(mask(raw, keep)) == len(alnum)

    @given(raw=TEXT, keep=st.integers(min_value=0, max_value=50))
    def test_masking_is_deterministic(self, raw, keep):
        assert mask(raw, keep) == mask(raw, keep)

    @given(raw=NON_ALNUM)
    def test_a_value_with_no_alphanumerics_masks_to_nothing(self, raw):
        assert mask(raw, 4) == ""


class TestCorrelationIsKeyedAndStable:
    """Correlation must answer "the same value appeared elsewhere"
    without anything storing the value."""

    @given(raw=TEXT, key=KEYS)
    def test_the_digest_is_only_ever_hex(self, raw, key):
        """Whatever went in, what comes out carries none of it: 32 hex
        characters and nothing else."""
        digest = correlate(raw, key)
        assert len(digest) == 32
        assert set(digest) <= set(string.hexdigits.lower())

    @given(raw=ALNUM_ISH.filter(lambda s: len(s) >= 4), key=KEYS)
    def test_the_digest_never_contains_the_value(self, raw, key):
        assert raw.lower() not in correlate(raw, key)

    @given(raw=TEXT, key=KEYS)
    def test_the_same_value_and_key_always_agree(self, raw, key):
        assert correlate(raw, key) == correlate(raw, key)

    @given(raw=TEXT, a=KEYS, b=KEYS)
    def test_a_different_key_gives_a_different_digest(self, raw, a, b):
        assume(a != b)
        assert correlate(raw, a) != correlate(raw, b)

    @given(raw=TEXT, key=KEYS)
    def test_formatting_does_not_defeat_correlation(self, raw, key):
        """"4111 1111 1111 1111" and "4111-1111-1111-1111" are the same
        card. If punctuation changed the digest, correlation would miss
        the case it exists for."""
        spaced = " ".join(raw)
        assert correlate(raw, key) == correlate(spaced, key)

    @given(raw=TEXT, key=KEYS)
    def test_case_does_not_defeat_correlation(self, raw, key):
        """casefold, not lower: `'ß'.upper()` is `'SS'`, and a normaliser
        built on lower() would call those two different values."""
        assert correlate(raw.upper(), key) == correlate(raw.lower(), key)

    @given(
        a=st.text(alphabet="abcßñüΩд日", min_size=1, max_size=12),
        b=st.text(alphabet="abcßñüΩд日", min_size=1, max_size=12),
        key=KEYS,
    )
    def test_different_non_ascii_values_do_not_all_collide(self, a, b, key):
        """The bug this file was written to find. The normaliser was
        ASCII-only, so every wholly non-Latin value reduced to the empty
        string and shared one digest — a Cyrillic name, a Japanese address
        and a Greek identifier all correlating as "the same value in 3
        documents". Not a near miss: a confident wrong answer, in most of
        the world's deployments."""
        assume(_normalize(a) != _normalize(b))
        assert correlate(a, key) != correlate(b, key)


class TestScanningHoldsItsInvariants:
    """The engine's output is what everything downstream trusts: the
    index, the console, every sink, and reveal's re-derivation."""

    def _engine(self, pattern: str, **cfg) -> DLPEngine:
        rule = Rule({"id": "p.rule", "name": "Prop", "pattern": pattern, **cfg})
        return DLPEngine(rules=[rule], hmac_key=b"property-test-key")

    @given(lines=st.lists(TEXT, min_size=1, max_size=8))
    @settings(max_examples=200, deadline=None)
    def test_no_hit_ever_carries_the_raw_match(self, lines):
        engine = self._engine(r"\w+")
        for hit in engine.scan(_doc(lines)):
            source = lines[hit.line_number]
            matched = source[hit.start : hit.end]
            alnum = "".join(c for c in matched if c.isalnum())
            if alnum:
                assert hit.masked_text != alnum

    @given(lines=st.lists(TEXT, min_size=1, max_size=8))
    @settings(max_examples=200, deadline=None)
    def test_offsets_always_point_at_what_was_matched(self, lines):
        """Reveal re-derives a value from these offsets and checks it
        reproduces the stored mask. Offsets that drift make reveal either
        fail or — much worse — show an unrelated slice of the document."""
        engine = self._engine(r"\w+")
        for hit in engine.scan(_doc(lines)):
            source = lines[hit.line_number]
            assert 0 <= hit.start <= hit.end <= len(source)
            matched = source[hit.start : hit.end]
            assert mask(matched, 0) == hit.masked_text

    @given(lines=st.lists(TEXT, min_size=1, max_size=6))
    @settings(max_examples=200, deadline=None)
    def test_scanning_arbitrary_text_never_raises(self, lines):
        """A document is untrusted input. The engine failing on one is a
        job that fails closed at best and a crashed daemon at worst."""
        self._engine(r"[\w.@-]+").scan(_doc(lines))

    @given(
        lines=st.lists(ALNUM_ISH, min_size=1, max_size=10),
        min_line=st.integers(min_value=0, max_value=9),
    )
    @settings(max_examples=200, deadline=None)
    def test_a_positional_window_is_never_matched_outside(self, lines, min_line):
        """Positional windows are the reason this project exists; a rule
        that fires outside its window is the feature not working."""
        engine = self._engine(
            r"[A-Za-z0-9]+", line_scope="document", min_line=min_line
        )
        for hit in engine.scan(_doc(lines)):
            assert hit.line_number >= min_line

    @given(lines=st.lists(ALNUM_ISH, min_size=1, max_size=8))
    @settings(max_examples=200, deadline=None)
    def test_every_hit_maps_to_a_line_that_exists(self, lines):
        engine = self._engine(r"[A-Za-z0-9]+", scope="document")
        doc = _doc(lines)
        for hit in engine.scan(doc):
            assert 0 <= hit.line_number < len(doc.lines)

    @given(lines=st.lists(ALNUM_ISH, min_size=1, max_size=8))
    @settings(max_examples=100, deadline=None)
    def test_the_same_document_always_yields_the_same_verdict(self, lines):
        """Reprocessing compares a fresh scan against a stored one. A
        non-deterministic engine would produce phantom escalations."""
        engine = self._engine(r"[A-Za-z0-9]+")
        doc = _doc(lines)
        first = [(h.start, h.end, h.masked_text, h.match_hmac) for h in engine.scan(doc)]
        second = [(h.start, h.end, h.masked_text, h.match_hmac) for h in engine.scan(doc)]
        assert first == second

    @given(lines=st.lists(ALNUM_ISH, min_size=1, max_size=8))
    @settings(max_examples=100, deadline=None)
    def test_an_ignore_action_still_records_a_masked_hit(self, lines):
        """`ignore` means "do not route on this", not "store it raw"."""
        engine = self._engine(r"[A-Za-z0-9]+", action="ignore")
        for hit in engine.scan(_doc(lines)):
            assert set(hit.masked_text) <= {"•"}


class TestSeverityOrderingIsTotal:
    """Disposition asks for the highest severity across hits, so the
    ordering has to be a real one — not just comparable in the cases the
    example tests happen to use."""

    @given(a=st.sampled_from(list(Severity)), b=st.sampled_from(list(Severity)))
    def test_ranking_is_antisymmetric(self, a, b):
        if a.rank < b.rank:
            assert b.rank > a.rank
        elif a.rank == b.rank:
            assert a is b

    @given(severities=st.lists(st.sampled_from(list(Severity)), min_size=1, max_size=10))
    def test_the_highest_is_never_beaten_by_a_member(self, severities):
        highest = max(severities, key=lambda s: s.rank)
        assert all(s.rank <= highest.rank for s in severities)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
