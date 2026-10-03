"""Query capability beyond a single literal: search syntax, filters shared
by search / the jobs list / correlation, and value correlation over the
permanent index."""

from pathlib import Path

import pytest

from dlpduck.config import Config
from dlpduck.content import purge_content
from dlpduck.correlate import digest_for, find
from dlpduck.pipeline import Pipeline
from dlpduck.reprocess import latest_index_rows
from dlpduck.search import IndexFilters, SearchError, parse_query, search
from tests.pdf_factory import write_pdf

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"
CARD = "4111 1111 1111 1111"


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
    src = tmp_path / "drops"
    src.mkdir()
    config = Config.model_validate({
        "source": {"name": "floor-3", "path": str(src), "metadata_format": "none"},
        "destination": {"archive": str(tmp_path / "a"), "quarantine": str(tmp_path / "q"),
                        "work_dir": str(tmp_path / "w")},
        "extraction": {"isolate_worker": False, "native_min_chars": 0},
        "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
    })
    pipeline = Pipeline(config)
    staging = config.destination.work_dir / "_processing"
    docs = {
        "card_memo": ["Quarterly invoice memo", f"Card {CARD} on file"],
        "card_draft": ["Draft invoice", f"Card {CARD.replace(' ', '-')} again"],
        "plain": ["Quarterly invoice", "nothing sensitive in the account number field"],
        "wrapped": ["The account", "number is withheld"],
    }
    jobs = {}
    for name, lines in docs.items():
        ctx = pipeline.run_job(write_pdf(tmp_path / f"{name}.pdf", lines), None, staging)
        jobs[name] = ctx.job_id
    return pipeline, jobs


def _search(pipeline, q, **kwargs):
    return {r.job_id for r in search(pipeline.content_root, pipeline.index_root, q, **kwargs).results}


class TestQuerySyntax:
    def test_terms_are_all_required(self, corpus):
        pipeline, jobs = corpus
        assert _search(pipeline, "quarterly invoice") == {jobs["card_memo"], jobs["plain"]}

    def test_a_phrase_must_appear_together(self, corpus):
        pipeline, jobs = corpus
        assert _search(pipeline, '"invoice memo"') == {jobs["card_memo"]}

    def test_a_phrase_matches_across_a_line_break(self, corpus):
        pipeline, jobs = corpus
        assert _search(pipeline, '"account number"') == {jobs["plain"], jobs["wrapped"]}

    def test_an_exclusion_removes_matches(self, corpus):
        pipeline, jobs = corpus
        assert _search(pipeline, "invoice -draft -memo") == {jobs["plain"]}

    def test_only_exclusions_is_refused(self):
        with pytest.raises(SearchError, match="at least one term"):
            parse_query("-draft")

    def test_parsing(self):
        assert parse_query('a "b c" -d -"e f" "unclosed g') == parse_query(
            'a "b c" -d -"e f" "unclosed g"'
        )
        parsed = parse_query('a "b c" -d')
        assert parsed.include == (("a",), ("b", "c"))
        assert parsed.exclude == (("d",),)

    def test_regex_syntax_in_a_term_is_literal(self, corpus):
        pipeline, _ = corpus
        assert _search(pipeline, ".*") == set()
        assert _search(pipeline, "(a|b)") == set()

    def test_the_snippet_flattens_a_wrapped_match(self, corpus):
        pipeline, jobs = corpus
        [result] = [r for r in search(pipeline.content_root, pipeline.index_root,
                                      '"account number"').results
                    if r.job_id == jobs["wrapped"]]
        assert "account number" in result.snippet.lower()
        assert "\n" not in result.snippet


class TestFilters:
    def test_by_rule(self, corpus):
        pipeline, jobs = corpus
        found = _search(pipeline, "card", filters=IndexFilters(rule_id="pan.generic"))
        assert found == {jobs["card_memo"], jobs["card_draft"]}

    def test_by_flagged(self, corpus):
        pipeline, jobs = corpus
        assert _search(pipeline, "invoice", filters=IndexFilters(flagged=False)) == {jobs["plain"]}

    def test_by_minimum_severity(self, corpus):
        pipeline, jobs = corpus
        found = _search(pipeline, "invoice", filters=IndexFilters(min_severity="LOW"))
        assert jobs["plain"] not in found and jobs["card_memo"] in found

    def test_by_source(self, corpus):
        pipeline, _ = corpus
        assert _search(pipeline, "invoice", filters=IndexFilters(source_name="elsewhere")) == set()

    def test_invalid_filters_are_refused(self):
        with pytest.raises(SearchError):
            IndexFilters(min_severity="SEVERE")
        with pytest.raises(SearchError):
            IndexFilters(disposition="failed")

    def test_the_jobs_list_shares_them(self, corpus):
        pipeline, jobs = corpus
        rows = latest_index_rows(pipeline.index_root, filters=IndexFilters(flagged=True))
        assert {r["job_id"] for r in rows} == {jobs["card_memo"], jobs["card_draft"]}


class TestCorrelation:
    def test_one_value_in_different_formatting_correlates(self, corpus):
        pipeline, jobs = corpus
        found = find(pipeline.index_root, digest_for(CARD, pipeline.config.hmac_key()))
        assert {h.job_id for h in found.hits} == {jobs["card_memo"], jobs["card_draft"]}
        assert found.documents == 2
        assert all("4111111111111111" not in h.masked_text for h in found.hits)  # masked only

    def test_from_a_hit_on_screen(self, corpus):
        pipeline, jobs = corpus
        [row] = latest_index_rows(pipeline.index_root, job_ids=[jobs["card_memo"]])
        digest = row["hits"][0]["match_hmac"]
        assert {h.job_id for h in find(pipeline.index_root, digest).hits} == {
            jobs["card_memo"], jobs["card_draft"],
        }

    def test_it_still_answers_after_content_is_purged(self, corpus):
        pipeline, jobs = corpus
        for job_id in jobs.values():
            purge_content(pipeline.content_root, job_id)
        found = find(pipeline.index_root, digest_for(CARD, pipeline.config.hmac_key()))
        assert found.documents == 2

    def test_a_malformed_digest_is_refused(self, corpus):
        pipeline, _ = corpus
        with pytest.raises(SearchError):
            find(pipeline.index_root, "' OR 1=1 --")

    def test_an_unknown_value_finds_nothing(self, corpus):
        pipeline, _ = corpus
        assert find(pipeline.index_root, digest_for("5500 0000 0000 0004", b"k")).hits == []
