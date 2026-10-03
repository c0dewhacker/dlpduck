"""The console's query surface: jobs-list filters, search filters, value
correlation, and CSV export — each with the permission its results need."""

import csv
import io

from tests.test_console_app import _csrf_token, _login, env  # noqa: F401 — env is a fixture


def _rows(resp) -> list[list[str]]:
    return list(csv.reader(io.StringIO(resp.text)))


def _events(env, kind):  # noqa: F811 — env is the fixture value here
    return [e for e in env["pipeline"].audit.events(limit=500) if e["event"] == kind]


class TestJobsListFilters:
    def test_filter_by_hits(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "inv1")
        with_hits = client.get("/jobs?flagged=yes").text
        without = client.get("/jobs?flagged=no").text
        assert "card.pdf" in with_hits and "clean.pdf" not in with_hits
        assert "clean.pdf" in without and "card.pdf" not in without

    def test_a_rule_filter_needs_hit_permission(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "viewer1")
        assert client.get("/jobs?rule=pan.generic").status_code == 403

    def test_an_unknown_severity_is_a_400_not_a_500(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "viewer1")
        assert client.get("/jobs?min_severity=SEVERE").status_code == 400


class TestExport:
    def test_jobs_export_is_csv_and_audited(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "inv1")
        resp = client.get("/jobs?format=csv")

        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        assert resp.headers["content-disposition"].startswith("attachment")
        header, *rows = _rows(resp)
        assert header[:2] == ["received_at", "job_id"]
        assert {r[1] for r in rows} == {env["clean_job"], env["sensitive_job"]}
        [event] = _events(env, "ui.export")
        assert (event["what"], event["rows"], event["actor"]) == ("jobs", 2, "inv1")

    def test_a_viewer_export_omits_rule_ids(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "viewer1")
        header, *rows = _rows(client.get("/jobs?format=csv"))
        rule_column = header.index("rule_ids")
        assert all(r[rule_column] == "" for r in rows)

    def test_spreadsheet_formulas_are_neutralised(self):
        from dlpduck.console.queries import _csv_cell

        assert _csv_cell("=HYPERLINK(\"http://x\")") == "'=HYPERLINK(\"http://x\")"
        assert _csv_cell("+1") == "'+1" and _csv_cell("@SUM(A1)") == "'@SUM(A1)"
        assert _csv_cell("ordinary.pdf") == "ordinary.pdf"

    def test_search_export_withholds_contained_snippets(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "inv1")
        header, *rows = _rows(client.get("/search?q=card&format=csv"))
        [row] = rows
        assert row[header.index("snippet")] == "[withheld]"


class TestSearchFilters:
    def test_syntax_and_filters_reach_the_query(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "admin1")
        link = f"/jobs/{env['sensitive_job']}"
        assert link in client.get('/search?q="card"+-memo&flagged=yes').text
        assert link not in client.get("/search?q=card&flagged=no").text
        assert link not in client.get("/search?q=card+-file").text

    def test_a_query_of_only_exclusions_is_explained(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "admin1")
        assert "at least one term" in client.get("/search?q=-card").text

    def test_filters_are_audited(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "admin1")
        client.get("/search?q=card&rule=pan.generic")
        [event] = _events(env, "ui.search")
        assert event["filters"] == {"rule": "pan.generic"}


class TestCorrelation:
    def _digest(self, env):  # noqa: F811
        from dlpduck.reprocess import latest_index_rows

        [row] = latest_index_rows(env["pipeline"].index_root, job_ids=[env["sensitive_job"]])
        return row["hits"][0]["match_hmac"]

    def test_a_hit_links_to_its_correlation(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "inv1")
        page = client.get(f"/jobs/{env['sensitive_job']}").text
        assert f"/correlate?hmac={self._digest(env)}" in page

    def test_an_auditor_can_follow_a_digest(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "aud1")
        resp = client.get(f"/correlate?hmac={self._digest(env)}")
        assert resp.status_code == 200
        assert f"/jobs/{env['sensitive_job']}" in resp.text
        assert "4111 1111 1111 1111" not in resp.text
        [event] = _events(env, "ui.correlate")
        assert event["match_hmac"] == self._digest(env)

    def test_a_viewer_cannot_correlate(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "viewer1")
        assert client.get(f"/correlate?hmac={self._digest(env)}").status_code == 403

    def test_looking_up_a_typed_value_never_puts_it_in_a_url(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "inv1")
        token = _csrf_token(client.get("/correlate").text)

        resp = client.post("/correlate", data={"value": "4111-1111-1111-1111", "csrf_token": token},
                           follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == f"/correlate?hmac={self._digest(env)}"
        [event] = _events(env, "ui.correlate_lookup")
        assert "query" not in event  # hashed by default

    def test_an_auditor_cannot_look_up_a_typed_value(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "aud1")
        page = client.get("/correlate").text
        assert 'name="value"' not in page
        assert client.post("/correlate", data={"value": "x", "csrf_token": "x"}).status_code == 403

    def test_a_malformed_digest_is_reported_inline(self, env):  # noqa: F811
        client = env["client"]
        _login(client, "inv1")
        resp = client.get("/correlate?hmac=not-a-digest")
        assert resp.status_code == 200
        assert "32 hex characters" in resp.text
