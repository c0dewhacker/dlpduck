"""The index is the one store meant to be permanent, so it has to survive
the program that writes it changing shape.

Parquet files are written per assessment and read back with a single glob,
which means a release that adds a column is reading its own new files
alongside every old one. Without union_by_name that read fails outright —
not for the old rows, for the whole query — so the first schema addition
after a deployment goes live would take the jobs list, job detail, search
and reprocess with it.
"""

from pathlib import Path

import pyarrow.parquet as pq
import pytest

from dlpduck.config import Config
from dlpduck.pipeline import Pipeline
from dlpduck.reindex import indexed_job_ids
from dlpduck.reprocess import latest_index_rows
from dlpduck.search import search
from tests.pdf_factory import write_pdf

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
    src = tmp_path / "drops"
    src.mkdir()
    return Config.model_validate(
        {
            "source": {"name": "t", "path": str(src), "metadata_format": "none"},
            "destination": {
                "archive": str(tmp_path / "archive"),
                "quarantine": str(tmp_path / "quarantine"),
                "work_dir": str(tmp_path / "work"),
            },
            "extraction": {"isolate_worker": False, "native_min_chars": 0},
            "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
        }
    )


def _pdf(path: Path, lines: list[str]) -> Path:
    return write_pdf(path, lines)


def _write_legacy_row(pipeline, *, job_id: str, drop: list[str]):
    """Forge a row as an older release would have written it: the current
    row minus columns that release did not have yet."""
    [current] = pipeline.index_root.glob("dt=*/*.parquet")
    table = pq.read_table(current)
    rows = table.to_pylist()
    rows[0]["job_id"] = job_id
    import pyarrow as pa

    legacy = pa.Table.from_pylist(rows, schema=table.schema).drop_columns(drop)
    out = current.parent / f"{job_id}_0001.parquet"
    pq.write_table(legacy, out)
    return out


class TestAnAddedColumnDoesNotBreakHistory:
    def _ingest(self, tmp_path, config):
        pipeline = Pipeline(config)
        ctx = pipeline.run_job(
            _pdf(tmp_path / "doc.pdf", ["ordinary memo content"]),
            None,
            config.destination.work_dir / "_processing",
        )
        return pipeline, ctx.job_id

    def test_rows_written_before_the_column_existed_still_read(self, tmp_path, config):
        pipeline, current_id = self._ingest(tmp_path, config)
        legacy_id = "0" * 32
        _write_legacy_row(pipeline, job_id=legacy_id, drop=["release_pending"])

        rows = latest_index_rows(pipeline.index_root)

        assert {r["job_id"] for r in rows} == {current_id, legacy_id}

    def test_the_missing_column_reads_as_null_not_an_error(self, tmp_path, config):
        pipeline, _ = self._ingest(tmp_path, config)
        legacy_id = "0" * 32
        _write_legacy_row(pipeline, job_id=legacy_id, drop=["release_pending"])

        rows = {r["job_id"]: r for r in latest_index_rows(pipeline.index_root)}

        assert rows[legacy_id]["release_pending"] is None
        # and NULL must behave as "no release pending", since the concept
        # did not exist when that row was written.
        assert not rows[legacy_id]["release_pending"]

    def test_several_columns_can_be_missing_at_once(self, tmp_path, config):
        pipeline, _ = self._ingest(tmp_path, config)
        legacy_id = "1" * 32
        _write_legacy_row(
            pipeline, job_id=legacy_id, drop=["release_pending", "supersedes_seq", "audit_fields"]
        )

        rows = {r["job_id"]: r for r in latest_index_rows(pipeline.index_root)}

        assert legacy_id in rows
        assert rows[legacy_id]["supersedes_seq"] is None

    def test_search_still_joins_across_mixed_schemas(self, tmp_path, config):
        pipeline, current_id = self._ingest(tmp_path, config)
        _write_legacy_row(pipeline, job_id="2" * 32, drop=["release_pending"])

        response = search(pipeline.content_root, pipeline.index_root, "memo")

        # The legacy row has no content-store entry, so it cannot match —
        # what matters is that the query runs at all.
        assert [r.job_id for r in response.results] == [current_id]

    def test_reindex_still_sees_which_jobs_are_indexed(self, tmp_path, config):
        pipeline, current_id = self._ingest(tmp_path, config)
        legacy_id = "3" * 32
        _write_legacy_row(pipeline, job_id=legacy_id, drop=["release_pending"])

        assert indexed_job_ids(pipeline.index_root) == {current_id, legacy_id}


class TestTheConsoleRendersLegacyRows:
    """A row missing a column must not just parse — the screens built on it
    have to render, and a NULL must not surface as the word "None"."""

    @pytest.fixture
    def console(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        from dlpduck.console.app import create_app
        from dlpduck.console.auth import hash_password

        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
        monkeypatch.setenv("DLPDUCK_SESSION_SECRET", "test-session-secret-not-for-production")
        src = tmp_path / "drops"
        src.mkdir()
        cfg = Config.model_validate(
            {
                "source": {"name": "t", "path": str(src), "metadata_format": "none"},
                "destination": {
                    "archive": str(tmp_path / "archive"),
                    "quarantine": str(tmp_path / "quarantine"),
                    "work_dir": str(tmp_path / "work"),
                },
                "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
                "console": {
                    "auth": {
                        "users": [
                            {
                                "username": "admin1",
                                "password_hash": hash_password("pw"),
                                "role": "dlp_admin",
                            }
                        ]
                    }
                },
            }
        )
        pipeline = Pipeline(cfg)
        pipeline.run_job(
            _pdf(tmp_path / "doc.pdf", ["ordinary memo content"]),
            None,
            cfg.destination.work_dir / "_processing",
        )
        legacy_id = "4" * 32
        _write_legacy_row(pipeline, job_id=legacy_id, drop=["release_pending"])

        client = TestClient(create_app(cfg, pipeline))
        client.post("/login", data={"username": "admin1", "password": "pw"})
        return client, legacy_id

    def test_the_jobs_list_and_overview_still_render(self, console):
        client, _ = console
        assert client.get("/jobs").status_code == 200
        assert client.get("/").status_code == 200

    def test_the_legacy_job_detail_page_renders(self, console):
        client, legacy_id = console
        assert client.get(f"/jobs/{legacy_id}").status_code == 200

    def test_a_null_column_is_not_shown_as_the_word_none(self, console):
        client, legacy_id = console
        body = client.get(f"/jobs/{legacy_id}").text
        marker = "<dt>release pending</dt><dd>"
        rendered = body.split(marker)[1].split("</dd>")[0]
        assert rendered.strip() in {"yes", "no"}

    def test_a_legacy_job_is_treated_as_having_no_release_pending(self, console):
        """The concept did not exist when the row was written, so NULL must
        not be mistaken for a pending release — that would wrongly gate the
        PDF behind the quarantined tier."""
        client, legacy_id = console
        body = client.get(f"/jobs/{legacy_id}").text
        assert "release pending</dt><dd>no" in body.replace("\n", "")
