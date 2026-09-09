"""The CLI is where an operator does the irreversible things — purge,
retention --apply, release — so its exit codes, its dry-run defaults, and
its refusals matter as much as the library code underneath. This module
drives the real commands through Click's runner rather than calling the
functions directly, so option names and wiring are covered too.
"""

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from dlpduck.cli import main
from tests.pdf_factory import encrypted_pdf, make_pdf, write_pdf

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DLPDUCK_HMAC_KEY", "test-key-not-for-production")
    src = tmp_path / "drops"
    src.mkdir()
    config_path = tmp_path / "config.yaml"
    config_path.write_text(f"""
source:
  name: cli-test
  path: {src}
  metadata_format: none
destination:
  archive: {tmp_path / "archive"}
  quarantine: {tmp_path / "quarantine"}
  work_dir: {tmp_path / "work"}
extraction:
  isolate_worker: false
  native_min_chars: 0
dlp:
  rules:
    - include: {DEFAULT_RULES_PATH}
""")
    return {"config": config_path, "tmp": tmp_path, "src": src}


def _pdf(path: Path, lines: list[str]) -> Path:
    return write_pdf(path, lines)


def _ingest(env, runner, name="doc.pdf", lines=("An ordinary memo.",)) -> str:
    """Run one document through the real pipeline and return its job id."""
    from dlpduck.config import load_config
    from dlpduck.pipeline import Pipeline

    config = load_config(env["config"])
    pipeline = Pipeline(config)
    staging = config.destination.work_dir / "_processing"
    ctx = pipeline.run_job(_pdf(env["tmp"] / name, list(lines)), None, staging)
    return ctx.job_id


class TestValidateConfig:
    def test_valid_config_exits_zero_and_lists_rules(self, env, runner):
        result = runner.invoke(main, ["validate-config", "--config", str(env["config"])])
        assert result.exit_code == 0, result.output
        assert "rules loaded" in result.output
        assert "pan.generic" in result.output

    def test_missing_config_file_is_a_clean_error(self, runner, tmp_path):
        result = runner.invoke(main, ["validate-config", "--config", str(tmp_path / "nope.yaml")])
        assert result.exit_code != 0

    def test_bad_rule_regex_fails_validation(self, env, runner, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(f"""
source: {{name: t, path: {env["src"]}, metadata_format: none}}
destination:
  archive: {tmp_path / "a"}
  quarantine: {tmp_path / "q"}
  work_dir: {tmp_path / "w"}
dlp:
  rules:
    - id: broken.rule
      name: Broken
      pattern: '([unclosed'
""")
        result = runner.invoke(main, ["validate-config", "--config", str(bad)])
        assert result.exit_code == 1
        assert "INVALID" in result.output


class TestScan:
    def test_scan_reports_hits_without_writing_anything(self, env, runner):
        pdf = _pdf(env["tmp"] / "card.pdf", ["Card 4111 1111 1111 1111 on file"])
        result = runner.invoke(main, ["scan", str(pdf), "--config", str(env["config"])])

        assert result.exit_code == 0, result.output
        assert "pan.generic" in result.output
        # The line dump deliberately shows the extracted text — inspecting a
        # document you already have in hand is the entire point of `scan`.
        # What must still be masked is the HIT, because that is the shape
        # that gets stored and forwarded everywhere else.
        hit_line = next(line for line in result.output.splitlines() if "pan.generic" in line)
        assert "•" in hit_line
        assert "4111 1111 1111 1111" not in hit_line
        # "Nothing is written" is the documented contract — hold it to that.
        assert not (env["tmp"] / "archive").exists() or not list(
            (env["tmp"] / "archive").glob("dt=*/*.pdf")
        )

    def test_clean_document_reports_no_hits(self, env, runner):
        pdf = _pdf(env["tmp"] / "clean.pdf", ["An ordinary memo about lunch."])
        result = runner.invoke(main, ["scan", str(pdf), "--config", str(env["config"])])
        assert result.exit_code == 0
        assert "no hits" in result.output


class TestPurgeContentCommand:
    def test_malformed_job_id_is_refused_and_deletes_nothing(self, env, runner):
        _ingest(env, runner)
        content = env["tmp"] / "work" / "content"
        before = list(content.glob("dt=*/*.parquet"))
        assert before

        result = runner.invoke(
            main,
            ["purge-content", "*", "--config", str(env["config"]), "--reason", "oops"],
        )

        assert result.exit_code == 1
        assert "32 hex characters" in result.output
        assert list(content.glob("dt=*/*.parquet")) == before

    def test_soft_purge_removes_content_and_leaves_the_pdf(self, env, runner):
        job_id = _ingest(env, runner)
        result = runner.invoke(
            main,
            ["purge-content", job_id, "--config", str(env["config"]), "--reason", "wrong doc"],
        )
        assert result.exit_code == 0, result.output
        assert "purged content" in result.output
        assert not list((env["tmp"] / "work" / "content").glob("dt=*/*.parquet"))
        assert list((env["tmp"] / "archive").glob("dt=*/*.pdf"))  # PDF survives

    def test_hard_purge_also_removes_the_pdf(self, env, runner):
        job_id = _ingest(env, runner)
        result = runner.invoke(
            main,
            [
                "purge-content", job_id,
                "--config", str(env["config"]),
                "--reason", "erasure request",
                "--hard",
            ],
        )
        assert result.exit_code == 0, result.output
        assert not list((env["tmp"] / "archive").glob("dt=*/*.pdf"))

    def test_purge_is_audited_with_the_reason_and_actor(self, env, runner):
        job_id = _ingest(env, runner)
        runner.invoke(
            main,
            [
                "purge-content", job_id,
                "--config", str(env["config"]),
                "--reason", "data subject request 42",
                "--actor", "alice",
            ],
        )
        events = _audit_events(env)
        purged = [e for e in events if e["event"] == "content.purged"]
        assert len(purged) == 1
        assert purged[0]["reason"] == "data subject request 42"
        assert purged[0]["actor"] == "alice"


class TestRetentionCommand:
    def _age_a_partition(self, env, store="content"):
        root = env["tmp"] / "work" / store
        [partition] = list(root.glob("dt=*"))
        old = root / "dt=2020-01-01"
        shutil.move(str(partition), str(old))
        return old

    def test_no_windows_configured_says_so_and_deletes_nothing(self, env, runner):
        _ingest(env, runner)
        result = runner.invoke(main, ["retention", "--config", str(env["config"])])
        assert result.exit_code == 0
        assert "no retention windows configured" in result.output

    def test_dry_run_is_the_default_and_removes_nothing(self, env, runner):
        _ingest(env, runner)
        old = self._age_a_partition(env)
        _add_retention(env, "documents_days: 30")

        result = runner.invoke(main, ["retention", "--config", str(env["config"])])

        assert result.exit_code == 0
        assert "dry run" in result.output
        assert old.exists()  # still there

    def test_apply_actually_deletes_and_audits(self, env, runner):
        _ingest(env, runner)
        old = self._age_a_partition(env)
        _add_retention(env, "documents_days: 30")

        result = runner.invoke(main, ["retention", "--config", str(env["config"]), "--apply"])

        assert result.exit_code == 0, result.output
        assert not old.exists()
        events = _audit_events(env)
        applied = [e for e in events if e["event"] == "retention.applied"]
        assert applied, "a deletion under policy must itself be recorded"


class TestVerifyAudit:
    def test_intact_chain_passes(self, env, runner):
        _ingest(env, runner)
        result = runner.invoke(main, ["verify-audit", "--config", str(env["config"])])
        assert result.exit_code == 0, result.output
        assert "chain intact" in result.output

    def test_tampering_is_detected_and_exits_nonzero(self, env, runner):
        _ingest(env, runner)
        [log] = (env["tmp"] / "work" / "audit").glob("dt=*/events.jsonl")
        lines = log.read_text().splitlines()
        event = json.loads(lines[0])
        event["disposition"] = "archive-but-actually-edited"
        lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
        log.write_text("\n".join(lines) + "\n")

        result = runner.invoke(main, ["verify-audit", "--config", str(env["config"])])

        assert result.exit_code != 0
        assert "break" in result.output.lower()


class TestRedactAudit:
    def _seq_of_first_event(self, env) -> int:
        return _audit_events(env)[0]["seq"]

    def test_redacts_and_the_chain_still_verifies(self, env, runner):
        _ingest(env, runner)
        seq = self._seq_of_first_event(env)

        redact = runner.invoke(
            main,
            [
                "redact-audit", "--config", str(env["config"]),
                "--seq", str(seq), "--field", "disposition",
                "--reason", "erasure request 41", "--actor", "admin",
            ],
        )
        assert redact.exit_code == 0, redact.output

        verify = runner.invoke(main, ["verify-audit", "--config", str(env["config"])])
        assert verify.exit_code == 0, verify.output
        assert "chain intact" in verify.output

    def test_verify_reports_the_redaction_even_though_it_passes(self, env, runner):
        """An auditor reading "chain intact" must not be left thinking
        nothing was ever removed."""
        _ingest(env, runner)
        seq = self._seq_of_first_event(env)
        runner.invoke(
            main,
            [
                "redact-audit", "--config", str(env["config"]),
                "--seq", str(seq), "--field", "disposition", "--reason", "r",
            ],
        )

        verify = runner.invoke(main, ["verify-audit", "--config", str(env["config"])])

        assert "redacted" in verify.output
        assert f"seq {seq}" in verify.output

    def test_the_reason_and_actor_land_in_the_trail(self, env, runner):
        _ingest(env, runner)
        seq = self._seq_of_first_event(env)
        runner.invoke(
            main,
            [
                "redact-audit", "--config", str(env["config"]),
                "--seq", str(seq), "--field", "disposition",
                "--reason", "erasure request 41", "--actor", "admin",
            ],
        )

        [recorded] = [e for e in _audit_events(env) if e["event"] == "audit.redacted"]
        assert recorded["reason"] == "erasure request 41"
        assert recorded["actor"] == "admin"

    def test_an_unknown_sequence_exits_nonzero(self, env, runner):
        _ingest(env, runner)
        result = runner.invoke(
            main,
            [
                "redact-audit", "--config", str(env["config"]),
                "--seq", "999999", "--field", "disposition", "--reason", "r",
            ],
        )
        assert result.exit_code != 0

    def test_chain_fields_are_refused(self, env, runner):
        _ingest(env, runner)
        seq = self._seq_of_first_event(env)
        result = runner.invoke(
            main,
            [
                "redact-audit", "--config", str(env["config"]),
                "--seq", str(seq), "--field", "hash", "--reason", "r",
            ],
        )
        assert result.exit_code != 0
        assert runner.invoke(
            main, ["verify-audit", "--config", str(env["config"])]
        ).exit_code == 0


class TestSearchCommand:
    def test_finds_an_ingested_document(self, env, runner):
        _ingest(env, runner, lines=["The quarterly roadmap is attached."])
        result = runner.invoke(
            main, ["search", "roadmap", "--config", str(env["config"])]
        )
        assert result.exit_code == 0, result.output
        assert "roadmap" in result.output.lower()

    def test_unknown_severity_is_a_clean_error_not_a_traceback(self, env, runner):
        _ingest(env, runner)
        result = runner.invoke(
            main, ["search", "memo", "--config", str(env["config"]), "--severity", "NOPE"]
        )
        assert result.exit_code == 1
        assert "unknown severity" in result.output

    def test_search_is_audited(self, env, runner):
        _ingest(env, runner, lines=["The quarterly roadmap is attached."])
        runner.invoke(main, ["search", "roadmap", "--config", str(env["config"])])
        events = _audit_events(env)
        searches = [e for e in events if e["event"] == "ui.search"]
        assert len(searches) == 1
        assert "query" not in searches[0]
        assert len(searches[0]["terms_hmac"]) == 32


class TestReprocessCommand:
    def test_preview_is_the_default_and_writes_nothing(self, env, runner):
        _ingest(env, runner)
        index = env["tmp"] / "work" / "index"
        before = sorted(p.name for p in index.glob("dt=*/*.parquet"))

        result = runner.invoke(main, ["reprocess", "--config", str(env["config"])])

        assert result.exit_code == 0, result.output
        assert "preview only" in result.output
        assert sorted(p.name for p in index.glob("dt=*/*.parquet")) == before

    def test_commit_reports_what_it_wrote(self, env, runner):
        _ingest(env, runner)
        result = runner.invoke(
            main, ["reprocess", "--config", str(env["config"]), "--commit"]
        )
        assert result.exit_code == 0, result.output
        assert "assessment" in result.output


class TestReleaseCommand:
    def test_releasing_a_job_with_nothing_pending_is_refused(self, env, runner):
        job_id = _ingest(env, runner)
        result = runner.invoke(
            main,
            ["release", job_id, "--config", str(env["config"]), "--reason", "reviewed"],
        )
        assert result.exit_code != 0
        assert "no release is pending" in result.output

    def test_releasing_an_unknown_job_is_refused(self, env, runner):
        _ingest(env, runner)
        result = runner.invoke(
            main,
            ["release", "0" * 32, "--config", str(env["config"]), "--reason", "x"],
        )
        assert result.exit_code != 0
        assert "not found" in result.output


class TestReplaySink:
    def test_unknown_sink_name_is_a_clean_error(self, env, runner):
        result = runner.invoke(main, ["replay-sink", "nosuch", "--config", str(env["config"])])
        assert result.exit_code == 1
        assert "no replayable sink" in result.output


class TestReindexCommand:
    def test_dry_run_reports_without_writing(self, env, runner):
        _ingest(env, runner)
        index = env["tmp"] / "work" / "index"
        shutil.rmtree(index)

        result = runner.invoke(main, ["reindex", "--config", str(env["config"])])

        assert result.exit_code == 0, result.output
        assert not index.exists() or not list(index.glob("dt=*/*.parquet"))

    def test_commit_rebuilds_the_index_from_content(self, env, runner):
        job_id = _ingest(env, runner)
        index = env["tmp"] / "work" / "index"
        shutil.rmtree(index)

        result = runner.invoke(main, ["reindex", "--config", str(env["config"]), "--commit"])

        assert result.exit_code == 0, result.output
        rebuilt = list(index.glob("dt=*/*.parquet"))
        assert rebuilt, "the index should have been rebuilt"
        assert any(job_id in p.name for p in rebuilt)


class TestConsoleHashPassword:
    def test_emits_an_argon2id_hash_for_the_given_password(self, runner):
        result = runner.invoke(main, ["console", "hash-password", "hunter2"])
        assert result.exit_code == 0
        assert result.output.strip().startswith("$argon2id$")

    def test_prompts_when_no_password_is_given_so_it_stays_out_of_shell_history(self, runner):
        result = runner.invoke(main, ["console", "hash-password"], input="hunter2\nhunter2\n")
        assert result.exit_code == 0
        assert "$argon2id$" in result.output


def _audit_events(env) -> list[dict]:
    out = []
    for log in (env["tmp"] / "work" / "audit").glob("dt=*/events.jsonl"):
        out += [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
    return out


def _add_retention(env, line: str) -> None:
    env["config"].write_text(env["config"].read_text() + f"\nretention:\n  {line}\n")


class TestTestRulesCommand:
    """Show what each rule matches in a corpus before production use."""

    def test_reports_per_rule_hit_counts_over_a_corpus(self, env, runner, tmp_path):
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        _pdf(corpus / "card.pdf", ["Card 4111 1111 1111 1111 on file"])
        _pdf(corpus / "clean.pdf", ["An ordinary memo about lunch."])

        result = runner.invoke(
            main, ["test-rules", "--corpus", str(corpus), "--config", str(env["config"])]
        )

        assert result.exit_code == 0, result.output
        assert "pan.generic" in result.output
        assert "hit(s)" in result.output

    def test_rule_filter_narrows_the_report(self, env, runner, tmp_path):
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        _pdf(corpus / "card.pdf", ["Card 4111 1111 1111 1111 on file"])

        result = runner.invoke(
            main,
            [
                "test-rules", "--corpus", str(corpus),
                "--config", str(env["config"]), "--rule", "uk.nhs",
            ],
        )

        assert result.exit_code == 0, result.output
        assert "pan.generic" not in result.output  # filtered out

    def test_an_empty_corpus_is_a_clean_error(self, env, runner, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        result = runner.invoke(
            main, ["test-rules", "--corpus", str(empty), "--config", str(env["config"])]
        )
        assert result.exit_code == 1
        assert "no .pdf files" in result.output

    def test_an_unreadable_document_is_skipped_not_fatal(self, env, runner, tmp_path):
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        _pdf(corpus / "good.pdf", ["An ordinary memo."])
        (corpus / "broken.pdf").write_bytes(b"this is not a PDF at all")

        result = runner.invoke(
            main, ["test-rules", "--corpus", str(corpus), "--config", str(env["config"])]
        )

        assert result.exit_code == 0, result.output
        assert "skipped" in result.output


class TestScanExitCodes:
    """Exit codes are the scriptable contract — a wrapper script has to be
    able to tell "clean" from "could not assess"."""

    def test_an_encrypted_document_exits_nonzero(self, env, runner, tmp_path):
        enc = tmp_path / "encrypted.pdf"
        enc.write_bytes(encrypted_pdf(make_pdf([["secret content"]])))

        result = runner.invoke(main, ["scan", str(enc), "--config", str(env["config"])])

        assert result.exit_code == 1
        assert "encrypted" in result.output
        assert "fail closed" in result.output


class TestMalformedDateOptions:
    def test_a_bad_start_date_is_a_clean_error_not_a_traceback(self, env, runner):
        result = runner.invoke(
            main, ["search", "memo", "--config", str(env["config"]), "--start", "garbage"]
        )
        assert result.exit_code == 1
        assert "YYYY-MM-DD" in result.output
        assert "Traceback" not in result.output

    def test_reprocess_rejects_a_bad_date_too(self, env, runner):
        result = runner.invoke(
            main, ["reprocess", "--config", str(env["config"]), "--end", "2026-13-45"]
        )
        assert result.exit_code == 1
        assert "YYYY-MM-DD" in result.output


class TestCliErrorPathsExitCleanly:
    """The branches an operator only meets when something is wrong. Each
    must print something actionable and exit non-zero — a traceback is
    not a refusal, and a zero exit code on a failed operation is worse.
    """

    def test_a_search_that_is_refused_exits_nonzero(self, env, runner):
        _ingest(env, runner)
        result = runner.invoke(
            main,
            ["search", "x" * 500, "--config", str(env["config"])],
        )
        assert result.exit_code != 0
        assert "invalid search" in result.output
        assert "Traceback" not in result.output

    def test_an_unknown_severity_is_refused(self, env, runner):
        _ingest(env, runner)
        result = runner.invoke(
            main,
            ["search", "memo", "--config", str(env["config"]), "--severity", "SEVERE"],
        )
        assert result.exit_code != 0
        assert "invalid search" in result.output

    def test_verify_audit_says_so_when_chaining_is_off(self, env, runner, tmp_path):
        _ingest(env, runner)
        config = tmp_path / "unchained.yaml"
        config.write_text(env["config"].read_text() + "\naudit:\n  integrity: none\n")

        result = runner.invoke(main, ["verify-audit", "--config", str(config)])

        assert result.exit_code == 0
        assert "nothing to verify" in result.output

    def test_replay_sink_names_the_sinks_it_knows(self, env, runner):
        result = runner.invoke(
            main, ["replay-sink", "no-such-sink", "--config", str(env["config"])]
        )
        assert result.exit_code != 0
        assert "no replayable sink" in result.output

    def test_validate_config_prints_warnings_without_failing(self, env, runner, tmp_path):
        """Warnings must not change the exit code CI gates on."""
        config = tmp_path / "warned.yaml"
        config.write_text(
            env["config"].read_text()
            + "\nretention:\n  audit_days: 30\n  documents_days: 365\n"
        )

        result = runner.invoke(main, ["validate-config", "--config", str(config)])

        assert result.exit_code == 0
        assert "warning(s)" in result.output
        assert "audit_days" in result.output

    def test_a_bind_the_console_cannot_listen_on_fails_validation(
        self, env, runner, tmp_path
    ):
        """Better here than in the daemon's first second of life."""
        config = tmp_path / "badbind.yaml"
        config.write_text(
            env["config"].read_text() + '\nconsole:\n  bind: "127.0.0.1:not-a-port"\n'
        )

        result = runner.invoke(main, ["validate-config", "--config", str(config)])

        assert result.exit_code == 1
        assert "INVALID" in result.output

    def test_an_ipv6_bind_validates(self, env, runner, tmp_path):
        config = tmp_path / "v6.yaml"
        config.write_text(env["config"].read_text() + '\nconsole:\n  bind: "[::1]:8080"\n')

        result = runner.invoke(main, ["validate-config", "--config", str(config)])

        assert result.exit_code == 0, result.output
