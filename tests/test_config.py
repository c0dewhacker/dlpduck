"""Config is validated eagerly — a bad rule or an unset HMAC key must fail
the process at boot, not on document 4,000. See §11.
"""

from pathlib import Path

import pytest

from dlpduck.config import (
    Config,
    ConfigError,
    ConsoleConfig,
    config_warnings,
    load_config,
    validate_config,
)

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "dlpduck" / "builtin_rules" / "default.yaml"


def _write_config(tmp_path: Path, extra_dlp: str = "") -> Path:
    src = tmp_path / "drops"
    src.mkdir()
    text = f"""
source:
  name: test
  path: {src}
  metadata_format: none
destination:
  archive: {tmp_path / "archive"}
  quarantine: {tmp_path / "quarantine"}
  work_dir: {tmp_path / "work"}
dlp:
  rules:
    - include: {DEFAULT_RULES_PATH}
{extra_dlp}
"""
    path = tmp_path / "config.yaml"
    path.write_text(text)
    return path


class TestLoadConfig:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_config(tmp_path / "does_not_exist.yaml")

    def test_missing_required_section_raises(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text("source:\n  name: x\n  path: /tmp\n")  # no destination
        with pytest.raises(ConfigError):
            load_config(path)

    def test_valid_config_loads(self, tmp_path):
        path = _write_config(tmp_path)
        config = load_config(path)
        assert config.source.name == "test"
        assert config.audit.integrity == "chained"  # default

    def test_config_dir_used_to_resolve_relative_rule_includes(self, tmp_path):
        path = _write_config(tmp_path)
        config = load_config(path)
        rules = config.load_rules()
        assert any(r.id == "pan.generic" for r in rules)


class TestValidateConfig:
    def test_missing_hmac_key_env_fails_validation(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DLPDUCK_HMAC_KEY", raising=False)
        path = _write_config(tmp_path)
        with pytest.raises(ConfigError, match="DLPDUCK_HMAC_KEY"):
            validate_config(path)

    def test_valid_config_with_hmac_key_passes(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "a-real-key")
        path = _write_config(tmp_path)
        config = validate_config(path)
        assert config.destination.archive.is_dir()  # created by validate_config

    def test_missing_source_path_fails(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "a-real-key")
        path = _write_config(tmp_path)
        import shutil

        shutil.rmtree(tmp_path / "drops")
        with pytest.raises(ConfigError, match="source.path"):
            validate_config(path)

    def test_invalid_rule_regex_fails_validation_not_silently_dropped(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "a-real-key")
        src = tmp_path / "drops"
        src.mkdir()
        path = tmp_path / "config.yaml"
        path.write_text(
            f"""
source:
  name: test
  path: {src}
  metadata_format: none
destination:
  archive: {tmp_path / "archive"}
  quarantine: {tmp_path / "quarantine"}
  work_dir: {tmp_path / "work"}
dlp:
  rules:
    - id: broken
      name: Broken
      pattern: "("
"""
        )
        with pytest.raises(ConfigError, match="invalid pattern"):
            validate_config(path)

    def test_empty_ruleset_fails_validation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "a-real-key")
        src = tmp_path / "drops"
        src.mkdir()
        path = tmp_path / "config.yaml"
        path.write_text(
            f"""
source:
  name: test
  path: {src}
  metadata_format: none
destination:
  archive: {tmp_path / "archive"}
  quarantine: {tmp_path / "quarantine"}
  work_dir: {tmp_path / "work"}
"""
        )
        with pytest.raises(ConfigError, match="empty"):
            validate_config(path)

    def test_metadata_allowlist_defaults_to_empty(self, tmp_path, monkeypatch):
        # No fields configured -> everything the printer sends is dropped,
        # not silently kept. This is the §6.4 default.
        monkeypatch.setenv("DLPDUCK_HMAC_KEY", "a-real-key")
        path = _write_config(tmp_path)
        config = validate_config(path)
        assert config.source.metadata_fields == []


def _minimal(tmp_path: Path) -> dict:
    src = tmp_path / "drops"
    src.mkdir(exist_ok=True)
    return {
        "source": {"name": "t", "path": str(src), "metadata_format": "none"},
        "destination": {
            "archive": str(tmp_path / "archive"),
            "quarantine": str(tmp_path / "quarantine"),
            "work_dir": str(tmp_path / "work"),
        },
        "dlp": {"rules": [{"include": str(DEFAULT_RULES_PATH)}]},
    }


class TestUmask:
    """Everything DLPDuck writes is sensitive and inherits the process
    umask, so it's set once from config at startup rather than chmod'd at
    each of the dozen places that create a file."""

    def _restore(self, previous):
        import os

        os.umask(previous)

    def test_default_umask_is_owner_only(self, tmp_path, monkeypatch):

        config = Config.model_validate(_minimal(tmp_path))
        assert config.umask == "0077"
        previous = config.apply_umask()
        try:
            (tmp_path / "written.txt").write_text("x")
            mode = (tmp_path / "written.txt").stat().st_mode & 0o777
            assert mode & 0o077 == 0, oct(mode)  # nothing for group or other
        finally:
            self._restore(previous)

    def test_umask_can_be_widened_for_a_reviewer_group(self, tmp_path):
        import os

        config = Config.model_validate({**_minimal(tmp_path), "umask": "0027"})
        previous = config.apply_umask()
        try:
            assert os.umask(0o027) == 0o027
        finally:
            self._restore(previous)

    def test_null_umask_leaves_the_process_alone(self, tmp_path):
        config = Config.model_validate({**_minimal(tmp_path), "umask": None})
        assert config.apply_umask() is None

    def test_a_nonsense_umask_is_a_config_error(self, tmp_path):
        config = Config.model_validate({**_minimal(tmp_path), "umask": "not-octal"})
        with pytest.raises(ConfigError):
            config.apply_umask()


class TestShippedExampleConfig:
    """config.example.yaml is the first thing a new operator copies. An
    example that no longer matches the schema — a renamed field, a setting
    added to the code but never to the example — is a silent papercut, so
    it is parsed and checked here like any other config.
    """

    EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.yaml"

    def test_it_parses_against_the_current_schema(self):
        import yaml

        raw = yaml.safe_load(self.EXAMPLE.read_text())
        config = Config.model_validate(raw)  # extra/renamed keys would fail here
        assert config.source.name

    def test_it_documents_every_security_setting_the_readme_promises(self):
        import yaml

        raw = yaml.safe_load(self.EXAMPLE.read_text())
        assert "umask" in raw, "the example must show the umask setting"
        console = raw["console"]
        assert "session_max_age_seconds" in console
        assert "session_cookie_secure" in console

    def test_its_values_round_trip_to_the_intended_defaults(self):
        import yaml

        config = Config.model_validate(yaml.safe_load(self.EXAMPLE.read_text()))
        assert config.umask == "0077"  # owner-only
        assert config.console.session_cookie_secure is False  # localhost out of the box
        assert config.audit.integrity == "chained"
        assert config.dlp.quarantine_on_degraded is True  # fail closed
        assert config.retention.documents_days is None  # opt-in, never a surprise


class TestConfigVersionIsChecked:
    """`version:` exists so a format change can be detected rather than
    guessed at. Pydantic ignores unknown keys and fills missing ones with
    defaults, so a key that moved between versions would otherwise be
    silently dropped — and for something like quarantine_on_degraded that
    means a policy quietly flipping on upgrade."""

    def _config_text(self, tmp_path, header: str) -> Path:
        src = tmp_path / "drops"
        src.mkdir(exist_ok=True)
        path = tmp_path / "c.yaml"
        path.write_text(
            header
            + f"""
source: {{name: t, path: {src}, metadata_format: none}}
destination:
  archive: {tmp_path / "a"}
  quarantine: {tmp_path / "q"}
  work_dir: {tmp_path / "w"}
dlp:
  rules: [{{id: r.x, name: X, pattern: 'x'}}]
"""
        )
        return path

    def test_the_current_version_is_accepted(self, tmp_path):
        assert load_config(self._config_text(tmp_path, "version: 2\n")).version == 2

    def test_omitting_it_is_accepted_as_the_current_version(self, tmp_path):
        assert load_config(self._config_text(tmp_path, "")).version == 2

    def test_an_older_format_is_refused_rather_than_reinterpreted(self, tmp_path):
        with pytest.raises(ConfigError, match="version"):
            load_config(self._config_text(tmp_path, "version: 1\n"))

    def test_a_newer_format_is_refused_too(self, tmp_path):
        """A config written for a later release may use keys this one does
        not know; taking defaults for them is the dangerous outcome."""
        with pytest.raises(ConfigError, match="version"):
            load_config(self._config_text(tmp_path, "version: 3\n"))

    def test_the_error_names_both_versions(self, tmp_path):
        with pytest.raises(ConfigError) as exc:
            load_config(self._config_text(tmp_path, "version: 1\n"))
        assert "1" in str(exc.value) and "2" in str(exc.value)


class TestConfigWarnings:
    """Legal settings that quietly switch off a property the system
    otherwise claims. None of them should fail a build — an install may
    have chosen each deliberately — but nothing else would report them.
    """

    def _config(self, tmp_path, **overrides):
        src = tmp_path / "drops"
        src.mkdir(exist_ok=True)
        base = {
            "source": {"name": "t", "path": str(src), "metadata_format": "none"},
            "destination": {
                "archive": str(tmp_path / "archive"),
                "quarantine": str(tmp_path / "quarantine"),
                "work_dir": str(tmp_path / "work"),
            },
            "dlp": {"rules": [{"include": "builtin:default.yaml"}]},
        }
        base.update(overrides)
        return Config.model_validate(base)

    def test_a_sane_config_warns_about_nothing(self, tmp_path):
        assert config_warnings(self._config(tmp_path)) == []

    def test_ageing_out_purge_records_before_documents_is_flagged(self, tmp_path):
        """reindex reads purge records from the audit trail to avoid
        restoring erased content. Age the trail out first and a rebuild
        has no way to know the erasure happened."""
        config = self._config(
            tmp_path, retention={"audit_days": 30, "documents_days": 365}
        )
        [warning] = config_warnings(config)
        assert "audit_days" in warning and "erased on purpose" in warning

    def test_the_reverse_ordering_is_fine(self, tmp_path):
        config = self._config(
            tmp_path, retention={"audit_days": 365, "documents_days": 30}
        )
        assert config_warnings(config) == []

    def test_an_unset_window_is_not_a_comparison(self, tmp_path):
        """None means keep forever, which is longer than any number."""
        config = self._config(tmp_path, retention={"documents_days": 365})
        assert config_warnings(config) == []

    def test_a_non_loopback_bind_without_a_secure_cookie_is_flagged(self, tmp_path):
        config = self._config(tmp_path, console={"bind": "0.0.0.0:8080"})
        assert any("session_cookie_secure" in w for w in config_warnings(config))

    def test_loopback_without_a_secure_cookie_is_the_documented_default(self, tmp_path):
        for bind in ("127.0.0.1:8080", "localhost:8080", "[::1]:8080"):
            config = self._config(tmp_path, console={"bind": bind})
            assert config_warnings(config) == [], bind

    def test_disabling_chaining_is_flagged(self, tmp_path):
        config = self._config(tmp_path, audit={"integrity": "none"})
        assert any("verify-audit" in w for w in config_warnings(config))


class TestConsoleBindParsing:
    """`dlpduck console run` used a bare partition(":") on this, which is
    wrong for IPv6: `[::1]:8080` split at the first colon and left
    int(":1]:8080"). Binding a console to an IPv6 address is ordinary, and
    a config that validates clean and then refuses to start is the worst
    way to find out.
    """

    def test_ipv4_with_a_port(self):
        assert ConsoleConfig(bind="127.0.0.1:8080").host_port() == ("127.0.0.1", 8080)

    def test_a_bracketed_ipv6_literal_with_a_port(self):
        assert ConsoleConfig(bind="[::1]:8080").host_port() == ("::1", 8080)
        assert ConsoleConfig(bind="[::]:9000").host_port() == ("::", 9000)

    def test_a_bare_ipv6_literal_takes_the_default_port(self):
        assert ConsoleConfig(bind="::1").host_port() == ("::1", 8080)

    def test_a_bracketed_ipv6_literal_with_no_port(self):
        assert ConsoleConfig(bind="[::1]").host_port() == ("::1", 8080)

    def test_a_hostname_with_no_port(self):
        assert ConsoleConfig(bind="localhost").host_port() == ("localhost", 8080)

    def test_a_port_that_is_not_a_number_is_refused(self):
        with pytest.raises(ConfigError, match="not a number"):
            ConsoleConfig(bind="host:abc").host_port()

    def test_a_port_out_of_range_is_refused(self):
        for bind in ("host:0", "host:99999", "host:-1"):
            with pytest.raises(ConfigError):
                ConsoleConfig(bind=bind).host_port()

    def test_an_unclosed_bracket_is_refused(self):
        with pytest.raises(ConfigError, match="unclosed"):
            ConsoleConfig(bind="[::1:8080").host_port()

    def test_an_empty_host_is_refused(self):
        with pytest.raises(ConfigError, match="no host"):
            ConsoleConfig(bind=":8080").host_port()

    def test_the_warning_check_and_the_server_agree_about_loopback(self, tmp_path):
        """These parse `bind` for different reasons and must not disagree
        — a config warned as "loopback, fine" that then won't start is
        exactly the inconsistency this shares one parser to avoid."""
        src = tmp_path / "drops"
        src.mkdir(exist_ok=True)
        for bind in ("127.0.0.1:8080", "[::1]:8080", "localhost:8080"):
            config = Config.model_validate(
                {
                    "source": {"name": "t", "path": str(src), "metadata_format": "none"},
                    "destination": {
                        "archive": str(tmp_path / "archive"),
                        "quarantine": str(tmp_path / "quarantine"),
                        "work_dir": str(tmp_path / "work"),
                    },
                    "dlp": {"rules": [{"include": "builtin:default.yaml"}]},
                    "console": {"bind": bind},
                }
            )
            assert config_warnings(config) == [], bind
            assert config.console.host_port()[1] == 8080
