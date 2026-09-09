"""Documentation claims that can be checked mechanically.

Most users meet this project through the README and the example config, not
the source. Those rot quietly: a new config field, a new audit event, a
renamed permission, and the docs still look authoritative while being
wrong. Each check here is narrow on purpose — it asserts a thing exists,
never how it is worded, so prose can be rewritten freely.
"""

import re
import subprocess
from pathlib import Path

import pytest
import yaml

from dlpduck.config import Config
from dlpduck.console import rbac

REPO = Path(__file__).resolve().parents[1]
README = (REPO / "README.md").read_text()
EXAMPLE_PATH = REPO / "config.example.yaml"
EXAMPLE_TEXT = EXAMPLE_PATH.read_text()


def _leaf_fields(model, prefix: str = "") -> set[str]:
    """Dotted paths of every configurable leaf, descending into nested models."""
    found: set[str] = set()
    for name, field in model.model_fields.items():
        path = f"{prefix}{name}"
        annotation = field.annotation
        nested = getattr(annotation, "model_fields", None)
        if nested is None:  # unwrap Optional[Model]
            for arg in getattr(annotation, "__args__", ()):
                if hasattr(arg, "model_fields"):
                    annotation = arg
                    nested = arg.model_fields
        if nested is not None:
            found |= _leaf_fields(annotation, path + ".")
        else:
            found.add(path)
    return found


class TestTheExampleConfigStaysCurrent:
    def test_every_setting_appears_in_the_example(self):
        """A setting nobody can discover may as well not exist. Entries
        under `users`/`oidc` are per-account and shown by example."""
        documented = set(re.findall(r"^\s*#?\s*([a-z_]+):", EXAMPLE_TEXT, re.M))
        missing = sorted(
            path.rsplit(".", 1)[-1]
            for path in _leaf_fields(Config)
            if not path.startswith(("console.auth.users.", "console.auth.oidc."))
            and path.rsplit(".", 1)[-1] not in documented
        )
        assert not missing, f"settings the example never shows: {missing}"

    def test_the_example_parses_as_the_current_schema(self):
        Config.model_validate(yaml.safe_load(EXAMPLE_TEXT))

    def test_it_declares_the_config_version_it_is_written_for(self):
        """load_config refuses a version it does not understand, so the
        example has to declare the current one or it stops being a
        copy-paste starting point."""
        from dlpduck.config import SUPPORTED_CONFIG_VERSION

        assert yaml.safe_load(EXAMPLE_TEXT)["version"] == SUPPORTED_CONFIG_VERSION


class TestTheReadmeStaysCurrent:
    def test_every_cli_command_is_in_the_reference_table(self):
        help_text = subprocess.run(
            ["uv", "run", "dlpduck", "--help"], capture_output=True, text=True, cwd=REPO
        ).stdout
        commands = set(re.findall(r"^  ([a-z][a-z-]+)\s{2,}", help_text, re.M))
        documented = set(re.findall(r"^\| `([a-z][a-z -]*?)(?:\s+<[^>]+>)?` \|", README, re.M))
        # `console` is a group; its subcommands are what an operator runs.
        missing = sorted(commands - documented - {"console"})
        assert not missing, f"commands absent from the CLI reference: {missing}"
        assert "console run" in README and "console hash-password" in README

    def test_every_permission_appears_in_the_role_table(self):
        missing = sorted(p for p in rbac._MATRIX if p not in README)
        assert not missing, f"permissions absent from the role table: {missing}"

    def test_every_role_appears_in_the_role_table(self):
        missing = sorted(r for r in rbac.ALL_ROLES if r not in README)
        assert not missing, f"roles absent from the role table: {missing}"

    def test_every_audit_event_is_listed(self):
        source = "\n".join(
            p.read_text() for p in (REPO / "dlpduck").rglob("*.py")
        )
        emitted = set(re.findall(r'audit\.append\(\s*\n?\s*"([a-z.]+)"', source))
        assert emitted, "the scraper found no audit events — it has stopped working"
        missing = sorted(e for e in emitted if f"`{e}`" not in README)
        assert not missing, f"audit events the README never mentions: {missing}"

    @pytest.mark.parametrize(
        "path", ["SECURITY.md", "CONTRIBUTING.md", "LICENSE"]
    )
    def test_the_documents_the_readme_links_to_exist(self, path):
        assert (REPO / path).is_file()
        assert path in README or path.split("/")[-1] in README


class TestTheProjectIsPackagedForRelease:
    def test_a_licence_is_declared_and_present(self):
        pyproject = (REPO / "pyproject.toml").read_text()
        assert 'license = "Apache-2.0"' in pyproject
        assert "Apache License" in (REPO / "LICENSE").read_text()

    def test_ci_runs_the_checks_contributing_promises(self):
        """CONTRIBUTING tells a contributor that passing locally means
        passing in CI. That is only true if CI runs the same things."""
        # Checks are split by purpose so a dependency-advisory outage does
        # not obscure whether the code itself passed lint and tests.
        ci = "\n".join(
            path.read_text()
            for path in (REPO / ".github" / "workflows").glob("*.yml")
        )
        for command in ("ruff check", "pytest", "mypy", "pip-audit", "validate-config"):
            assert command in ci, f"CI does not run {command!r}"


class TestEverythingTheRuntimeNeedsShipsInsideThePackage:
    """A wheel contains `dlpduck/`, and nothing else. An asset that lives
    beside the package works for anyone who cloned and silently isn't
    there for anyone who ran `pip install` — which was true of the
    baseline ruleset, and would have made the README's own quick start
    fail on a fresh install.
    """

    PACKAGE = REPO / "dlpduck"

    def _shipped(self, relative: str) -> Path:
        return self.PACKAGE / relative

    def test_the_baseline_ruleset_is_inside_the_package(self):
        assert self._shipped("builtin_rules/default.yaml").is_file()

    def test_the_console_templates_are_inside_the_package(self):
        assert list(self._shipped("console/templates").glob("*.html"))

    def test_the_console_assets_are_inside_the_package(self):
        static = self._shipped("console/static")
        assert (static / "fonts.css").is_file()
        assert list((static / "fonts").glob("*.woff2"))

    def test_no_documented_include_points_outside_the_package(self):
        """Every `include:` the docs hand a new user has to resolve on a
        machine that only ever ran `pip install dlpduck`."""
        for doc in (REPO / "README.md", REPO / "config.example.yaml"):
            # Only YAML list entries — prose says "Events include: ..." too.
            includes = re.findall(r"^\s*-\s*include:\s*(\S+)\s*$", doc.read_text(), re.M)
            assert includes, f"{doc.name} documents no ruleset include at all"
            for include in includes:
                assert include.startswith("builtin:") or include.startswith("/"), (
                    f"{doc.name} documents `include: {include}`, which resolves "
                    "relative to the config file and so only works in a checkout"
                )
