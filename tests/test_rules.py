from pathlib import Path

import pytest

from dlpduck.rules import (
    BUILTIN_RULES_DIR,
    RuleConfigError,
    builtin_rulesets,
    load_ruleset,
)


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


class TestLoadRuleset:
    def test_simple_list_loads_in_order(self, tmp_path):
        entries = [
            {"id": "a", "name": "A", "pattern": "x", "severity": "LOW"},
            {"id": "b", "name": "B", "pattern": "y", "severity": "HIGH"},
        ]
        rules = load_ruleset(entries, tmp_path)
        assert [r.id for r in rules] == ["a", "b"]

    def test_disabled_rule_is_excluded(self, tmp_path):
        entries = [
            {"id": "a", "name": "A", "pattern": "x", "enabled": False},
            {"id": "b", "name": "B", "pattern": "y"},
        ]
        rules = load_ruleset(entries, tmp_path)
        assert [r.id for r in rules] == ["b"]

    def test_include_pulls_in_another_file(self, tmp_path):
        _write(
            tmp_path,
            "base.yaml",
            "rules:\n  - id: from_base\n    name: Base\n    pattern: 'x'\n",
        )
        entries = [{"include": "base.yaml"}, {"id": "local", "name": "Local", "pattern": "y"}]
        rules = load_ruleset(entries, tmp_path)
        assert [r.id for r in rules] == ["from_base", "local"]

    def test_local_entry_overrides_included_rule_by_id_but_keeps_its_position(self, tmp_path):
        _write(
            tmp_path,
            "base.yaml",
            "rules:\n"
            "  - id: shared\n    name: Base version\n    pattern: 'x'\n    severity: LOW\n"
            "  - id: other\n    name: Other\n    pattern: 'z'\n",
        )
        entries = [
            {"include": "base.yaml"},
            {"id": "shared", "name": "Overridden version", "pattern": "x", "severity": "CRITICAL"},
        ]
        rules = load_ruleset(entries, tmp_path)
        assert [r.id for r in rules] == ["shared", "other"]
        shared = next(r for r in rules if r.id == "shared")
        assert shared.name == "Overridden version"
        assert shared.severity.value == "CRITICAL"

    def test_missing_include_raises(self, tmp_path):
        with pytest.raises(RuleConfigError, match="not found"):
            load_ruleset([{"include": "does_not_exist.yaml"}], tmp_path)

    def test_missing_required_field_raises(self, tmp_path):
        with pytest.raises(RuleConfigError):
            load_ruleset([{"id": "a", "name": "A"}], tmp_path)  # no pattern

    def test_invalid_regex_raises(self, tmp_path):
        with pytest.raises(RuleConfigError, match="invalid pattern"):
            load_ruleset([{"id": "a", "name": "A", "pattern": "("}], tmp_path)

    def test_invalid_action_raises(self, tmp_path):
        with pytest.raises(RuleConfigError, match="action"):
            load_ruleset(
                [{"id": "a", "name": "A", "pattern": "x", "action": "delete_everything"}],
                tmp_path,
            )

    def test_the_default_ruleset_loads_cleanly(self, tmp_path):
        rules = load_ruleset([{"include": "builtin:default.yaml"}], tmp_path)
        ids = {r.id for r in rules}
        assert "pan.generic" in ids
        assert "mark.itar" not in ids  # shipped enabled: false
        assert len(rules) == 14


class TestBuiltinRulesetsAreReachableFromAnInstall:
    """The baseline ruleset has to resolve with no repository checkout.
    A relative `rules/default.yaml` worked only for people who had cloned,
    which is not who `pip install` produces.
    """

    def test_the_builtin_scheme_resolves_from_anywhere(self, tmp_path):
        """Deliberately relative to a directory with no rules in it — the
        shape of a config in /etc pointing at an installed package."""
        rules = load_ruleset([{"include": "builtin:default.yaml"}], tmp_path)
        assert rules

    def test_the_default_ruleset_ships_inside_the_package(self):
        assert "default.yaml" in builtin_rulesets()
        assert (BUILTIN_RULES_DIR / "default.yaml").is_file()

    def test_an_unknown_builtin_says_what_is_available(self, tmp_path):
        with pytest.raises(RuleConfigError, match="this install ships default.yaml"):
            load_ruleset([{"include": "builtin:nonexistent.yaml"}], tmp_path)

    def test_the_scheme_cannot_escape_the_packaged_directory(self, tmp_path):
        """`builtin:` names a bundled file, not an arbitrary path — a rule
        file read from somewhere unexpected is one someone else may
        control."""
        with pytest.raises(RuleConfigError, match="outside the packaged"):
            load_ruleset([{"include": "builtin:../../../etc/passwd"}], tmp_path)

    def test_relative_includes_still_work(self, tmp_path):
        """The scheme is additive; an existing config with a path next to
        it must keep loading."""
        (tmp_path / "local.yaml").write_text(
            "rules:\n  - id: local.thing\n    name: Thing\n    pattern: 'x'\n"
        )
        rules = load_ruleset([{"include": "local.yaml"}], tmp_path)
        assert [r.id for r in rules] == ["local.thing"]

    def test_a_local_ruleset_can_override_a_builtin_rule_by_id(self, tmp_path):
        """The documented way to customise: include the baseline, then
        redefine what you disagree with."""
        (tmp_path / "site.yaml").write_text(
            "rules:\n"
            "  - include: builtin:default.yaml\n"
            "  - id: pan.generic\n"
            "    name: Payment card number\n"
            "    pattern: 'x'\n"
            "    action: flag\n"
        )
        rules = load_ruleset([{"include": "site.yaml"}], tmp_path)
        [pan] = [r for r in rules if r.id == "pan.generic"]
        assert pan.action == "flag"  # baseline ships quarantine


class TestRuleIdIsConstrained:
    """A rule id is a reference key that ends up in audit events, log lines
    and console markup — and rulesets get copied between installs. It is
    treated as untrusted input and constrained at load, rather than relying
    on every downstream consumer to escape it correctly.
    """

    @pytest.mark.parametrize(
        "bad_id",
        [
            "has spaces",
            "quote'injection",
            '"double"',
            "<script>alert(1)</script>",
            "semi;colon",
            "back\\slash",
            "",
            ".leading-dot",
            "x" * 65,  # over the length cap
        ],
    )
    def test_a_dangerous_or_malformed_id_is_refused(self, tmp_path, bad_id):
        # An empty id trips the loader's own "missing id" check before the
        # charset rule ever sees it; both are refusals, which is the point.
        with pytest.raises(RuleConfigError, match="rule id|missing 'id'"):
            load_ruleset([{"id": bad_id, "name": "A", "pattern": "x"}], tmp_path)

    @pytest.mark.parametrize("good_id", ["pan.generic", "uk.nhs", "local_rule-2", "a", "A9"])
    def test_ordinary_ids_still_load(self, tmp_path, good_id):
        [rule] = load_ruleset([{"id": good_id, "name": "A", "pattern": "x"}], tmp_path)
        assert rule.id == good_id


class TestRuleValidationRejectsBadConfig:
    """The design's promise is that a bad ruleset fails at boot, not on
    document 4,000 — so every one of these has to raise at load time.
    """

    def test_missing_id_is_refused(self, tmp_path):
        with pytest.raises(RuleConfigError, match="id"):
            load_ruleset([{"name": "A", "pattern": "x"}], tmp_path)

    def test_missing_name_is_refused(self, tmp_path):
        with pytest.raises(RuleConfigError, match="required field"):
            load_ruleset([{"id": "a.b", "pattern": "x"}], tmp_path)

    def test_missing_pattern_is_refused(self, tmp_path):
        with pytest.raises(RuleConfigError, match="required field"):
            load_ruleset([{"id": "a.b", "name": "A"}], tmp_path)

    def test_unknown_line_scope_is_refused(self, tmp_path):
        with pytest.raises(RuleConfigError, match="line_scope"):
            load_ruleset(
                [{"id": "a.b", "name": "A", "pattern": "x", "line_scope": "paragraph"}], tmp_path
            )

    def test_unknown_scope_is_refused(self, tmp_path):
        with pytest.raises(RuleConfigError, match="scope"):
            load_ruleset([{"id": "a.b", "name": "A", "pattern": "x", "scope": "sentence"}], tmp_path)

    def test_unknown_validator_is_refused(self, tmp_path):
        with pytest.raises(RuleConfigError, match="a.b"):
            load_ruleset(
                [{"id": "a.b", "name": "A", "pattern": "x", "validator": "astrology"}], tmp_path
            )

    def test_invalid_requires_context_pattern_is_refused(self, tmp_path):
        with pytest.raises(RuleConfigError, match="requires_context"):
            load_ruleset(
                [
                    {
                        "id": "a.b",
                        "name": "A",
                        "pattern": "x",
                        "requires_context": {"pattern": "([unclosed", "within_lines": 1},
                    }
                ],
                tmp_path,
            )

    def test_an_entry_with_no_id_inside_an_include_is_refused(self, tmp_path):
        included = _write(
            tmp_path, "inc.yaml", "rules:\n  - name: No Id Here\n    pattern: 'x'\n"
        )
        with pytest.raises(RuleConfigError, match="missing 'id'"):
            load_ruleset([{"include": str(included)}], tmp_path)

    def test_a_missing_include_file_is_refused(self, tmp_path):
        with pytest.raises(RuleConfigError, match="include not found"):
            load_ruleset([{"include": str(tmp_path / "nope.yaml")}], tmp_path)


class TestDocumentScopedLineWindows:
    def test_document_scope_counts_lines_from_the_document_start(self, tmp_path):
        from dlpduck.types import TextLine

        [rule] = load_ruleset(
            [
                {
                    "id": "a.b", "name": "A", "pattern": "x",
                    "line_scope": "document", "min_line": 5, "max_line": 10,
                }
            ],
            tmp_path,
        )

        def _line(n):
            return TextLine(
                line_number=n, page_number=1, line_on_page=0, lines_on_page=20,
                text="x", source="native",
            )

        assert rule.in_range(_line(7)) is True
        assert rule.in_range(_line(4)) is False   # before the window
        assert rule.in_range(_line(11)) is False  # after it

    def test_repr_names_the_rule_for_a_readable_traceback(self, tmp_path):
        [rule] = load_ruleset(
            [{"id": "a.b", "name": "A", "pattern": "x", "severity": "HIGH"}], tmp_path
        )
        assert "a.b" in repr(rule)
        assert "HIGH" in repr(rule)
