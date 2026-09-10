import json
import tomllib
from pathlib import Path

import yaml

from dlpduck import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_release_version_is_consistent_across_shipped_artifacts():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    chart = yaml.safe_load((ROOT / "charts/dlpduck/Chart.yaml").read_text())
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    locked_project = next(
        package
        for package in lock["package"]
        if package["name"] == "dlpduck" and package.get("source", {}).get("editable") == "."
    )

    assert project["project"]["version"] == __version__
    assert locked_project["version"] == __version__
    assert chart["version"] == __version__
    assert chart["appVersion"] == __version__


def test_release_please_updates_each_explicit_version_file():
    config = json.loads((ROOT / "release-please-config.json").read_text())
    extra_files = config["packages"]["."]["extra-files"]

    # The Python strategy owns pyproject.toml; these are the other shipped
    # version fields that do not have a language-specific updater.
    assert config["release-type"] == "python"
    assert "dlpduck/__init__.py" in extra_files
    yaml_targets = {
        (entry["path"], entry["jsonpath"])
        for entry in extra_files
        if isinstance(entry, dict) and entry["type"] == "yaml"
    }
    assert yaml_targets == {
        ("charts/dlpduck/Chart.yaml", "$.version"),
        ("charts/dlpduck/Chart.yaml", "$.appVersion"),
    }

    release_workflow = (ROOT / ".github/workflows/release-please.yml").read_text()
    assert "uv lock" in release_workflow
