"""The codebase cites the design document by section — `§8.4`, `§6.4` —
rather than restating reasoning at every call site. That only works if the
sections exist: 126 references to a document nobody can open is worse than
no references at all, because each one looks like it leads somewhere.

This fails when a citation is added for a section that was never written,
or when a section is renumbered out from under its citations.
"""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DESIGN = REPO / "docs" / "DESIGN.md"
CITATION = re.compile(r"§(\d+(?:\.\d+)?)")
HEADING = re.compile(r"^#{2,3} §(\d+(?:\.\d+)?)", re.M)

SEARCHED = [REPO / "dlpduck", REPO / "tests", REPO / "README.md", REPO / "CONTRIBUTING.md"]


def _documented() -> set[str]:
    return set(HEADING.findall(DESIGN.read_text()))


def _cited() -> dict[str, set[str]]:
    """section -> the files citing it."""
    out: dict[str, set[str]] = {}
    for target in SEARCHED:
        files = target.rglob("*.py") if target.is_dir() else [target]
        for path in files:
            if "__pycache__" in path.parts or path.name == Path(__file__).name:
                continue
            for section in CITATION.findall(path.read_text(encoding="utf-8")):
                out.setdefault(section, set()).add(str(path.relative_to(REPO)))
    return out


def test_the_design_document_exists():
    assert DESIGN.is_file(), "the code cites it on every other page"


def test_every_cited_section_resolves():
    documented = _documented()
    dead = {
        section: sorted(files)
        for section, files in _cited().items()
        if section not in documented
    }
    assert not dead, f"citations with nowhere to land: {dead}"


def test_the_document_actually_says_something_under_each_heading():
    """A heading with no body would satisfy the check above while still
    leaving a reader with nothing.

    Only leaf sections are held to this: a `## §8 Storage` that exists to
    introduce §8.1-§8.5 is doing its job with two lines.
    """
    text = DESIGN.read_text()
    blocks = re.split(r"^(#{2,3} .+)$", text, flags=re.M)[1:]
    headings = [h for h in blocks[::2]]
    bodies = [b for b in blocks[1::2]]

    thin = []
    for i, (heading, body) in enumerate(zip(headings, bodies, strict=True)):
        depth = len(heading) - len(heading.lstrip("#"))
        next_depth = (
            len(headings[i + 1]) - len(headings[i + 1].lstrip("#"))
            if i + 1 < len(headings)
            else depth
        )
        introduces_subsections = next_depth > depth
        if not introduces_subsections and len(body.strip()) < 120:
            thin.append(heading.lstrip("# "))
    assert not thin, f"sections that are headings and little else: {thin}"


@pytest.mark.parametrize("anchor", ["§3.2", "§6.4", "§8.4", "§10.6"])
def test_the_load_bearing_sections_are_present(anchor):
    """These four carry the properties the rest of the system rests on:
    fail closed, never store the raw value, append-only reassessment, and
    search's containment rule. A refactor that loses one should not be
    quietly possible."""
    assert anchor in DESIGN.read_text()
