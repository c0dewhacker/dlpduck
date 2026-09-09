# Contributing

Thanks for looking. DLPDuck decides whether documents containing sensitive data
get archived or quarantined, so the bar here is a little different from most
projects: a subtle wrong answer is worse than an obvious crash.

## Getting set up

```bash
uv sync
export DLPDUCK_HMAC_KEY="$(openssl rand -hex 32)"
export DLPDUCK_SESSION_SECRET="$(openssl rand -hex 32)"
uv run pytest -q -n 2 --dist=loadscope
uv run python scripts/mutation_test.py   # does the suite actually catch a bug? (~20 min)
uv run ruff check .
uv run mypy dlpduck/
uv run pip-audit --skip-editable    # this tool should know its own dependencies
```

The CI and Security workflows run those checks, while Build validates the wheel,
source distribution, packaged assets, and a clean installation. CI also runs
`dlpduck validate-config` against the shipped example.

## Releases

Release Please collects conventional commits on `main` into a release PR.
Use `feat:`, `fix:`, or `perf:` for user-facing changes; `deps:` records a
dependency update. Merging the release PR creates a `vX.Y.Z` GitHub release and
attaches the built wheel and source distribution. The release PR also keeps the
version in `pyproject.toml` and the local package entry in `uv.lock` aligned.

`mypy` runs with `union-attr` disabled, and the reason is in `pyproject.toml`:
that code reports one known modelling gap (`JobContext.text` is `Optional` but
always set by the time anything downstream reads it, an invariant `Pipeline.commit`
now enforces at the boundary). Excluding it keeps the checker useful for
annotations that are actually wrong — it caught a handler declared
`-> HTMLResponse` that returned a redirect. If you find yourself adding a
`type: ignore`, prefer fixing the type; there are only two in the codebase and
both are third-party stub gaps with a comment saying so.

## The one principle

**Fail closed.** When DLPDuck cannot be sure what a document contains, it must
not treat it as clean. A page that wouldn't render, a rule that ran out of time,
a limit exceeded, an extraction that produced nothing at all — each of those ends
in `failed/` or quarantine, never in the archive. If a change makes an uncertain
outcome look like a confident one, it's wrong even if every test passes.

Two corollaries that come up constantly:

- **Raw matched values are never stored.** A hit carries a masked form and a
  keyed HMAC. Nothing may persist, log, or forward the cleartext of a match.
- **Raw document text follows the document.** If a role may not open a document,
  no other screen may serve text from it — search excerpts included.

## Tests

New behaviour needs a test. Security boundaries need one that proves the
*negative* case too: not just "an admin can reveal a hit" but "an investigator
cannot".

Some things line coverage can't see, and there are modules for each:

| Module | What it covers |
|---|---|
| `tests/test_fail_closed.py` | Every way certainty can be lost, and where it lands |
| `tests/test_concurrency.py` | Properties that only break with two writers |
| `tests/test_scale.py` | Reads that are unbounded by nature |
| `tests/test_schema_evolution.py` | An index written by an older release |
| `tests/test_malformed_pdfs.py` | Broken, hostile, and merely awkward documents |
| `tests/test_ocr_integration.py` | The scan-to-verdict path, with a real OCR model |

If you're changing something safety-critical, a useful check is to break it
deliberately and confirm a test fails. Several bugs in this codebase were found
exactly that way.

## Changing the index schema

Index rows are permanent, and a release reads its own new files alongside every
old one. Adding a column is safe — `union_by_name` fills it as NULL for older
rows, and `tests/test_schema_evolution.py` covers it. **Renaming or removing one
is not**, and needs a migration story before it goes in.

## Rules

The baseline lives at `dlpduck/builtin_rules/default.yaml` — inside the package,
so it ships in a wheel and configs can reach it as `builtin:default.yaml` without
a repository checkout. It is deliberately conservative: a false positive
quarantines a document someone needs. New rules want a checksum `validator` where
the data type has one, and `dlpduck test-rules --corpus <dir>` output in the PR
showing what they actually fire on.

## Reporting a vulnerability

Please don't open a public issue — see [SECURITY.md](SECURITY.md), which also
lists what counts, what doesn't, and the risks that are accepted and documented.

## Style

`ruff check` is enforced; `ruff format` deliberately isn't, because several
comments here are prose that wraps where it reads best. Match the surrounding
code.

Comments should explain why a non-obvious safety or compatibility constraint
exists, especially when changing it could alter stored data or routing behavior.
