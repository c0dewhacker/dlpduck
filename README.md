<p align="center">
  <img src="dlpduck/console/static/mascot.png" width="280" alt="DLPDuck mascot: a security duck holding a laptop">
</p>

<h1 align="center">DLPDuck</h1>

<p align="center">
  <strong>Line-aware OCR and data-loss prevention for scanned documents.</strong><br>
  Watch a folder. Read every page. Quarantine sensitive documents. Keep the evidence.
</p>

<p align="center">
  <img alt="Python 3.12 or newer" src="https://img.shields.io/badge/Python-3.12%2B-46305F?style=flat-square&logo=python&logoColor=white">
  <img alt="Apache 2.0 license" src="https://img.shields.io/badge/License-Apache--2.0-46305F?style=flat-square">
  <img alt="Project status: pre-1.0" src="https://img.shields.io/badge/Status-pre--1.0-B4560B?style=flat-square">
  <img alt="Local-first processing" src="https://img.shields.io/badge/Processing-local--first-2C5C86?style=flat-square">
</p>

<p align="center">
  <a href="https://github.com/c0dewhacker/dlpduck/actions/workflows/ci.yml"><img alt="CI status" src="https://github.com/c0dewhacker/dlpduck/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/c0dewhacker/dlpduck/actions/workflows/build.yml"><img alt="Build status" src="https://github.com/c0dewhacker/dlpduck/actions/workflows/build.yml/badge.svg"></a>
  <a href="https://github.com/c0dewhacker/dlpduck/actions/workflows/security.yml"><img alt="Dependency security status" src="https://github.com/c0dewhacker/dlpduck/actions/workflows/security.yml/badge.svg"></a>
  <a href="https://github.com/c0dewhacker/dlpduck/actions/workflows/codeql.yml"><img alt="CodeQL status" src="https://github.com/c0dewhacker/dlpduck/actions/workflows/codeql.yml/badge.svg"></a>
  <a href="https://github.com/c0dewhacker/dlpduck/actions/workflows/release-please.yml"><img alt="Release automation status" src="https://github.com/c0dewhacker/dlpduck/actions/workflows/release-please.yml/badge.svg"></a>
</p>

---

DLPDuck watches a PDF drop folder, extracts native text and OCR page by page,
applies position-aware DLP rules, and routes each document to an archive or a
quarantine. Decisions go into a hash-chained audit trail; the web console gives
operators one place to investigate hits, search text, retry failures, reassess
documents under new rules, approve releases, and purge retained content.

| Built for | What DLPDuck does |
|---|---|
| Scanners and MFPs | Waits for stable PDF and companion metadata files before claiming them |
| Mixed PDFs | Uses native text where it is trustworthy and OCR on sparse or image-bearing pages |
| Position-sensitive policy | Matches by page, line, document scope, and configurable line ranges |
| Sensitive findings | Stores masked values and keyed correlation digests, never the raw match |
| Operational review | Provides quarantine, a Needs attention queue, search, reassessment, and release workflows |
| Evidential history | Keeps append-only assessments and a verifiable, hash-chained audit log |

> [!NOTE]
> DLPDuck is pre-1.0. Pin a version in production.

---

## Table of contents

- [How it works](#how-it-works)
- [Install](#install)
- [Docker](#docker)
- [Kubernetes](#kubernetes)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Writing rules](#writing-rules)
- [Storage, purge, and maintenance](#storage-purge-and-maintenance)
- [Audit trail](#audit-trail)
- [Admin console](#admin-console)
- [CLI reference](#cli-reference)
- [Writing plugins](#writing-plugins)

---

## How it works

1. The watcher waits until a PDF stops changing, then moves it into staging.
2. Each page uses native text when suitable and OCR when it is sparse or contains images.
3. Rules inspect lines or the complete document and mask every recorded match.
4. Enrichment plugins can add routing context before the final decision.
5. Clean documents enter the archive; matches and incomplete extraction enter quarantine.
6. DLPDuck writes the PDF, searchable content, assessment index, and audit event before notifying emit plugins.

A file that cannot be assessed never passes as clean. Findings contain masked text and a keyed correlation digest, never the raw matched value.

---

## Install

Requires Python 3.12+.

```bash
cd dlpduck                    # from a source checkout
uv sync                       # or: pip install -e .
```

Two environment variables are required before anything runs:

```bash
export DLPDUCK_HMAC_KEY="$(openssl rand -hex 32)"        # correlation digests
export DLPDUCK_SESSION_SECRET="$(openssl rand -hex 32)"  # console cookie signing
```

`DLPDUCK_HMAC_KEY` must be stable for the life of a deployment and must never be
written into config, the archive, or the audit trail.

---

## Docker

```bash
docker pull c0dewhacker/dlpduck
```

Set `DLPDUCK_RUN_BOTH=true` to run the watcher and console together:

```bash
docker run -d --name dlpduck \
  -e DLPDUCK_HMAC_KEY="$(openssl rand -hex 32)" \
  -e DLPDUCK_SESSION_SECRET="$(openssl rand -hex 32)" \
  -e DLPDUCK_RUN_BOTH=true \
  -v /srv/dlpduck/config.yaml:/etc/dlpduck/config.yaml:ro \
  -v /srv/dlpduck/drops:/srv/drops \
  -v /srv/dlpduck/archive:/srv/archive \
  -v /srv/dlpduck/quarantine:/srv/quarantine \
  -v /srv/dlpduck/work:/srv/work \
  -v /srv/dlpduck/audit:/srv/audit \
  -p 8080:8080 \
  c0dewhacker/dlpduck --config /etc/dlpduck/config.yaml
```

Set `audit.path: /srv/audit` in the config for the separate audit mount. Without
it, audit data remains under the mounted `work_dir/audit`. The endpoints
`/health/live` and `/health/ready` provide container liveness and watcher
readiness checks. Omit `DLPDUCK_RUN_BOTH` and pass `run` or `console run` to run
one role. Container paths in the config must match the mounted paths, which must
be writable by the image's non-root user.

## Kubernetes

A Helm chart in [`charts/dlpduck`](charts/dlpduck) runs the watcher and console
together with separate persistent claims for incoming files, archive,
quarantine, working data and the audit trail:

```bash
helm upgrade --install dlpduck charts/dlpduck \
  --namespace dlpduck --create-namespace -f my-values.yaml
```

See the [deployment guide](DEPLOYMENT.md) for secrets, local or OIDC login,
storage, ingress, TLS, upgrades and recovery.

---

## Quick start

```bash
mkdir -p /srv/dlpduck/{drops,archive,quarantine,work}

cat > config.yaml <<'YAML'
source:
  name: mfp-3f
  path: /srv/dlpduck/drops
  metadata_format: none
destination:
  archive: /srv/dlpduck/archive
  quarantine: /srv/dlpduck/quarantine
  work_dir: /srv/dlpduck/work
dlp:
  rules:
    - include: builtin:default.yaml
YAML

dlpduck validate-config --config config.yaml   # compiles every regex, checks paths, warns
dlpduck run --config config.yaml               # start the watcher
```

In another shell:

```bash
dlpduck console run --config config.yaml       # http://127.0.0.1:8080
```

Before dropping real documents, dry-run one:

```bash
dlpduck scan some.pdf --config config.yaml     # prints lines + what would hit
```

---

## Configuration

A minimal config is `source`, `destination`, and `dlp.rules`; everything else has
a default. The full shape:

Environment variables named `DLPDUCK__SECTION__FIELD` override YAML before
validation. For example, `DLPDUCK__CONSOLE__BIND=0.0.0.0:8080` overrides
`console.bind`; lists and mappings accept JSON or inline YAML. The HMAC and
session values remain in `DLPDUCK_HMAC_KEY` and `DLPDUCK_SESSION_SECRET`, so
they never need to appear in the configuration file.

```yaml
version: 2                      # the config format; a mismatch is refused, not guessed at
umask: "0077"                   # owner-only for everything written; null to inherit

source:
  name: mfp-3f                  # recorded on every job
  path: /srv/dlpduck/drops
  pdf_suffix: .pdf
  metadata_format: none         # xml | json | text | none
  metadata_suffix: .xml         # companion file: scan.pdf + scan.xml
  metadata_fields: []           # ALLOWLIST — see the note below
  poll_seconds: 5.0
  stability_polls: 2            # size must hold this many polls before claiming
  metadata_grace_polls: 3       # extra polls to wait for a companion that's en route

limits:
  max_bytes: 209715200          # 200 MB
  max_pages: 500
  rule_budget_ms: 2000          # per rule, per document
  max_metadata_bytes: 1048576   # 1 MB — companion files are bounded too

extraction:
  dpi: 150                      # OCR raster resolution
  native_min_chars: 20          # per page: below this, the page goes to OCR
  isolate_worker: true          # contain parser/OCR hangs in a child process
  timeout_seconds: 120          # whole-document extraction budget

dlp:
  quarantine_on_degraded: true  # fail closed
  hmac_key_env: DLPDUCK_HMAC_KEY
  rules:
    - include: builtin:default.yaml
    - id: local.badge_number    # inline rules work too
      name: Site badge number
      pattern: '\bBADGE-\d{6}\b'
      severity: MEDIUM
      action: flag

destination:
  archive: /srv/dlpduck/archive
  quarantine: /srv/dlpduck/quarantine    # a SEPARATE mount/ACL in production
  work_dir: /srv/dlpduck/work            # index/, content/, failed/, spool/

audit:
  integrity: chained            # chained | none
  path: /srv/dlpduck/audit      # optional; defaults to work_dir/audit

retention:                      # opt-in; unset means keep forever
  documents_days: null          # PDFs, failed queue + the content store
  index_days: null
  audit_days: null

console:
  bind: 127.0.0.1:8080         # IPv6 literals in brackets: "[::1]:8080"
  session_secret_env: DLPDUCK_SESSION_SECRET
  session_max_age_seconds: 28800     # 8h; sessions can be revoked sooner
  session_cookie_secure: false       # set true behind TLS
  audit_search_terms: hashed         # hashed avoids storing search queries
  auth:
    max_failed_logins: 10       # then that username/address waits out the lockout
    lockout_seconds: 300
    users:                      # local/break-glass accounts
      - username: breakglass
        password_hash: '$argon2id$...'   # dlpduck console hash-password
        role: dlp_admin
    oidc:                       # the primary path where you have an IdP
      issuer: https://idp.example/realms/dlpduck
      client_id: dlpduck-console
      client_secret_env: DLPDUCK_OIDC_CLIENT_SECRET
      roles_claim: roles
      role_map:
        corp-dlp-team: dlp_admin

plugins:
  - name: syslog
    args: {host: siem.example, port: 514, protocol: tcp}
  - name: webhook
    critical: false
    args: {url: https://soc.example/hook, secret_env: DLPDUCK_WEBHOOK_SECRET}
```

`metadata_fields` is an **allowlist** — only keys named here survive from a
companion file or the PDF's own Info dictionary; an empty list (the default)
keeps nothing. PDF-derived keys are prefixed `pdf_` (`pdf_title`, `pdf_author`,
…); where both set a key, the companion wins.

```yaml
source:
  metadata_fields: [device_id, department, pdf_title]
```

---

## Writing rules

### Starting from the baseline

DLPDuck ships a conservative baseline ruleset inside the package. Include it by
name — not by path, so it resolves the same whether you cloned the repository or
ran `pip install`:

```yaml
dlp:
  rules:
    - include: builtin:default.yaml   # the bundled baseline
    - include: site-rules.yaml        # your own, relative to this config file
    - id: pan.generic                 # redefine anything you disagree with
      name: Payment card number
      pattern: '\b(?:\d[ -]?){12,18}\d\b'
      validator: luhn
      action: flag                    # baseline ships `quarantine`
```

Later definitions win by `id`, so you never edit the baseline in place —
everything you don't redefine keeps tracking upstream when you update. Paths
without the `builtin:` prefix resolve relative to the file doing the including.

```yaml
rules:
  - id: fin.iban
    name: IBAN
    pattern: '\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b'
    severity: HIGH              # INFO | LOW | MEDIUM | HIGH | CRITICAL
    action: quarantine          # quarantine | flag | ignore
    validator: iban_mod97       # luhn | iban_mod97 | nhs_mod11 | none — checksum, kills false positives
    scope: line                 # line | document
    mask_keep: 0                # trailing chars left visible; 0 = fully masked
    enabled: true

  - id: mark.banner_header
    name: Classification banner
    pattern: 'OFFICIAL-SENSITIVE|SECRET'
    severity: CRITICAL
    action: quarantine
    scope: line
    line_scope: page            # position window is per page, not per document
    min_line: 0
    max_line: 3                 # only the first four lines of any page

  - id: mark.footer_marking
    name: Footer marking
    pattern: 'RESTRICTED'
    from_end: true              # count the window from the END of the page
    min_line: 0
    max_line: 2

  - id: cred.password_assignment
    name: Password assignment
    pattern: '\b\S{8,}\b'
    requires_context:           # only a hit if this appears nearby
      pattern: '(?i)password|passwd|pwd'
      within_lines: 1           # ± lines (default 2)
```

Field reference:

| Field | Meaning |
|---|---|
| `id` | Unique key. Letters, digits, `.`, `_`, `-`; max 64 chars. |
| `pattern` | Python regex. No implicit flags — write `(?i)` if you want one. |
| `severity` | Ranked; the document's highest hit wins. |
| `action` | `quarantine` routes the document; `flag` records it and archives; `ignore` records nothing. |
| `scope` | `line` matches per line; `document` matches the joined text (for values that wrap). |
| `line_scope` | With a position window: `page` (per page) or `document`. |
| `min_line` / `max_line` | Inclusive 0-indexed window. Omit both for "anywhere". |
| `from_end` | Count the window from the end (footers). |
| `validator` | Checksum applied to each candidate before it counts. |
| `mask_keep` | Trailing characters left visible. Ignored when the match is short enough that a tail would reveal most of it. |
| `requires_context` | `{pattern, within_lines}` — a predicate on surrounding lines. |
| `enabled` | `false` keeps a rule in the file but out of the ruleset. |

Test a ruleset against a real corpus before deploying it:

```bash
dlpduck test-rules ./corpus --config config.yaml            # every rule
dlpduck test-rules ./corpus --config config.yaml --rule-id fin.iban
```

---

## Storage, purge, and maintenance

| Store | Contents | Purge behaviour |
|---|---|---|
| `index/` | Metadata, disposition, and masked findings | Retained as assessment history |
| `content/` | Searchable raw text and structured lines | Deleted by purge |
| `archive/` and `quarantine/` | Original PDFs | Deleted only by hard purge or retention |

```bash
dlpduck purge-content <job_id>            # delete extracted content
dlpduck purge-content <job_id> --hard     # also delete the original PDF
dlpduck compact-index --config config.yaml --commit
dlpduck reindex --config config.yaml --commit
```

Stores use UTC `dt=YYYY-MM-DD` partitions. Configure retention per store; unset windows keep data indefinitely. `compact-index` merges completed daily index partitions, while `reindex` reconstructs missing index rows without restoring content previously recorded as purged.

---

## Audit trail

Audit events live under `work_dir/audit/dt=YYYY-MM-DD/events.jsonl`. With `audit.integrity: chained`, each event links to the previous event so edits are detectable.

```bash
dlpduck verify-audit --config config.yaml
dlpduck redact-audit --config config.yaml \
  --seq 4182 --field query --reason "erasure request 41"
```

Redaction replaces selected event fields with `[redacted]`, preserves the chain, and records who performed it and why. Purge and retention record intent before making irreversible changes.

---

## Admin console

```bash
dlpduck console run --config config.yaml
```

Screens: Overview, Jobs, job detail (findings, receipt history, metadata,
reveal, reprocess, purge, audit timeline), Needs attention, Search, Rules,
Audit, Access. Overview counters link to their filtered queue; a worker card
shows watcher heartbeat, activity and drop-folder backlog.

Needs attention holds refused, failed and interrupted documents — inspect,
retry (individually or in bulk), or mark resolved with a reason. A crash mid
external-delivery requires acknowledging the first attempt may have succeeded
before retrying. Failed documents follow `retention.documents_days`.

### Roles

| Permission | viewer | investigator | dlp_admin | auditor |
|---|:--:|:--:|:--:|:--:|
| `jobs.list`, `jobs.metadata.read`, `rules.read` | ✅ | ✅ | ✅ | ✅ |
| `dlp.hits.read` (masked) | | ✅ | ✅ | ✅ |
| `jobs.text.read` (search) | | ✅ | ✅ | |
| `jobs.pdf.read` (archived PDFs) | | ✅ | ✅ | |
| `jobs.pdf.read.quarantined` | | | ✅ | |
| `dlp.reveal` (cleartext) | | | ✅ | |
| `quarantine.release`, `jobs.purge`, `rules.write`, `access.write` | | | ✅ | |
| `jobs.failed.manage` (the refused/unprocessable queue) | | | ✅ | |
| `jobs.reprocess.preview` | | ✅ | ✅ | |
| `jobs.reprocess.commit` | | | ✅ | |
| `audit.read`, `audit.verify` | | | ✅ | ✅ |

A document counts as quarantined if its disposition says so, a release is
pending, **or** the file physically sits under the quarantine root — one rule
gates both whether its PDF opens and whether a search snippet shows. `dlp_admin`
is the superuser role; `auditor` is its opposite (audit trail and masked hits,
never document text, the PDF, or cleartext).

### Auth

- **OIDC** is the primary path. With `console.auth.oidc` configured, `/login`
  redirects to the IdP; roles come from `roles_claim` via `role_map`.
- **Local accounts** are the break-glass/air-gapped fallback, at
  `/login?auth=local`. Hash a password with `dlpduck console hash-password`.

---

## CLI reference

| Command | What it does |
|---|---|
| `validate-config` | Parse config, compile every regex, check paths. Prints warnings too. Use it in CI. |
| `run` | Start the watcher daemon. |
| `scan <pdf>` | Dry-run one document; print lines and what would hit. Writes nothing. |
| `test-rules <dir>` | Run the ruleset over a corpus and report per-rule hit counts. |
| `search <query>` | Full-text search across the content store. |
| `reprocess` | Re-run the current ruleset over already-ingested jobs. Preview by default; `--commit` to apply. `--mode extract` re-runs OCR too. |
| `release <job_id>` | Carry out a pending de-escalation (quarantine → archive). |
| `purge-content <job_id>` | Soft purge; `--hard` also deletes the PDF. |
| `retention` | Show what's past each retention window. Dry run; `--apply` to delete. |
| `verify-audit` | Walk the hash chain and report the first break. |
| `redact-audit` | Empty named fields from one audit event, recording who and why. |
| `compact-index` | Merge each past day's assessment files into one. Dry-run by default. |
| `reindex` | Rebuild the index from the content store, or from the PDFs. Disaster recovery — restores where each document is filed, never re-judges it. |
| `replay-sink <name>` | Drain a sink's spool after an outage. |
| `console run` | Start the admin console. |
| `console hash-password` | Hash a password for `console.auth.users`. |

---

## Writing plugins

A plugin is a small class with one method. There are two phases, and the phase
you pick decides what your plugin can *do*, not just when it runs.

### The two phases

| | `enrich` | `emit` |
|---|---|---|
| Runs | after the DLP scan, **before** disposition | after commit — the PDF is filed, stores written, audit event appended |
| Can change routing? | **yes** — mutate `ctx` and the decision follows | no, the decision is already recorded |
| Typical use | look up a device/department in a directory, attach context | forward to SIEM, webhook, ticketing |
| Failure impact | a `critical` failure routes the job to `failed/` | a failure is audited and spooled; the job is already safe |

### The interface

```python
from dlpduck.plugins.base import Plugin
from dlpduck.types import JobContext

class MyPlugin(Plugin):
    phase = "enrich"          # or "emit"
    name = "my_plugin"        # appears in audit events and log lines

    def __init__(self, some_option: str, name: str | None = None,
                 critical: bool = False, spool_root=None):
        self.some_option = some_option
        self.critical = critical
        if name:
            self.name = name

    def run(self, ctx: JobContext) -> None:
        ...
```

The loader inspects your `__init__` signature and passes `name`, `critical`, and
`spool_root` **only if you accept them** (by name, or via `**kwargs`). Everything
under the config entry's `args:` is passed through as keyword arguments. A
`TypeError` from your constructor becomes a startup config error, not a runtime
surprise — a misconfigured plugin fails `validate-config`, not document 4,000.

### What you get: `JobContext`

```python
ctx.job_id          # blake2b of the PDF bytes — stable, content-derived
ctx.received_at     # UTC datetime
ctx.source_name     # from config
ctx.pdf_path        # staged PDF (enrich phase); moved by the time emit runs
ctx.pdf_sha256
ctx.metadata        # dict — the ALLOWLISTED companion/PDF metadata
ctx.text            # DocumentText: .lines, .full_text, .page_count, .degraded
ctx.hits            # list[DLPHit] — masked_text and match_hmac, never raw values
ctx.disposition     # "pending" during enrich; "archive"/"quarantine"/"failed" at emit
ctx.highest_severity
ctx.audit_fields    # dict — YOUR output surface; lands in the index row
ctx.errors          # list[str] — appended to on plugin failure
```

**`ctx.audit_fields` is the enrich phase's product.** Write there rather than
mutating `ctx.metadata`: metadata records what arrived with the document,
`audit_fields` records what the system worked out about it, and the console shows
them separately.

### Rules for plugin authors

1. **Never write a raw match anywhere.** `DLPHit` deliberately doesn't carry the
   matched value — only `masked_text` and a keyed `match_hmac`. If your sink
   needs to correlate values across documents, forward the HMAC. A plugin that
   re-derives cleartext from `ctx.text` and ships it off-box defeats the entire
   point of the tool.
2. **Be idempotent.** Emit plugins can be replayed from the spool.
3. **Fail loudly, not silently.** Raise. The runner audits the failure as
   `plugin.failed` with your name and the error, appends to `ctx.errors`, and
   continues — unless you set `critical: true`, which stops the job.
4. **Don't block.** Set a timeout on anything doing I/O. The pipeline is
   single-threaded per document.
5. **Choose `critical` deliberately.** `critical: true` means "if this doesn't
   happen, the document must not be treated as processed" — right for a
   compliance-mandated SIEM feed, wrong for a Slack notification.

### A worked example: an emit sink

Delivery-failure handling is inherited — subclass `SpoolingSink` and implement
`build()` and `deliver()`. On failure, the payload is spooled and re-raised; the
same `deliver()` is reused later by `dlpduck replay-sink`, so a replayed event
takes exactly the path a live one would have.

```python
# mycompany/dlpduck_plugins.py
from dlpduck.plugins.sinks import SpoolingSink
from dlpduck.types import JobContext
import json, urllib.request

class TicketSink(SpoolingSink):
    phase = "emit"
    default_name = "ticket"

    def __init__(self, endpoint: str, queue: str = "dlp-review", **kwargs):
        super().__init__(**kwargs)          # name/critical/spool_root/timeout
        self.endpoint = endpoint
        self.queue = queue

    def build(self, ctx: JobContext) -> dict:
        # Runs in-process, so keep it cheap and side-effect free.
        return {
            "queue": self.queue,
            "title": f"{ctx.disposition}: {ctx.job_id[:12]}",
            "severity": ctx.highest_severity.value if ctx.highest_severity else None,
            "rules": sorted({h.rule_id for h in ctx.hits}),
            "masked": [h.masked_text for h in ctx.hits],   # never h. raw anything
            "department": ctx.audit_fields.get("department"),
        }

    def deliver(self, payload: dict) -> None:
        # Raise on failure — the base class spools and re-raises for you.
        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            if resp.status >= 300:
                raise RuntimeError(f"ticket API returned HTTP {resp.status}")
```

Only quarantined documents raise a ticket? Filter in `run()`:

```python
    def run(self, ctx: JobContext) -> None:
        if ctx.disposition != "quarantine":
            return
        super().run(ctx)
```

### A worked example: summarising with an LLM provider

This one is a deliberate exception to rule #1 above — it ships the document's
full text off-box, to a third-party API, on purpose. That's why it's gated
hard: only `archive`-disposition documents (never quarantined ones, which are
exactly the sensitive content this tool exists to keep in-house), and only
against an LLM endpoint you've actually reviewed for this — a self-hosted
model, or a vendor under contract — never a default. Think about that gate
before adapting this for your own use.

```python
# mycompany/dlpduck_plugins.py
import json
import os
import urllib.request

from dlpduck.plugins.sinks import SpoolingSink
from dlpduck.types import JobContext


class LlmSummarySink(SpoolingSink):
    """Summarises an archived document's text with an LLM provider and posts
    the summary to an internal endpoint. Targets an OpenAI-compatible chat
    completions API; adjust build()/deliver() for another provider's shape.
    """

    phase = "emit"
    default_name = "llm_summary"

    def __init__(
        self,
        api_url: str,
        api_key_env: str,
        model: str,
        summary_endpoint: str,
        max_chars: int = 20_000,
        **kwargs,
    ):
        super().__init__(**kwargs)          # name/critical/spool_root/timeout
        self.api_url = api_url
        self.api_key = os.environ[api_key_env]   # fail at startup, not mid-run
        self.model = model
        self.summary_endpoint = summary_endpoint
        self.max_chars = max_chars

    def run(self, ctx: JobContext) -> None:
        if ctx.disposition != "archive":
            return                          # never summarise a quarantined document
        super().run(ctx)

    def build(self, ctx: JobContext) -> dict:
        return {"job_id": ctx.job_id, "text": ctx.text.full_text[: self.max_chars]}

    def deliver(self, payload: dict) -> None:
        summary = self._summarise(payload["text"])
        req = urllib.request.Request(
            self.summary_endpoint,
            data=json.dumps({"job_id": payload["job_id"], "summary": summary}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            if resp.status >= 300:
                raise RuntimeError(f"summary endpoint returned HTTP {resp.status}")

    def _summarise(self, text: str) -> str:
        req = urllib.request.Request(
            self.api_url,
            data=json.dumps({
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "Summarise this document in three sentences."},
                    {"role": "user", "content": text},
                ],
            }).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read())
        return body["choices"][0]["message"]["content"]
```

```yaml
plugins:
  - path: mycompany.dlpduck_plugins.LlmSummarySink
    args:
      api_url: https://api.your-llm-provider.example/v1/chat/completions
      api_key_env: DLPDUCK_LLM_API_KEY
      model: your-provider-model-id
      summary_endpoint: https://intranet.example/dlp-summaries
      timeout: 30
```

### A worked example: an enrich plugin

```python
class LdapEnrich(Plugin):
    phase = "enrich"
    name = "ldap_enrich"

    def __init__(self, server: str, key_field: str = "device_id",
                 name: str | None = None, critical: bool = False, spool_root=None):
        self.server = server
        self.key_field = key_field
        self.critical = critical
        if name:
            self.name = name

    def run(self, ctx: JobContext) -> None:
        key = ctx.metadata.get(self.key_field)
        if key is None:
            return                       # nothing to look up isn't an error
        ctx.audit_fields.update(self._lookup(key))
```

Because this runs before disposition, whatever it writes to `ctx.audit_fields` is
visible to everything downstream and is stored on the index row. See
`dlpduck/plugins/enrich.py` for a working static-mapping version.

### Registering it

Built-ins are selected by `name`; anything else needs a dotted `path` that's
importable from the running environment:

```yaml
plugins:
  - name: syslog                          # built-in
    args: {host: siem.example, protocol: tcp}

  - path: mycompany.dlpduck_plugins.TicketSink
    critical: false
    args:
      endpoint: https://tickets.example/api/v1/issues
      queue: dlp-review

  - path: mycompany.dlpduck_plugins.LdapEnrich
    enabled: false                        # keep the config, skip the plugin
    args: {server: ldaps://dc1.example}
```

Built-in names: `syslog`, `webhook`, `static_enrich`.

`webhook` posts to exactly the URL you configure and refuses to follow
redirects — a redirect target returning 200 would otherwise read as a
successful delivery while nothing was actually received, and the signing
header would travel to a host you didn't choose. A redirect spools as a
delivery failure instead, retryable with `replay-sink`.

Then verify before you deploy:

```bash
dlpduck validate-config --config config.yaml   # loads and constructs every plugin
```

### Testing a plugin

Plugins take a plain `JobContext`, so they test without a pipeline:

```python
def test_ticket_sink_omits_raw_values():
    ctx = make_context(hits=[hit(rule_id="pan.generic", masked_text="••••1111")])
    payload = TicketSink(endpoint="http://x").build(ctx)
    assert "4111" not in json.dumps(payload)
```

---

## Licence

Apache License 2.0 — see [LICENSE](LICENSE).

The console ships the IBM Plex typeface (`dlpduck/console/static/fonts/`), which
is licensed separately under the SIL Open Font License 1.1 — see
[fonts/LICENSE.txt](dlpduck/console/static/fonts/LICENSE.txt). It is bundled
rather than fetched from a CDN so the console works with no route to the
internet, and emits no telemetry to a third party.
