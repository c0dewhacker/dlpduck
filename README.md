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
> DLPDuck is pre-1.0. The security model is deliberate and extensively tested,
> but production deployments should pin a revision and follow the
> [security guidance](SECURITY.md).

The architectural reasoning lives in **[docs/DESIGN.md](docs/DESIGN.md)**. Code
comments that cite a `§` point there. The design also records earlier mistakes
and why the current recovery, storage, and authorization boundaries exist.

---

## Table of contents

- [How it works](#how-it-works)
- [Install](#install)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Writing rules](#writing-rules)
- [The two stores, and what purge actually deletes](#the-two-stores-and-what-purge-actually-deletes)
- [The audit trail](#the-audit-trail)
- [Admin console](#admin-console)
- [CLI reference](#cli-reference)
- [Writing plugins](#writing-plugins)
- [Security notes](#security-notes)
- [Development](#development)

---

## How it works

```
   drop folder
        │
        │  1. watch — wait for the file to stop growing
        ▼
   ┌─────────┐
   │  claim  │  move into a job-scoped staging dir; job_id = blake2b(pdf bytes)
   └────┬────┘  refuse symlinks; enforce max_bytes
        ▼
   ┌─────────┐
   │ extract │  per page: native text when sufficient; OCR sparse/image pages
   └────┬────┘  OCR boxes are clustered into visual rows, not raw top-edge order
        ▼
   ┌─────────┐
   │  scan   │  every rule against every line (or the joined document text)
   └────┬────┘  masked at match time — the raw value is never stored
        ▼
   ┌─────────┐
   │ enrich  │  enrich-phase plugins run HERE, before routing, so they can
   └────┬────┘  attach context that changes the decision
        ▼
   ┌─────────┐
   │ dispose │  quarantine if any hit says so, or if extraction was degraded
   └────┬────┘
        ▼
   ┌─────────┐   archive/ or quarantine/   (the PDF)
   │ commit  │─▶ index/                    (permanent metadata, masked hits)
   └────┬────┘   content/                  (raw full text — the purgeable part)
        │        audit/                    (hash-chained JSONL)
        ▼
   ┌─────────┐
   │  emit   │  emit-phase plugins/sinks run last, best-effort, spooled on failure
   └─────────┘
```

Two properties are worth calling out, because most of the design follows from
them:

**Fail closed.** If any page fails to extract, the document is marked `degraded`
and quarantined rather than being silently assessed on partial text. A rule that
exceeds its time budget fails the job rather than being skipped. And a document
that yielded *no* text at all — a scan too faint for OCR, an unmappable font, a
damaged content stream — is quarantined as `no_text_extracted`, because "we read
nothing" is not evidence of "there is nothing to find". All three are governed by
`dlp.quarantine_on_degraded`. A file refused before a job even exists — over
`limits.max_bytes`, or a symlink planted in the drop folder — is moved to
`failed/` and audited too, rather than being left where it was and retried on
every poll forever.

Parsing and OCR run in a disposable worker process by default. The configured
`extraction.timeout_seconds` bounds the whole extraction; a worker that exceeds
it is terminated and the document enters the Needs attention queue. A page that
contains embedded images is OCR'd even when it also has a native text heading,
and a page that yields no native or OCR text makes the extraction incomplete.

**Never store the raw match.** A hit records a *masked* form (`••••1111`) plus a
keyed HMAC digest for correlation. "This same value appeared in 12 documents" is
answerable without any of those documents storing the value.

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

`DLPDUCK_HMAC_KEY` must be stable for the life of a deployment — rotating it
makes previously-stored correlation digests incomparable with new ones. It must
never be written into config, the archive, or the audit trail.

> **Upgrade note — correlation digests changed.** Values are now normalised with
> Unicode case folding (NFKC + `casefold`) instead of an ASCII-only rule that
> silently discarded every non-Latin character. The old behaviour reduced *any*
> wholly non-ASCII value to the empty string, so a Cyrillic name, a Japanese
> address and a Greek identifier all shared one digest and correlated as the same
> value. Digests written before this change won't match ones written after it, in
> exactly the way a key rotation wouldn't; run `dlpduck reprocess --commit` to
> re-derive them if you rely on correlation across older documents.

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
  work_dir: /srv/dlpduck/work            # index/, content/, audit/, spool/

audit:
  integrity: chained            # chained | none

retention:                      # opt-in; unset means keep forever
  documents_days: null          # PDFs, failed queue + the content store
  index_days: null
  audit_days: null

console:
  bind: 127.0.0.1:8080         # IPv6 literals in brackets: "[::1]:8080"
  session_secret_env: DLPDUCK_SESSION_SECRET
  session_max_age_seconds: 28800     # 8h; sessions can be revoked sooner
  session_cookie_secure: false       # set true behind TLS
  audit_search_terms: hashed         # hashed | plain — see Security notes
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

### `metadata_fields` is an allowlist

Whatever a companion file (or the PDF's own Info dictionary) carries, **only the
keys named in `source.metadata_fields` are kept**. An empty list — the default —
keeps nothing. This is deliberate: scanner metadata routinely carries user names,
network paths, and device serials that you do not want copied into a permanent
index. Name the fields you actually want:

```yaml
source:
  metadata_fields: [device_id, department, pdf_title]
```

PDF-derived keys are prefixed `pdf_` (`pdf_title`, `pdf_author`, …). Where a
companion file and the PDF both set a key, the companion wins.

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

## The two stores, and what purge actually deletes

Ingest writes to two Parquet stores, and the split is the whole basis of the
purge model:

| | `index/` | `content/` |
|---|---|---|
| Holds | metadata, disposition, **masked** hits | raw `full_text` + structured lines |
| Rows | one per **assessment** (append-only history) | one per job (no history) |
| Purpose | permanent proof the job happened | what makes a job searchable |
| Purge deletes it? | **never** | yes — that's what a purge *is* |

So:

- **Soft purge** (`dlpduck purge-content <job_id>`) deletes the job's content
  file. The document stops being searchable and hits can no longer be revealed.
  The index row, the archived PDF, and the audit trail are untouched — the record
  that the job existed and what was decided about it survives, and none of them
  ever held the raw text.
- **Hard purge** (`--hard`) additionally deletes the archived PDF. A real erasure.
  The index row and audit trail still survive.

Neither rewrites history. A purge appends one new audit event describing itself.

---

## Dates are UTC, everywhere

`dt=` partitions — for the archive, the index, the content store and the audit
log alike — are named from the UTC date, and the console's date filters mean UTC
days. On a machine east of UTC the local calendar can already be tomorrow while
the current partition is still yesterday's, so "today" in a filter is a UTC
today. This is deliberate: partition names have to agree with each other and
with the audit trail across every host that touches the archive, and only UTC
does that.

Purged content stays purged. `dlpduck reindex` — which rebuilds a lost index by
re-extracting from the archived PDFs — checks the audit trail first and refuses to
re-create content for a job that was purged, because a soft purge leaves the PDF
and re-extracting it would silently make erased text searchable again. The index
row is still rebuilt (a soft purge never touched it); the row is marked
`content-withheld` and the operator is told. Restoring that text is then a
deliberate `dlpduck reprocess --mode extract`, not a side effect of recovery.

### Keeping the index fast

The write path produces one small Parquet file per assessment, which is what
makes it atomic and safe under contention. The read path pays for it: DuckDB
opens every file in the glob, so the jobs list and the Overview counters slow
down linearly with the number of documents ever ingested — and the index is
permanent by default. Almost all of that size is per-file overhead rather than
data. Measured on 20,000 single-row assessments:

| | files | index size | jobs-list query |
|---|---|---|---|
| before | 20,000 | 180.4 MB | 2.64 s |
| after  | 1 | 0.5 MB | 0.02 s |

```bash
dlpduck compact-index --config config.yaml            # what it would merge
dlpduck compact-index --config config.yaml --commit
```

Run it from cron. It is safe against a live system and safe to interrupt: the
merged file becomes visible *before* the originals are removed, so the only
window is one where every row is present twice — which every reader already
collapses to one row per job. Today's partition is never touched, because it is
still being appended to.

## The audit trail

`work_dir/audit/dt=YYYY-MM-DD/events.jsonl`, one JSON event per line, each
carrying `seq`, `ts`, `event`, and — when `audit.integrity: chained` — `prev`
(the previous event's hash) and its own `hash`. That makes silent edits
detectable:

```bash
dlpduck verify-audit --config config.yaml
```

Retention can delete whole old partitions. Doing that naively would make the
oldest surviving event's `prev` point at a hash nothing on disk can reproduce,
and `verify` would report it as tampering. `apply_retention` therefore writes a
**trim checkpoint** recording that hash before deleting, so an authorised trim
reads as a recorded fact rather than a hole.

Events include: `job.completed`, `job.failed`, `job.reassessed`, `job.released`,
`purge.started`, `content.purged`, `dlp.revealed`, `pdf.viewed`, `pdf.downloaded`,
`ui.search`, `reprocess.started`, `reprocess.completed`, `index.rebuilt`,
`retention.started`, `retention.applied`, `metadata.rejected`, `plugin.failed`,
`audit.redacted`, `auth.succeeded`, `auth.failed`, `auth.throttled`, `auth.logout`.

### Redacting a single event

Retention is all-or-nothing on a partition. Sometimes one field in one event is
the problem — a search term, a filename inside a parse error — and an erasure
request means it cannot stay:

```bash
dlpduck redact-audit --config config.yaml \
  --seq 4182 --field query --reason "erasure request 41"
```

That empties the named fields in place, leaving `[redacted]` behind. The event
keeps its position in the chain, so `verify-audit` still proves nothing around
it was inserted, removed or reordered — what it stops proving is that one
event's contents. `seq`, `ts`, `event`, `prev` and `hash` cannot be redacted;
removing them would break the chain rather than annotate it. Naming a field the
event doesn't have, or one that can't be redacted, fails the whole call and
removes nothing — a half-completed erasure reported as success is worse than a
refusal.

The removal is itself an `audit.redacted` event, chained like any other and
naming who did it and why. `verify-audit` reports every redacted event even
when the chain is clean, because "intact" and "intact, with three events
emptied" are different answers. An event marked redacted with no matching
`audit.redacted` record — content blanked by hand, in other words — is
reported as a **break**, and so is one emptied in more fields than the records
account for, so a single authorised redaction can't be stretched to cover
later ones.

Irreversible operations record their **intent before acting** and their outcome
after: `purge.started` then `content.purged`, `retention.started` then
`retention.applied`. The append is fsync'd, so a crash partway through leaves a
started record with no completion — visible evidence that a deletion was in
flight, rather than data quietly gone with nothing saying anyone asked for it.

---

## Behaviour as the archive grows

Three reads have no natural bound, and all three are on the hot path:

| Read | Bounded by |
|---|---|
| `/audit` | Newest partitions first, stopping at the page size — safe because `seq` rises with time, so nothing older can displace what's already in hand. |
| A job's timeline | Every partition is still searched (a purge lands long after ingest), but a substring test rejects records before they're decoded. |
| `/jobs` | Server-side filters followed by stable, 100-row pagination. |
| Overview counters | Aggregated in DuckDB rather than by loading every row into Python to count it. |

None of these are tuning: before them, a year of modest traffic meant 127MB and
2.6s to render 500 audit rows, and 48MB to display a job list — both growing for
as long as the deployment runs, since audit retention is opt-in.

## Admin console

```bash
dlpduck console run --config config.yaml
```

Screens: Overview, Jobs, job detail (findings first, receipt history, metadata,
reveal, reprocess, purge, audit timeline), Needs attention, Search, Rules,
Audit, Access. Overview counters open their corresponding filtered queue and a
worker card shows the watcher heartbeat, current activity and drop-folder
backlog. Jobs, Search and Audit have stable server-side pagination.

Needs attention contains refused, failed and interrupted documents. An admin can
inspect the original, retry after correcting the cause, or mark the item resolved
with a recorded reason. A crash during an external emit is called out separately:
retry requires acknowledging that the first delivery may have succeeded. Failed
documents follow `retention.documents_days`, including resolved items.

Document bytes identify an assessment history; each arrival has its own receipt
record with filename, source, allowlisted metadata and outcome. A repeated file
therefore remains visible as a business event without overwriting or duplicating
the document's evidence.

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

A document counts as quarantined if its disposition says so, if a release is
still pending, **or** if the file physically sits under the quarantine root. One
rule decides both whether its PDF can be opened and whether a search result
shows its excerpt — a snippet is a raw slice of the document, so withholding the
PDF while serving its text would make the gate decorative. A de-escalation records the new disposition immediately but
leaves the PDF in quarantine until someone with `quarantine.release` approves
the move — so disposition alone would open that window to Investigator, which is
the exact thing `release_pending` exists to prevent.

`dlp_admin` is the superuser role. The auditor role exists to hold the *opposite*
split: it sees the audit trail and masked hits, but never document text, the
original PDF, or cleartext. If you want strict separation of duties, provision a
real auditor with only the `auditor` role and treat `dlp_admin` as a
carefully-issued privilege.

### Auth

- **OIDC** is the primary path. With `console.auth.oidc` configured, `/login`
  redirects straight to the IdP. Roles come from the `roles_claim` in the ID
  token, mapped through `role_map`, then intersected with the four known roles —
  an IdP's own composite roles are noise, not privileges.
- **Local accounts** are the break-glass/air-gapped fallback, reachable at
  `/login?auth=local` even when SSO is the default. Passwords are argon2id
  hashes in config; generate one with `dlpduck console hash-password`.

---

## CLI reference

| Command | What it does |
|---|---|
| `validate-config` | Parse config, compile every regex, check paths. Also prints warnings for settings that are legal but quietly switch off a guarantee. Use it in CI. |
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

`webhook` posts to exactly the URL you configure. It refuses redirects rather
than following them: a 200 from a redirect target would otherwise read as a
successful delivery while your SIEM received nothing and nothing spooled, and
the signing header would travel to a host you didn't choose. A redirect is a
delivery failure, so the event spools and `replay-sink` can retry it once the
endpoint is fixed.

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

## Security notes

**Threat model.** DLPDuck assumes the drop folder is writable by something less
trusted than the daemon (an MFP's account, a share), that console users are
authenticated but variably privileged, and that the host itself is trusted.

What follows from that:

- **Symlinks in the drop folder are refused**, not followed — otherwise a link
  named `scan.pdf` would get its target's contents ingested into a searchable
  store.
- **`max_bytes` is enforced against what's actually read**, not just a prior
  `stat()`, so a file that grows mid-claim can't exceed it — and a companion
  metadata file is bounded by `max_metadata_bytes` rather than read whole.
- **Untrusted metadata values are length-capped** before they reach the index,
  which outlives a purge; a PDF declares its own Info dictionary, so a hostile
  Title would otherwise be stored verbatim and rendered in the console.
- **A corrupt audit record is reported, not fatal.** One truncated line — the
  ordinary shape of a crash — used to make the whole trail unreadable and stop
  the daemon restarting. Readable history still reads; `verify-audit` reports
  the hole and never passes clean.
- **Oversized pages are rasterised at a reduced dpi.** A PDF declares its own
  page size, and OCR'ing a metres-wide page at 150 dpi is a decompression bomb.
- **Job ids are validated (32 hex chars) before touching the filesystem.** They
  are interpolated into globs to find files, so this is a boundary, not a
  formality: `*` would otherwise turn "purge this job" into "purge everything".
- **Rule ids are constrained** to a safe charset. Rulesets get shared and copied
  between installs; an id ends up in audit events, logs, and console markup.
- **Search is fully parameterised**, with the query length capped, the result
  limit capped, and a wall-clock interrupt on the DuckDB connection.
- **Every rule match is time-bounded** on any thread, so a pathological pattern
  fails its document rather than pinning a core.
- **Reveal is verified, not trusted.** The raw value is never stored, so reveal
  re-derives it from the position the hit recorded — and then checks the result
  reproduces the masked form that *was* stored. If the content has changed under
  those offsets, reveal reports nothing rather than showing an unrelated slice of
  the document beneath a legitimate-looking audit entry.
- **The session is rotated at login**, so nothing chosen while a session was
  anonymous (a planted cookie, an anonymous CSRF token) survives the privilege
  boundary.
- **Sessions are revocable.** The signed browser cookie contains an opaque token
  that must still exist in the operational store. Logout revokes that token;
  administrators can revoke every active session for a user from Access, and
  local-account role or password-hash changes invalidate the old session.
- **A password_hash that isn't one is rejected at boot**, because the usual cause
  is a plaintext password pasted into config.
- **Disaster recovery never declassifies.** A rebuilt row takes its disposition
  from where the PDF is filed, not from re-running today's ruleset — otherwise a
  ruleset change would quietly mark a quarantined document "archive" with no
  release recorded. Disagreements are counted and reported so an operator can run
  a proper, audited `reprocess`.
- **The assessment history can't be silently overwritten.** Two writers racing
  for the same sequence number is refused rather than one clobbering the other.
- **CSRF tokens** are session-bound and required on every mutating form, compared
  in constant time over bytes rather than characters — `secrets.compare_digest`
  raises on a non-ASCII `str`, and the submitted token is attacker-controlled, so
  comparing characters turned one accented byte into a 500 on the guard itself.
- **Malformed input is refused, never a stack trace.** Every console parameter is
  exercised against hostile values in the suite; a 5xx is treated as a bug.
- **Purge requires typing `purge`** in a modal that also collects the reason —
  the one action nothing else in the console can walk back.
- **Failed logins are throttled before the password is checked**, per username
  *and* per client address. Guessing is the obvious risk; the sharper one is
  that argon2id is deliberately expensive and `/login` is unauthenticated, so
  without a ceiling a flood of POSTs — no valid username needed — exhausts
  memory and CPU. The lockout response is identical whether or not the account
  exists, so it doesn't hand back the enumeration the equal-time hashing avoids.
- **Who got in is audited too**, not just what they did afterwards:
  `auth.succeeded` (with the roles granted), `auth.failed`, `auth.throttled` and
  `auth.logout`, for the local and SSO paths alike. The attempted password is
  never recorded — a near-miss is somebody's real password somewhere else.

**The console makes no outbound requests.** Its fonts, stylesheet and images are
all served from `/static`, and the response headers say so: a strict CSP
(`default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`,
`base-uri 'none'`), plus `nosniff`, `X-Frame-Options: DENY` and
`Referrer-Policy: no-referrer`. An air-gapped install therefore renders
identically to a connected one, and no third party learns who is looking at a
DLP console or when. `frame-ancestors` earns its place here specifically:
purge is one click behind a confirmation, and clickjacking is the attack that
turns a click meant for something else into an irreversible deletion.

**Deploy behind TLS.** The console speaks plain HTTP and binds to `127.0.0.1` by
default. Terminate TLS in front of it and set `console.session_cookie_secure:
true` so the session cookie carries `Secure`. Sessions expire after
`session_max_age_seconds` (default 8h) and can be revoked sooner from Access.

**Filesystem permissions.** The daemon and console set the process umask from
config (`umask`, default `"0077"` — owner-only) before writing anything, so
archived PDFs, the content store, and the audit log aren't group- or
world-readable by accident. Widen it to `"0027"` if a reviewer group genuinely
needs filesystem access, or set it to `null` to inherit the invoking shell's.
Still run the daemon as a dedicated user, and keep `quarantine/` on a separate
mount/ACL from `archive/`.

**Known limitations, stated plainly:**

- Rulesets are trusted code — they are compiled regexes from your config. The
  per-rule time budget bounds a catastrophic pattern (it is enforced by the
  `regex` module on whatever thread the scan runs on, ingestion or console), but
  test new patterns with `dlpduck test-rules` before deploying them anyway.
- Audit appends are serialised with a `flock` on `work_dir/audit`. On a
  filesystem that doesn't implement it (some NFSv3 setups), concurrent appenders
  could still interleave — keep `work_dir` on local disk or NFSv4.
- Reporting a vulnerability: please open a private security advisory rather than
  a public issue.

---

## Development

CI (`.github/workflows/ci.yml`) runs the lint and the suite on every push and
PR, validates the shipped example config so it can't drift from the schema it
demonstrates, and — separately — builds the wheel, installs it into a clean
environment with no dev dependencies, and runs the quick start against it. That
last job exists because the suite runs *inside* the dev environment and so
cannot tell a runtime dependency from a dev one, or notice an asset that lives
beside the package rather than inside it. See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
uv sync
uv run pytest -q                       # full suite (~6 min; OCR is the slow part)
uv run pytest -q tests/test_engine.py  # one module
uv run ruff check .                    # lint — clean, and expected to stay that way
```

Two test modules are worth knowing about, because they cover things line
coverage cannot see:

`scripts/mutation_test.py` checks the *tests* rather than the code: it applies
22 hand-picked bugs to safety-critical predicates — reveal a mask tail that
wasn't asked for, accept a broken audit link, write purged content back, grant
every permission — and reports any the suite fails to notice. All 22 are caught.
Run it after changing anything in that list; a survivor means a property the code
holds by accident rather than by test.

```bash
uv run python scripts/mutation_test.py           # all of them (~20 min)
uv run python scripts/mutation_test.py -k audit  # just the audit ones
```

- `tests/test_properties.py` — Hypothesis over the invariants the design rests
  on: masking never reproduces a value, a hit's offsets always point at what it
  matched, correlation is keyed and stable. These are claims about *all* inputs,
  and the inputs are documents an organisation did not write. It earned its place
  immediately by finding that correlation's normaliser was ASCII-only, so every
  wholly non-Latin value shared one digest.
- `tests/test_concurrency.py` — properties that only fail with more than one
  writer: the audit chain under parallel appends and across real processes, and
  the assessment-history guard under genuine contention. Both were reasoned about
  before they were ever run in parallel.
- `tests/test_malformed_pdfs.py` — broken, hostile and merely awkward documents.
  A real corpus can't be synthesised, but the guarantee can: nothing unreadable
  reaches the clean archive.
- `tests/test_scale.py` — reads that are unbounded by nature: the audit browser,
  a job's timeline, the job list, and the Overview's counters. Each is asserted
  on work done (rows held, memory) rather than wall-clock, so they don't go
  flaky on a loaded machine.
- `tests/test_schema_evolution.py` — an index written by an older release must
  still read. Without `union_by_name` the first added column takes out every
  historical row, not just the old ones.
- `tests/test_ocr_integration.py` — the path the product exists for. Every
  other test builds PDFs that already carry a text layer, which quietly stubs
  out the slow half of the system; these rasterise a page and run the real OCR
  model over it, end to end into a quarantine decision.

`ruff format` is deliberately *not* enforced: several comments here are prose that
wraps where it reads best. Match the surrounding style rather than reformatting.

Layout:

```
dlpduck/
  watcher.py      drop-folder polling and stability detection
  pipeline.py     claim → process → dispose → commit
  extract.py      per-page native/OCR extraction, row clustering
  engine.py       rule evaluation
  rules.py        rule parsing/compilation
  validators.py   luhn / iban / nhs checksums
  masking.py      mask() and correlate()
  index.py        metadata store writes
  content.py      content store writes, reads, purge
  search.py       DuckDB join across both stores
  reprocess.py    reassessment history, release
  reindex.py      disaster recovery
  retention.py    partition-level deletion
  audit.py        hash-chained JSONL
  plugins/        base, loader, sinks, enrich, spool
  console/        FastAPI app, auth, RBAC, CSRF, templates
```

Tests mirror that layout in `tests/`. New behaviour needs a test; security
boundaries (job id validation, symlink refusal, RBAC, CSRF) need one that proves
the *negative* case too.

---

## Reporting a vulnerability

Please don't open a public issue. [SECURITY.md](SECURITY.md) has the private
reporting route, and — more usefully — states which properties count as
vulnerabilities, which don't (config is trusted input; plugins run in-process),
and the risks that are knowingly accepted and documented.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the setup, the one principle worth
internalising before changing anything, and which test module covers the things
line coverage cannot see.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE).

The console ships the IBM Plex typeface (`dlpduck/console/static/fonts/`), which
is licensed separately under the SIL Open Font License 1.1 — see
[fonts/LICENSE.txt](dlpduck/console/static/fonts/LICENSE.txt). It is bundled
rather than fetched from a CDN so the console works with no route to the
internet, and emits no telemetry to a third party.
