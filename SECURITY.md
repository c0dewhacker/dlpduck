# Security policy

DLPDuck handles documents that are, by definition, the ones an organisation most
wants to control. Please treat findings accordingly.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Use GitHub's private
vulnerability reporting ("Report a vulnerability" on the Security tab), which
opens a private advisory visible only to the maintainers.

Please include:

- what an attacker can do, and what access they need to start
- the smallest reproduction you have — a config snippet, a rule, a crafted PDF
  (a description is fine if sharing the file isn't)
- the version or commit

You'll get an acknowledgement within a few days. Fixes for anything that leaks
document content, bypasses RBAC, or corrupts the audit trail take priority over
everything else.

## What counts

These are the properties DLPDuck is meant to hold. A way to break one is a
vulnerability:

| Property | Meaning |
|---|---|
| Raw matches are never stored | A DLP hit records a masked form and a keyed HMAC. Any path that persists, logs, or forwards the cleartext of a match is a bug. |
| Raw document text follows the document | If a role may not open a document, no other screen may serve raw text from it — search excerpts included. |
| Cleartext reveal is privileged, audited, and verified | Only `dlp.reveal` re-derives a value; every reveal appends an audit event; and a re-derived value is displayed only if it reproduces the masked form recorded at scan time. |
| Role boundaries hold | An auditor must not reach document text or PDFs; a viewer must not reach hit details; only `dlp_admin` reaches quarantined PDFs and cleartext. A document awaiting release still counts as quarantined. |
| Purge deletes what it says, and it stays deleted | A soft purge removes content and nothing else; a hard purge also removes the PDF. Neither rewrites the index row or the audit trail — and no recovery path puts purged content back. |
| Deletions are never invisible | Purge and retention record intent before acting, so an interrupted deletion still leaves evidence it began. |
| The audit chain is tamper-evident | Editing or removing an event must make `dlpduck verify-audit` fail, except through a recorded trim checkpoint. |
| Ingestion is bounded | A crafted PDF must not be able to exhaust memory, pin a core indefinitely, or read files outside the drop folder. |
| Unread is not clean | A document DLPDuck could not extract must never be filed as though it were assessed and found harmless. |

## What doesn't count

- **Anything requiring write access to the config file or ruleset.** Config is
  trusted input: it names plugins to import and regexes to compile. If an
  attacker can edit it, they already have code execution as the daemon user.
- **A plugin misbehaving.** Third-party plugins run in-process with full access
  to `JobContext`. Vet them like any other dependency.
- **The console over plain HTTP.** It binds to `127.0.0.1` and expects TLS
  termination in front. Deploying it exposed without TLS is a deployment error;
  see the README's security notes.
- **Denial of service by an authenticated admin.** An admin can already purge.

## Known accepted risks

Documented rather than fixed, and stated plainly so you can decide whether they
matter in your deployment:

- **Permissions come from the umask, not per-file chmod.** The daemon sets it
  from config (default `0077`) before writing anything. Files created before an
  upgrade to that default keep their old modes — check them.
- **Exact search queries are optional permanent evidence.** The default
  `console.audit_search_terms: hashed` records a keyed digest, so repeated
  searches correlate without copying a sensitive query into the audit trail.
  Selecting `plain` is an explicit policy choice; it makes the query readable by
  Auditors until a separately recorded audit redaction.
- **Audit appends need a working `flock`.** Concurrent writers — the daemon and
  the console are two processes over one work directory — are serialised with a
  cross-process file lock, and each re-reads the chain head from disk inside it.
  On a filesystem that does not implement `flock` (some NFSv3 setups), that
  degrades to the single-writer assumption it replaced, and interleaved appends
  would break the chain. Keep `work_dir` on local disk or NFSv4.
- **Recovery reads purges from the audit trail.** `dlpduck reindex` refuses to
  re-extract content for a job the trail records as purged, so a rebuild cannot
  reverse an erasure. That depends on the purge record still being on disk: an
  install whose `retention.audit_days` is shorter than `retention.documents_days`
  can age out a `content.purged` event while its PDF survives, and a rebuild
  after that has no way to know. Keep the audit window at least as long as the
  document window.
- **PDFium parses untrusted PDFs.** Parsing and OCR run in a time-bounded worker
  process, so a crash or hang cannot take down the long-running daemon. This is
  process isolation rather than a privilege sandbox; keep pypdfium2 updated and
  apply OS-level isolation where hostile input is expected.

## Supported versions

Pre-1.0: fixes land on `main`. Pin a commit and watch releases if you're
deploying it.
