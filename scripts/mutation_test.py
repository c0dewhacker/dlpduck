"""Targeted mutation testing.

Random AST mutation over 2,900 statements would take hours and mostly
produce equivalent or uninteresting mutants. These are hand-picked: each
is a plausible bug a real change could introduce in a safety-critical
predicate, and each SHOULD be caught. A survivor is a gap in the suite —
a property the code holds by accident rather than by test.
"""
import argparse
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]

# (label, file, old, new, test target)
MUTATIONS = [
    # ---- masking: the never-store-the-raw-value guarantee
    ("mask: reveal a tail even when asked for none",
     "dlpduck/masking.py", "if keep <= 0 or len(chars) <= keep + 3:", "if len(chars) <= keep + 3:",
     "tests/test_masking.py tests/test_properties.py"),
    ("mask: reveal a tail on a short value",
     "dlpduck/masking.py", "if keep <= 0 or len(chars) <= keep + 3:", "if keep <= 0:",
     "tests/test_masking.py tests/test_properties.py"),
    ("correlate: drop the key (unkeyed digest)",
     "dlpduck/masking.py", "hmac.new(key, _normalize(raw).encode(\"utf-8\"), hashlib.sha256)",
     "hmac.new(b'', _normalize(raw).encode(\"utf-8\"), hashlib.sha256)",
     "tests/test_masking.py tests/test_properties.py"),

    # ---- job id validation: the purge-everything guard
    ("job id: accept anything",
     "dlpduck/content.py", '_JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")',
     '_JOB_ID_RE = re.compile(r".*")',
     "tests/test_cli.py::TestPurgeContentCommand tests/test_pipeline.py"),

    # ---- fail closed
    ("claim: follow symlinks out of the drop folder",
     "dlpduck/pipeline.py", "if pdf_path.is_symlink():", "if False:",
     "tests/test_fail_closed.py tests/test_pipeline.py"),
    ("claim: skip the stat-based size refusal",
     "dlpduck/pipeline.py", "if size > self.config.limits.max_bytes:", "if False:",
     "tests/test_fail_closed.py"),
    ("claim: skip the bounded-read size refusal",
     "dlpduck/pipeline.py", "if len(pdf_bytes) > limit:", "if False:",
     "tests/test_fail_closed.py"),

    # ---- audit integrity
    ("verify: accept a broken prev link",
     "dlpduck/audit.py", 'if event.get("prev") != prev_hash:', "if False:",
     "tests/test_audit.py"),
    ("verify: accept a rewritten event body",
     "dlpduck/audit.py", "if claimed != recomputed:", "if False:",
     "tests/test_audit.py"),
    ("verify: accept an unexplained redaction",
     "dlpduck/audit.py", "if redaction.seq not in explained:", "if False:",
     "tests/test_audit.py"),
    ("redact: allow the chain fields to be emptied",
     "dlpduck/audit.py", 'protected = {"seq", "ts", "event", "prev", "hash", "redacted"}',
     "protected = set()", "tests/test_audit.py"),
    ("append: skip the cross-process lock",
     "dlpduck/audit.py", "fcntl.flock(fd, fcntl.LOCK_EX)", "pass",
     "tests/test_concurrency.py"),
    # Targeted by its surrounding comment: the same statement appears in
    # __init__, and removing THAT one is an equivalent mutant precisely
    # because this one re-reads.
    ("append: trust the cached chain head instead of re-reading",
     "dlpduck/audit.py",
     "the lock is now the chain's real tail.\n                self._seq, self._prev_hash = self._resume()",
     "the lock is now the chain's real tail.\n                pass",
     "tests/test_concurrency.py"),

    # ---- recovery must not resurrect erased content
    ("reindex: write purged content back",
     "dlpduck/reindex.py", "if was_purged:", "if False:",
     "tests/test_reindex.py"),
    ("reindex: forget which jobs were purged",
     "dlpduck/reindex.py",
     'return self.pipeline.audit.job_ids_with_event("purge.started", "content.purged")',
     "return set()", "tests/test_reindex.py"),
    ("reindex: re-judge disposition with today's ruleset",
     "dlpduck/reindex.py", "disposition = located_disposition",
     "disposition = ruleset_disposition", "tests/test_reindex.py"),

    # ---- reprocess idempotency
    ("relocate: report an already-moved PDF as gone",
     "dlpduck/reprocess.py", "if dest.is_file():", "if False:",
     "tests/test_reprocess.py"),
    ("assessment write: allow a concurrent write to be clobbered",
     "dlpduck/index.py", "exclusive=exclusive", "exclusive=False",
     "tests/test_concurrency.py tests/test_reprocess.py"),

    # ---- console authorisation
    ("rbac: grant every permission",
     "dlpduck/console/rbac.py", "def has_permission(", "def has_permission_unused(",
     "tests/test_rbac.py"),
    ("csrf: accept any token",
     "dlpduck/console/csrf.py", "if not expected or not _matches(expected, submitted):",
     "if False:", "tests/test_console_app.py"),
    ("login: never throttle",
     "dlpduck/console/auth.py", "return any(len(self._recent(k, now)) >= self.max_failures",
     "return False and any(len(self._recent(k, now)) >= self.max_failures",
     "tests/test_console_auth.py tests/test_console_app.py"),

    # ---- durability
    ("atomic write: publish the name before the data is durable",
     "dlpduck/durability.py", "os.replace(tmp, path)", "shutil.copy(tmp, path)",
     "tests/test_audit.py tests/test_concurrency.py"),
]


def run(label, rel, old, new, target):
    path = REPO / rel
    original = path.read_text()
    if old not in original:
        return "SKIP (pattern not found — code moved?)"
    path.write_text(original.replace(old, new, 1))
    try:
        # S603/S607: the argv is built from this module's own MUTATIONS
        # table, never from user input, and the tool is deliberately the
        # `uv` on PATH so it picks up the project environment.
        proc = subprocess.run(  # noqa: S603
            ["uv", "run", "pytest", "-x", "-q", "-p", "no:cacheprovider", *target.split()],  # noqa: S607
            cwd=REPO, capture_output=True, text=True, timeout=1800,
        )
        return "caught" if proc.returncode != 0 else "SURVIVED"
    except subprocess.TimeoutExpired:
        return "caught (timeout)"
    finally:
        path.write_text(original)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-k", dest="pattern", default="", help="only run matching mutations")
    args = parser.parse_args()
    selected = [m for m in MUTATIONS if args.pattern.lower() in m[0].lower()]

    survivors = []
    for i, (label, rel, old, new, target) in enumerate(selected, 1):
        verdict = run(label, rel, old, new, target)
        mark = "ok  " if verdict.startswith("caught") else "MISS"
        print(f"  [{i:2}/{len(selected)}] {mark} {label}  -> {verdict}", flush=True)
        if verdict == "SURVIVED":
            survivors.append(label)
    print()
    print(f"{len(selected) - len(survivors)}/{len(selected)} mutations caught")
    if survivors:
        print("SURVIVORS (gaps in the suite):")
        for s in survivors:
            print("   -", s)
    sys.exit(1 if survivors else 0)
