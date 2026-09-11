"""Retention: drop dated store partitions and failed-job directories past
a configured window. Deletion is directory-level
and dry-run by default so a bad config cannot silently remove data.

Every store carries its own window and its own config field
(`retention.documents_days` / `index_days` / `audit_days`) — a store with
no window configured (None) is never touched. "documents" covers the
archived PDFs (both destination.archive and destination.quarantine), failed
documents, and the content store together: all hold raw, purgeable content and
naturally share one retention question. The metadata index and the audit
trail are each their own concern — audit almost always outlives content.

Deleting old audit partitions specifically needs one extra step beyond a
plain rmtree: dlpduck.audit.AuditLog.write_trim_checkpoint records, before
the delete, the hash the chain should resume verifying from — otherwise
verify() would report an authorized trim as if it were tampering.
"""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

from dlpduck.audit import AuditLog
from dlpduck.config import Config

logger = logging.getLogger("dlpduck.retention")


@dataclass
class RetentionPlan:
    store: str  # human label: "archive" | "quarantine" | "content" | "index" | "audit"
    root: Path
    cutoff: date | None  # None means retention isn't configured for this store
    eligible: list[Path] = field(default_factory=list)  # dt= directories past the cutoff


def eligible_partitions(root: Path, cutoff: date) -> list[Path]:
    root = Path(root)
    if not root.is_dir():
        return []
    out = []
    for p in sorted(root.glob("dt=*")):
        if not p.is_dir():
            continue
        try:
            partition_date = date.fromisoformat(p.name.removeprefix("dt="))
        except ValueError:
            continue  # not a dt= directory in the expected shape — leave it alone
        if partition_date < cutoff:
            out.append(p)
    return out


def eligible_failures(root: Path, cutoff: date) -> list[Path]:
    """Failed documents are job directories rather than date partitions."""
    if not root.is_dir():
        return []
    eligible = []
    for folder in sorted(root.iterdir()):
        if not folder.is_dir() or folder.is_symlink():
            continue
        try:
            metadata = json.loads((folder / "metadata.json").read_text())
            received = date.fromisoformat(metadata["received_at"][:10])
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if received < cutoff:
            eligible.append(folder)
    return eligible


def plan_retention(config: Config, today: date | None = None) -> list[RetentionPlan]:
    today = today or date.today()
    r = config.retention

    def cutoff_for(days: int | None) -> date | None:
        return today - timedelta(days=days) if days is not None else None

    doc_cutoff = cutoff_for(r.documents_days)
    index_cutoff = cutoff_for(r.index_days)
    audit_cutoff = cutoff_for(r.audit_days)

    targets = [
        ("archive", config.destination.archive, doc_cutoff),
        ("quarantine", config.destination.quarantine, doc_cutoff),
        ("content", config.destination.work_dir / "content", doc_cutoff),
        ("failed", config.destination.work_dir / "failed", doc_cutoff),
        ("index", config.destination.work_dir / "index", index_cutoff),
        ("audit", config.audit_dir, audit_cutoff),
    ]
    plans = []
    for store, root, cutoff in targets:
        if cutoff is None:
            eligible = []
        elif store == "failed":
            eligible = eligible_failures(Path(root), cutoff)
        else:
            eligible = eligible_partitions(root, cutoff)
        plans.append(RetentionPlan(store=store, root=Path(root), cutoff=cutoff, eligible=eligible))
    return plans


def apply_retention(plans: list[RetentionPlan], audit: AuditLog) -> int:
    """Actually delete the eligible partitions. The audit store's
    partitions are checkpointed first so verify() can still confirm the
    surviving chain is intact — every other store has no such concern,
    since none of them are hash-chained.
    """
    removed = 0
    for plan in plans:
        if not plan.eligible:
            continue
        # Same reasoning as a purge: the intent is recorded before the
        # first rmtree, because a sweep interrupted halfway would
        # otherwise destroy partitions and leave nothing saying it had
        # started. Retention deletes in bulk, so that gap is wider here
        # than anywhere else in the system.
        audit.append(
            "retention.started",
            store=plan.store,
            cutoff=plan.cutoff.isoformat() if plan.cutoff else None,
            partitions=[p.name for p in plan.eligible],
            count=len(plan.eligible),
        )
        if plan.store == "audit":
            audit.write_trim_checkpoint(plan.eligible)
        for path in plan.eligible:
            shutil.rmtree(path)
            removed += 1
        logger.debug("retention: removed %d partition(s) from %s (cutoff=%s)", len(plan.eligible), plan.store, plan.cutoff)
        # Retention is a deletion of evidence, so it is itself evidence:
        # without this, "the document from March is gone" has no recorded
        # explanation, and a policy-driven delete is indistinguishable
        # from an unexplained one. Written per store, after the fact, so
        # it reflects what actually happened rather than what was planned.
        audit.append(
            "retention.applied",
            store=plan.store,
            cutoff=plan.cutoff.isoformat() if plan.cutoff else None,
            partitions_removed=[p.name for p in plan.eligible],
            count=len(plan.eligible),
        )
    return removed
