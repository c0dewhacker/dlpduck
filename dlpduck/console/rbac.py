"""Role-based access control. Four roles, built on one idea: seeing THAT
something happened is a different privilege from seeing WHAT it
contained, and both differ from CHANGING what the system does.

DLP Admin holds every permission by default — it's the superuser role.
This is a deliberate reversal of this module's earlier design, which
withheld audit.read/audit.verify from DLP Admin specifically so no single
account could both act and erase the evidence of acting (a real
separation-of-duties property). That property is valuable for a deployment that
wants it, but it isn't the right default for a small install where the
admin account IS the one person operating the whole thing and being
locked out of the audit trail on their own system is just friction. A
deployment that wants the stricter separation back can still get it: give
a real auditor a distinct account with only the `auditor` role, and treat
`dlp_admin` as privileged enough that who holds it is controlled
carefully — the protection moves from "the matrix forbids it" to "the
account is provisioned narrowly," same as most break-glass admin roles
work in practice.
"""

from __future__ import annotations

Role = str

VIEWER = "viewer"
INVESTIGATOR = "investigator"
DLP_ADMIN = "dlp_admin"
AUDITOR = "auditor"

ALL_ROLES = (VIEWER, INVESTIGATOR, DLP_ADMIN, AUDITOR)

# permission -> roles that hold it
_MATRIX: dict[str, tuple[Role, ...]] = {
    "jobs.list": ALL_ROLES,
    "jobs.failed.manage": (DLP_ADMIN,),
    "jobs.metadata.read": ALL_ROLES,
    "dlp.hits.read": (INVESTIGATOR, DLP_ADMIN, AUDITOR),  # masked values only
    "jobs.text.read": (INVESTIGATOR, DLP_ADMIN),
    "jobs.pdf.read": (INVESTIGATOR, DLP_ADMIN),
    "jobs.pdf.read.quarantined": (DLP_ADMIN,),
    "dlp.reveal": (DLP_ADMIN,),  # cleartext
    "quarantine.release": (DLP_ADMIN,),
    "rules.read": ALL_ROLES,
    "rules.write": (DLP_ADMIN,),
    "jobs.reprocess.preview": (INVESTIGATOR, DLP_ADMIN),
    "jobs.reprocess.commit": (DLP_ADMIN,),
    "jobs.purge": (DLP_ADMIN,),
    "audit.read": (AUDITOR, DLP_ADMIN),
    "audit.verify": (AUDITOR, DLP_ADMIN),
    "access.write": (DLP_ADMIN,),
}


def has_permission(roles: set[Role], permission: str) -> bool:
    """A user may hold several roles (they compose additively) — true if
    ANY of the user's roles grants this permission.
    """
    try:
        grantees = _MATRIX[permission]
    except KeyError:
        raise ValueError(f"unknown permission: {permission!r}") from None
    return any(r in grantees for r in roles)


def permissions_for(roles: set[Role]) -> set[str]:
    return {perm for perm, grantees in _MATRIX.items() if any(r in grantees for r in roles)}
