"""Seeing THAT something happened is a different privilege from
seeing WHAT it contained, and both differ from CHANGING what the system
does. The gaps in the matrix are deliberate separation of duties.
"""

import pytest

from dlpduck.console.rbac import (
    ALL_ROLES,
    AUDITOR,
    DLP_ADMIN,
    INVESTIGATOR,
    VIEWER,
    has_permission,
    permissions_for,
)


class TestBasicPermissions:
    def test_everyone_can_list_and_read_metadata(self):
        for role in ALL_ROLES:
            assert has_permission({role}, "jobs.list")
            assert has_permission({role}, "jobs.metadata.read")

    def test_viewer_cannot_see_hit_details(self):
        assert has_permission({VIEWER}, "dlp.hits.read") is False

    def test_investigator_can_see_masked_hits_but_not_reveal(self):
        assert has_permission({INVESTIGATOR}, "dlp.hits.read") is True
        assert has_permission({INVESTIGATOR}, "dlp.reveal") is False

    def test_only_dlp_admin_can_reveal_cleartext(self):
        for role in (VIEWER, INVESTIGATOR, AUDITOR):
            assert has_permission({role}, "dlp.reveal") is False
        assert has_permission({DLP_ADMIN}, "dlp.reveal") is True

    def test_unknown_permission_raises_rather_than_silently_denying(self):
        # A typo'd permission string should be loud, not a quiet "no".
        with pytest.raises(ValueError, match="unknown permission"):
            has_permission({DLP_ADMIN}, "jobs.definitely_not_a_real_permission")


class TestSeparationOfDuties:
    """What remains after DLP Admin became a superuser role: Auditor is
    still read-only and can't touch documents, rules, or releases — a
    dedicated auditor account still can't act, even though the admin
    account can now both act and read the audit trail (a deliberate
    trade-off — see rbac.py's module docstring).
    """

    def test_auditor_cannot_read_document_content(self):
        assert has_permission({AUDITOR}, "jobs.text.read") is False
        assert has_permission({AUDITOR}, "jobs.pdf.read") is False

    def test_auditor_cannot_change_rules_or_release_documents(self):
        assert has_permission({AUDITOR}, "rules.write") is False
        assert has_permission({AUDITOR}, "quarantine.release") is False
        assert has_permission({AUDITOR}, "jobs.purge") is False

    def test_dlp_admin_is_the_superuser_role_and_can_read_the_audit_trail(self):
        # DLP Admin holds every permission by default (see the module
        # docstring for why this changed from the original stricter
        # design) — a small install's one admin account shouldn't be
        # locked out of its own audit trail.
        assert has_permission({DLP_ADMIN}, "audit.read") is True
        assert has_permission({DLP_ADMIN}, "audit.verify") is True

    def test_only_auditor_and_dlp_admin_hold_audit_permissions(self):
        for role in (VIEWER, INVESTIGATOR):
            assert has_permission({role}, "audit.read") is False
            assert has_permission({role}, "audit.verify") is False
        assert has_permission({AUDITOR}, "audit.read") is True
        assert has_permission({AUDITOR}, "audit.verify") is True
        assert has_permission({DLP_ADMIN}, "audit.read") is True
        assert has_permission({DLP_ADMIN}, "audit.verify") is True


class TestRoleComposition:
    def test_roles_compose_additively(self):
        # A user holding both viewer and auditor gets the union, not
        # whichever role happens to be checked "first".
        combined = {VIEWER, AUDITOR}
        assert has_permission(combined, "audit.read")  # from auditor
        assert has_permission(combined, "jobs.list")  # from either

    def test_empty_roles_grants_nothing(self):
        assert has_permission(set(), "jobs.list") is False

    def test_permissions_for_returns_the_full_grant_set(self):
        perms = permissions_for({VIEWER})
        assert "jobs.list" in perms
        assert "dlp.reveal" not in perms

    def test_permissions_for_union_across_multiple_roles(self):
        perms = permissions_for({VIEWER, DLP_ADMIN})
        assert "dlp.reveal" in perms  # only from dlp_admin
        assert "jobs.list" in perms  # from either
