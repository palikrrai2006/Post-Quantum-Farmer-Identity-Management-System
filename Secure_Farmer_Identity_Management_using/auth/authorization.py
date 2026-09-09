"""
auth/authorization.py
=======================
Server-side Role-Based Access Control (RBAC).

CRITICAL RULE (spec section 10): authorization is enforced HERE, on every
backend endpoint, via auth/decorators.py — never by hiding a frontend button.
"""

import config

PERMISSIONS = {
    config.ROLE_FARMER: {
        "view_own_profile", "update_allowed_profile_fields", "view_own_land_records",
        "view_own_benefits", "view_own_schemes", "view_own_fingerprint_status",
        "request_correction",
    },
    config.ROLE_REGISTRATION_CENTER_OPERATOR: {
        "register_farmer", "capture_fingerprint", "register_fingerprint",
        "submit_registration", "view_center_registrations",
    },
    config.ROLE_GOVERNMENT_OFFICER: {
        "search_farmer", "view_authorized_farmer_profile", "verify_farmer_identity",
        "manage_land_records", "manage_benefits", "manage_schemes", "approve_farmer",
        "view_authorized_audit_records",
    },
    config.ROLE_ADMIN: {
        "manage_users", "manage_registration_centers", "manage_government_officers",
        "manage_roles", "view_system_logs", "manage_configuration",
    },
}


def role_has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, set())


def farmer_owns_record(session_farmer_id: str, target_farmer_id: str) -> bool:
    """A FARMER role may only ever act on their own farmer_id."""
    return session_farmer_id is not None and session_farmer_id == target_farmer_id
