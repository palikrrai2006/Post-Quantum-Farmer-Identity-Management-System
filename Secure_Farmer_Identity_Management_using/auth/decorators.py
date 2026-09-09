"""
auth/decorators.py
====================
@login_required and @require_role(...) — applied to EVERY protected Flask
route. This is what makes RBAC a backend guarantee instead of a UI nicety.
"""

from functools import wraps
from flask import session, redirect, url_for, abort, request

from auth.authorization import role_has_permission
from services.audit_service import log_action


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("index", next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


def require_role(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("index", next=request.path))
            role = session.get("role")
            if role not in allowed_roles:
                log_action(
                    user_id=session.get("user_id"), role=role, action=f"ACCESS_DENIED:{request.path}",
                    target_farmer_id=None, result="DENIED",
                )
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


def require_permission(permission: str):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("index", next=request.path))
            role = session.get("role")
            if not role_has_permission(role, permission):
                log_action(
                    user_id=session.get("user_id"), role=role,
                    action=f"PERMISSION_DENIED:{permission}", target_farmer_id=None, result="DENIED",
                )
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped
    return decorator
