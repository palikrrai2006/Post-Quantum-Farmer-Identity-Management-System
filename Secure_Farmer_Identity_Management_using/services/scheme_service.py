"""
services/scheme_service.py
============================
Government schemes CRUD — write access restricted to GOVERNMENT_OFFICER
(enforced at the route layer via @require_permission("manage_schemes")).
"""

from storage.db import db_cursor


def list_schemes(status: str = None):
    with db_cursor(commit=False) as cur:
        if status:
            cur.execute("SELECT * FROM government_schemes WHERE status = ? ORDER BY created_at DESC", (status,))
        else:
            cur.execute("SELECT * FROM government_schemes ORDER BY created_at DESC")
        return cur.fetchall()


def create_scheme(scheme_name: str, description: str, eligibility: str, start_date: str, end_date: str):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO government_schemes (scheme_name, description, eligibility, start_date, end_date)
               VALUES (?, ?, ?, ?, ?)""",
            (scheme_name, description, eligibility, start_date, end_date),
        )
        return cur.lastrowid


def close_scheme(scheme_id: int):
    with db_cursor() as cur:
        cur.execute(
            "UPDATE government_schemes SET status='CLOSED', updated_at = datetime('now') WHERE scheme_id = ?",
            (scheme_id,),
        )
