"""
services/center_service.py
===========================
Registration Center and Operator management.
Government officers create centers; centers get operators assigned.
"""

from storage.db import db_cursor
from auth.authentication import create_user


def list_centers():
    with db_cursor(commit=False) as cur:
        cur.execute(
            """SELECT rc.*, u.username AS operator_username
               FROM registration_centers rc
               LEFT JOIN users u ON rc.operator_user_id = u.user_id
               ORDER BY rc.created_at DESC"""
        )
        return cur.fetchall()


def get_center(center_id: int):
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM registration_centers WHERE center_id = ?", (center_id,))
        return cur.fetchone()


def create_center(center_name: str, registration_number: str, address: str,
                  district: str, state: str) -> int:
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO registration_centers
               (center_name, registration_number, address, district, state, status)
               VALUES (?, ?, ?, ?, ?, 'ACTIVE')""",
            (center_name, registration_number, address, district, state),
        )
        return cur.lastrowid


def count_centers() -> int:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT COUNT(*) AS n FROM registration_centers WHERE status='ACTIVE'")
        return cur.fetchone()["n"]


def list_operators():
    """All users with REGISTRATION_CENTER_OPERATOR role."""
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM users WHERE role='REGISTRATION_CENTER_OPERATOR' ORDER BY created_at DESC"
        )
        return cur.fetchall()


def create_operator(username: str, password: str, center_id: int) -> int:
    """Create a new operator user and assign to the given center."""
    user_id = create_user(username, password, 'REGISTRATION_CENTER_OPERATOR')
    with db_cursor() as cur:
        # Assign operator to center
        cur.execute(
            "UPDATE registration_centers SET operator_user_id = ? WHERE center_id = ?",
            (user_id, center_id),
        )
    return user_id

