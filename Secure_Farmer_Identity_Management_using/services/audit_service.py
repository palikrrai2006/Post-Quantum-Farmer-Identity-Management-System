"""
services/audit_service.py
===========================
Central audit logging. NEVER pass plaintext biometric data, AES keys, or
PQC secret keys into `action` or any other field here (spec section 6.8/39).
"""

from storage.db import db_cursor


def log_action(user_id, role, action, target_farmer_id=None, ip_address=None, result="SUCCESS"):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO audit_logs (user_id, role, action, target_farmer_id, ip_address, result)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, role, action, target_farmer_id, ip_address, result),
        )


def get_audit_logs_for_farmer(farmer_id: str):
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM audit_logs WHERE target_farmer_id = ? ORDER BY timestamp DESC", (farmer_id,)
        )
        return cur.fetchall()


def get_all_audit_logs(limit: int = 500):
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
        return cur.fetchall()


def count_todays_verifications() -> int:
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT COUNT(*) AS n FROM audit_logs "
            "WHERE action LIKE 'VERIFY%' AND DATE(timestamp) = DATE('now') AND result='SUCCESS'"
        )
        return cur.fetchone()["n"]


def count_total_verifications() -> int:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT COUNT(*) AS n FROM audit_logs WHERE action LIKE 'VERIFY%'")
        return cur.fetchone()["n"]
