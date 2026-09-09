"""
services/benefit_service.py
=============================
Benefits/payments — farmers may only VIEW theirs; only government officers
can create, approve, reject, or record payment (spec section 6.7/9).
"""

from storage.db import db_cursor


def get_benefits_for_farmer(farmer_id: str):
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM benefits WHERE farmer_id = ? ORDER BY created_at DESC", (farmer_id,))
        return cur.fetchall()


def create_benefit(scheme_id: int, farmer_id: str, benefit_name: str, description: str, amount: float):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO benefits (scheme_id, farmer_id, benefit_name, description, amount, status)
               VALUES (?, ?, ?, ?, ?, 'PENDING')""",
            (scheme_id, farmer_id, benefit_name, description, amount),
        )
        return cur.lastrowid


def approve_benefit(benefit_id: int, approved_by: int):
    with db_cursor() as cur:
        cur.execute(
            """UPDATE benefits SET status='APPROVED', approved_by=?, approved_at=datetime('now')
               WHERE benefit_id = ?""",
            (approved_by, benefit_id),
        )


def reject_benefit(benefit_id: int, approved_by: int):
    with db_cursor() as cur:
        cur.execute(
            """UPDATE benefits SET status='REJECTED', approved_by=?, approved_at=datetime('now')
               WHERE benefit_id = ?""",
            (approved_by, benefit_id),
        )


def record_payment(benefit_id: int, payment_reference: str):
    with db_cursor() as cur:
        cur.execute(
            """UPDATE benefits SET status='PAID', payment_reference=?, payment_date=datetime('now')
               WHERE benefit_id = ? AND status = 'APPROVED'""",
            (payment_reference, benefit_id),
        )
