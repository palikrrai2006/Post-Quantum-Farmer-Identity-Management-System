"""
services/land_service.py
==========================
Land records: farmers may only VIEW; only government officers may create
or verify/modify (spec section 6.5). Corrections go through
correction_requests instead of direct mutation by the farmer.
"""

from storage.db import db_cursor


def get_land_records(farmer_id: str):
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM land_records WHERE farmer_id = ? ORDER BY created_at DESC", (farmer_id,))
        return cur.fetchall()


def create_land_record(farmer_id: str, survey_number: str, land_area: float, area_unit: str,
                        village: str, taluk: str, district: str, state: str,
                        land_type: str, ownership_type: str, verified_by: int):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO land_records
               (farmer_id, survey_number, land_area, area_unit, village, taluk, district, state,
                land_type, ownership_type, verification_status, verified_by, verified_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, datetime('now'))""",
            (farmer_id, survey_number, land_area, area_unit, village, taluk, district, state,
             land_type, ownership_type, verified_by),
        )


def update_land_record(land_record_id: int, verified_by: int, **fields):
    """Only government officers should be able to reach this (enforced by @require_permission)."""
    if not fields:
        return
    allowed = {"survey_number", "land_area", "area_unit", "village", "taluk", "district",
               "state", "land_type", "ownership_type", "verification_status"}
    set_clauses = []
    values = []
    for k, v in fields.items():
        if k in allowed:
            set_clauses.append(f"{k} = ?")
            values.append(v)
    if not set_clauses:
        return
    set_clauses.append("verified_by = ?")
    values.append(verified_by)
    set_clauses.append("verified_at = datetime('now')")
    set_clauses.append("updated_at = datetime('now')")
    values.append(land_record_id)

    with db_cursor() as cur:
        cur.execute(f"UPDATE land_records SET {', '.join(set_clauses)} WHERE land_record_id = ?", values)


def request_land_correction(farmer_id: str, details: str):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO correction_requests (farmer_id, request_type, details) VALUES (?, 'LAND', ?)",
            (farmer_id, details),
        )
