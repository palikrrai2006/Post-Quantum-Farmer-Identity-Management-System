"""
services/farmer_service.py
============================
Farmer profile CRUD + fingerprint enrollment status, respecting
MIN_FINGERPRINTS/MAX_FINGERPRINTS and one-farmer-many-fingers rule.
"""

import config
from storage.db import db_cursor


def generate_next_farmer_id() -> str:
    """FARMER0001, FARMER0002, ... — sequential, zero-padded to 4 digits.
    Only considers rows whose farmer_id matches the standard FARMERNNNN format
    so that any non-standard rows (e.g. test records) can never cause a crash.
    """
    with db_cursor(commit=False) as cur:
        # Only pull IDs whose suffix is purely numeric
        cur.execute(
            "SELECT farmer_id FROM farmers "
            "WHERE farmer_id GLOB 'FARMER[0-9][0-9][0-9][0-9]' "
            "ORDER BY farmer_id DESC LIMIT 1"
        )
        row = cur.fetchone()
    if row is None:
        return "FARMER0001"
    suffix = row["farmer_id"][6:]          # strip leading 'FARMER'
    last_num = int(suffix) if suffix.isdigit() else 0
    return f"FARMER{last_num + 1:04d}"


def create_farmer(farmer_id: str, name: str, date_of_birth: str, gender: str, phone: str,
                   address: str, village: str, taluk: str, district: str, state: str,
                   registration_center_id: int, user_id: int = None):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO farmers (farmer_id, user_id, name, date_of_birth, gender, phone, address,
                                     village, taluk, district, state, registration_center_id,
                                     registration_status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'INCOMPLETE')""",
            (farmer_id, user_id, name, date_of_birth, gender, phone, address,
             village, taluk, district, state, registration_center_id),
        )


def get_farmer(farmer_id: str):
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM farmers WHERE farmer_id = ?", (farmer_id,))
        return cur.fetchone()


def get_enrolled_fingers(farmer_id: str):
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT * FROM farmer_fingerprints WHERE farmer_id = ? AND status = 'REGISTERED'",
            (farmer_id,),
        )
        return cur.fetchall()


def finger_already_enrolled(farmer_id: str, finger_position: str) -> bool:
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT 1 FROM farmer_fingerprints WHERE farmer_id = ? AND finger_position = ? AND status='REGISTERED'",
            (farmer_id, finger_position),
        )
        return cur.fetchone() is not None


def can_enroll_another_finger(farmer_id: str) -> bool:
    return len(get_enrolled_fingers(farmer_id)) < config.MAX_FINGERPRINTS


def record_fingerprint_metadata(farmer_id: str, finger_position: str, ipfs_cid: str,
                                 integrity_hash: str, blockchain_tx_hash: str,
                                 registration_center_id: int, registered_by: int):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO farmer_fingerprints
               (farmer_id, finger_position, ipfs_cid, integrity_hash, blockchain_transaction_hash,
                registration_center_id, registered_by, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'REGISTERED')""",
            (farmer_id, finger_position, ipfs_cid, integrity_hash, blockchain_tx_hash,
             registration_center_id, registered_by),
        )


def update_registration_status(farmer_id: str):
    """Marks farmer COMPLETE once MIN_FINGERPRINTS is reached; called after every enrollment."""
    count = len(get_enrolled_fingers(farmer_id))
    status = "COMPLETE" if count >= config.MIN_FINGERPRINTS else "INCOMPLETE"
    with db_cursor() as cur:
        cur.execute(
            "UPDATE farmers SET registration_status = ?, updated_at = datetime('now') WHERE farmer_id = ?",
            (status, farmer_id),
        )
    return status, count


def search_farmers(query: str):
    with db_cursor(commit=False) as cur:
        cur.execute(
            """SELECT * FROM farmers WHERE farmer_id LIKE ? OR name LIKE ? OR phone LIKE ?
               ORDER BY created_at DESC LIMIT 50""",
            (f"%{query}%", f"%{query}%", f"%{query}%"),
        )
        return cur.fetchall()


# ---------------------------------------------------------------------------
# Statistics / Dashboard counts
# ---------------------------------------------------------------------------

def count_all_farmers() -> int:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT COUNT(*) AS n FROM farmers")
        return cur.fetchone()["n"]


def count_complete_farmers() -> int:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT COUNT(*) AS n FROM farmers WHERE registration_status = 'COMPLETE'")
        return cur.fetchone()["n"]


def count_enrolled_fingerprints() -> int:
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT COUNT(*) AS n FROM farmer_fingerprints WHERE status = 'REGISTERED'")
        return cur.fetchone()["n"]


def count_todays_registrations() -> int:
    """Farmers whose first fingerprint was registered today."""
    with db_cursor(commit=False) as cur:
        cur.execute(
            "SELECT COUNT(DISTINCT farmer_id) AS n FROM farmer_fingerprints "
            "WHERE status='REGISTERED' AND DATE(registration_timestamp) = DATE('now')"
        )
        return cur.fetchone()["n"]


def get_all_farmers(limit: int = 500):
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM farmers ORDER BY created_at DESC LIMIT ?", (limit,))
        return cur.fetchall()
