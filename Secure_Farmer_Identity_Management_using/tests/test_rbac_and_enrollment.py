"""
tests/test_rbac_and_enrollment.py
====================================
Run: pytest tests/test_rbac_and_enrollment.py -v

Uses a temporary SQLite DB (via monkeypatching config.DATABASE_PATH) so
tests never touch the real project database.
"""

import os
import tempfile
import pytest

import config


@pytest.fixture(autouse=True)
def temp_database(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)  # let sqlite create it fresh
    monkeypatch.setattr(config, "DATABASE_PATH", path)
    from storage.db import init_db
    init_db()
    yield
    if os.path.exists(path):
        os.remove(path)


def test_rbac_permission_matrix():
    from auth.authorization import role_has_permission
    assert role_has_permission(config.ROLE_FARMER, "view_own_profile")
    assert not role_has_permission(config.ROLE_FARMER, "manage_benefits")
    assert role_has_permission(config.ROLE_GOVERNMENT_OFFICER, "manage_benefits")
    assert not role_has_permission(config.ROLE_GOVERNMENT_OFFICER, "register_farmer")
    assert role_has_permission(config.ROLE_REGISTRATION_CENTER_OPERATOR, "register_farmer")
    assert not role_has_permission(config.ROLE_REGISTRATION_CENTER_OPERATOR, "manage_users")


def test_farmer_owns_record():
    from auth.authorization import farmer_owns_record
    assert farmer_owns_record("FARMER0001", "FARMER0001")
    assert not farmer_owns_record("FARMER0001", "FARMER0002")
    assert not farmer_owns_record(None, "FARMER0001")


def test_farmer_id_sequential_generation():
    from services.farmer_service import generate_next_farmer_id, create_farmer
    assert generate_next_farmer_id() == "FARMER0001"
    create_farmer("FARMER0001", "Test One", "1990-01-01", "MALE", "111", "addr",
                   "village", "taluk", "district", "state", registration_center_id=None)
    assert generate_next_farmer_id() == "FARMER0002"


def test_duplicate_finger_position_rejected():
    from services.farmer_service import create_farmer, record_fingerprint_metadata, finger_already_enrolled
    create_farmer("FARMER0001", "Test", "1990-01-01", "MALE", "111", "addr",
                   "v", "t", "d", "s", registration_center_id=None)
    record_fingerprint_metadata("FARMER0001", "RIGHT_THUMB", "cid123", "hash123", "tx123",
                                 registration_center_id=None, registered_by=None)
    assert finger_already_enrolled("FARMER0001", "RIGHT_THUMB")

    from storage.db import db_cursor
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        with db_cursor() as cur:
            cur.execute(
                """INSERT INTO farmer_fingerprints (farmer_id, finger_position, status)
                   VALUES (?, ?, 'REGISTERED')""",
                ("FARMER0001", "RIGHT_THUMB"),
            )


def test_minimum_five_fingerprints_enforced():
    from services.farmer_service import (
        create_farmer, record_fingerprint_metadata, update_registration_status
    )
    create_farmer("FARMER0001", "Test", "1990-01-01", "MALE", "111", "addr",
                   "v", "t", "d", "s", registration_center_id=None)

    positions = ["RIGHT_THUMB", "RIGHT_INDEX", "RIGHT_MIDDLE", "LEFT_THUMB"]  # only 4
    for pos in positions:
        record_fingerprint_metadata("FARMER0001", pos, "cid", "hash", "tx",
                                     registration_center_id=None, registered_by=None)
    status, count = update_registration_status("FARMER0001")
    assert count == 4
    assert status == "INCOMPLETE"

    record_fingerprint_metadata("FARMER0001", "LEFT_INDEX", "cid", "hash", "tx",
                                 registration_center_id=None, registered_by=None)
    status, count = update_registration_status("FARMER0001")
    assert count == 5
    assert status == "COMPLETE"


def test_maximum_ten_fingerprints_enforced():
    from services.farmer_service import create_farmer, record_fingerprint_metadata, can_enroll_another_finger
    create_farmer("FARMER0001", "Test", "1990-01-01", "MALE", "111", "addr",
                   "v", "t", "d", "s", registration_center_id=None)
    for pos in config.VALID_FINGER_POSITIONS:  # all 10
        record_fingerprint_metadata("FARMER0001", pos, "cid", "hash", "tx",
                                     registration_center_id=None, registered_by=None)
    assert can_enroll_another_finger("FARMER0001") is False
