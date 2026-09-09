"""
storage/db.py
=============
SQLite database schema + connection helper.

IMPORTANT (spec section 6.3 / 20): this schema NEVER stores raw fingerprint
images, plaintext SourceAFIS templates, plaintext AES keys, or PQC secret
keys. farmer_fingerprints only stores the IPFS CID + integrity hash +
chain tx reference — the actual encrypted package lives in IPFS, and
private keys live only under keys/.
"""

import sqlite3
import os
from contextlib import contextmanager

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('ADMIN','GOVERNMENT_OFFICER','REGISTRATION_CENTER_OPERATOR','FARMER')),
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS registration_centers (
    center_id INTEGER PRIMARY KEY AUTOINCREMENT,
    center_name TEXT NOT NULL,
    registration_number TEXT UNIQUE NOT NULL,
    address TEXT,
    district TEXT,
    state TEXT,
    operator_user_id INTEGER REFERENCES users(user_id),
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS farmers (
    farmer_id TEXT PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    name TEXT NOT NULL,
    date_of_birth TEXT,
    gender TEXT,
    phone TEXT,
    address TEXT,
    village TEXT,
    taluk TEXT,
    district TEXT,
    state TEXT,
    registration_center_id INTEGER REFERENCES registration_centers(center_id),
    registration_status TEXT NOT NULL DEFAULT 'INCOMPLETE'
        CHECK (registration_status IN ('INCOMPLETE','COMPLETE','SUSPENDED')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS farmer_fingerprints (
    fingerprint_id INTEGER PRIMARY KEY AUTOINCREMENT,
    farmer_id TEXT NOT NULL REFERENCES farmers(farmer_id),
    finger_position TEXT NOT NULL,
    ipfs_cid TEXT,
    integrity_hash TEXT,
    blockchain_transaction_hash TEXT,
    registration_center_id INTEGER REFERENCES registration_centers(center_id),
    registered_by INTEGER REFERENCES users(user_id),
    registration_timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING','REGISTERED','FAILED','REVOKED')),
    UNIQUE(farmer_id, finger_position)
);

CREATE TABLE IF NOT EXISTS land_records (
    land_record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    farmer_id TEXT NOT NULL REFERENCES farmers(farmer_id),
    survey_number TEXT,
    land_area REAL,
    area_unit TEXT,
    village TEXT,
    taluk TEXT,
    district TEXT,
    state TEXT,
    land_type TEXT,
    ownership_type TEXT,
    verification_status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (verification_status IN ('PENDING','VERIFIED','REJECTED')),
    verified_by INTEGER REFERENCES users(user_id),
    verified_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS government_schemes (
    scheme_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scheme_name TEXT NOT NULL,
    description TEXT,
    eligibility TEXT,
    start_date TEXT,
    end_date TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','CLOSED')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS benefits (
    benefit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scheme_id INTEGER REFERENCES government_schemes(scheme_id),
    farmer_id TEXT NOT NULL REFERENCES farmers(farmer_id),
    benefit_name TEXT NOT NULL,
    description TEXT,
    amount REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING','APPROVED','REJECTED','PAID')),
    approved_by INTEGER REFERENCES users(user_id),
    approved_at TEXT,
    payment_reference TEXT,
    payment_date TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(user_id),
    role TEXT,
    action TEXT NOT NULL,
    target_farmer_id TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    ip_address TEXT,
    result TEXT
);

CREATE TABLE IF NOT EXISTS correction_requests (
    request_id INTEGER PRIMARY KEY AUTOINCREMENT,
    farmer_id TEXT NOT NULL REFERENCES farmers(farmer_id),
    request_type TEXT NOT NULL,
    details TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','APPROVED','REJECTED')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at TEXT,
    resolved_by INTEGER REFERENCES users(user_id)
);
"""


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db_cursor(commit: bool = True):
    conn = get_connection()
    try:
        cur = conn.cursor()
        yield cur
        if commit:
            conn.commit()
    finally:
        conn.close()


def init_db():
    os.makedirs(os.path.dirname(config.DATABASE_PATH), exist_ok=True)
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row["name"] for row in cur.fetchall()]
    print("Tables created:", tables)
    expected = {
        "users", "registration_centers", "farmers", "farmer_fingerprints",
        "land_records", "government_schemes", "benefits", "audit_logs",
        "correction_requests",
    }
    assert expected.issubset(set(tables)), f"Missing tables: {expected - set(tables)}"
    print("SELF-TEST PASSED — schema initialized at", config.DATABASE_PATH)
