"""
auth/authentication.py
========================
Password hashing (werkzeug's PBKDF2/scrypt-backed helpers, bundled with Flask)
and login verification against the users table. Never stores or compares
plaintext passwords.
"""

from werkzeug.security import generate_password_hash, check_password_hash

from storage.db import db_cursor


def hash_password(plain_password: str) -> str:
    return generate_password_hash(plain_password, method="pbkdf2:sha256", salt_length=16)


def create_user(username: str, plain_password: str, role: str) -> int:
    password_hash = hash_password(plain_password)
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )
        return cur.lastrowid


def authenticate(username: str, plain_password: str):
    """
    Returns the user row (sqlite3.Row) on success, or None on failure.
    Does not distinguish "unknown username" from "wrong password" to the caller,
    to avoid username enumeration.
    """
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

    if user is None:
        return None
    if user["status"] != "ACTIVE":
        return None
    if not check_password_hash(user["password_hash"], plain_password):
        return None
    return user


def get_user_by_id(user_id: int):
    with db_cursor(commit=False) as cur:
        cur.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        return cur.fetchone()
