"""
tests/test_crypto.py
======================
Run: pytest tests/test_crypto.py -v
"""

import os
import pytest

from crypto import hashing, aes_gcm, kdf


def test_aes_round_trip():
    key = os.urandom(32)
    plaintext = b"fingerprint-template-bytes"
    enc = aes_gcm.encrypt_template(key, plaintext)
    recovered = aes_gcm.decrypt_template(key, enc["ciphertext"], enc["nonce"], enc["tag"])
    assert recovered == plaintext


def test_aes_tampered_ciphertext_fails():
    key = os.urandom(32)
    plaintext = b"fingerprint-template-bytes"
    enc = aes_gcm.encrypt_template(key, plaintext)
    tampered = bytearray(enc["ciphertext"])
    tampered[0] ^= 0xFF
    with pytest.raises(aes_gcm.AESGCMAuthenticationError):
        aes_gcm.decrypt_template(key, bytes(tampered), enc["nonce"], enc["tag"])


def test_aes_tampered_tag_fails():
    key = os.urandom(32)
    enc = aes_gcm.encrypt_template(key, b"data")
    tampered_tag = bytearray(enc["tag"])
    tampered_tag[0] ^= 0xFF
    with pytest.raises(aes_gcm.AESGCMAuthenticationError):
        aes_gcm.decrypt_template(key, enc["ciphertext"], enc["nonce"], bytes(tampered_tag))


def test_sha3_integrity_mismatch_detected():
    package = {"farmer_id": "FARMER0001", "value": 1}
    h1 = hashing.compute_package_integrity_hash(package)
    package["value"] = 2
    h2 = hashing.compute_package_integrity_hash(package)
    assert h1 != h2


def test_sha3_canonical_hash_deterministic():
    p1 = {"b": 2, "a": 1}
    p2 = {"a": 1, "b": 2}
    assert hashing.compute_package_integrity_hash(p1) == hashing.compute_package_integrity_hash(p2)


def test_kdf_deterministic():
    shared_secret = os.urandom(32)
    salt = os.urandom(16)
    k1 = kdf.derive_aes_key(shared_secret, salt)
    k2 = kdf.derive_aes_key(shared_secret, salt)
    assert k1 == k2
    assert len(k1) == 32


def test_kdf_different_salt_gives_different_key():
    shared_secret = os.urandom(32)
    k1 = kdf.derive_aes_key(shared_secret, os.urandom(16))
    k2 = kdf.derive_aes_key(shared_secret, os.urandom(16))
    assert k1 != k2
