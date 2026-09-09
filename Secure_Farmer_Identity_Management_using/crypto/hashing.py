"""
crypto/hashing.py
=================
SHA3-256 integrity hashing.

CRITICAL RULE (see project spec section 18):
The exact same canonical serialization function must be used at
registration time and at verification time, or hashes will never match
even when the underlying data is identical byte-for-byte.

This module owns that canonical serialization so there is exactly one
implementation used everywhere (no risk of two call sites drifting apart).
"""

import hashlib
import hmac
import json
from typing import Any, Dict

# Fields that are excluded from the hashed representation because
# including them would create a circular dependency (the hash cannot
# depend on itself, and the signature is computed AFTER the package
# is otherwise finalized so it is also excluded from the integrity hash
# input — the signature has its own, separately-defined canonical input
# in crypto/secure_package.py).
HASH_EXCLUDED_FIELDS = {"integrity_hash"}


def canonical_bytes(data: Dict[str, Any], exclude_fields: set = None) -> bytes:
    """
    Deterministic canonical serialization used for both hashing and signing.

    - Keys sorted lexicographically at every nesting level (json.dumps sort_keys=True)
    - No whitespace ambiguity (separators fixed)
    - UTF-8 encoding
    - Excluded fields removed BEFORE serialization (never mutate caller's dict)
    """
    exclude_fields = exclude_fields or set()
    filtered = {k: v for k, v in data.items() if k not in exclude_fields}
    serialized = json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return serialized.encode("utf-8")


def sha3_256_hash(data: bytes) -> str:
    """Return hex-encoded SHA3-256 digest of raw bytes."""
    digest = hashlib.sha3_256(data).hexdigest()
    return digest


def compute_package_integrity_hash(package: Dict[str, Any]) -> str:
    """
    Compute the SHA3-256 integrity hash of a secure biometric package.

    This is the ONLY function that should ever be called to produce the
    hash that gets anchored on-chain, and the ONLY function that should
    ever be called to recompute it during verification.
    """
    raw = canonical_bytes(package, exclude_fields=HASH_EXCLUDED_FIELDS)
    return sha3_256_hash(raw)


def verify_package_integrity(package: Dict[str, Any], expected_hash: str) -> bool:
    """Recompute the hash and compare (constant-time) against the blockchain-anchored value."""
    recomputed = compute_package_integrity_hash(package)
    return hmac.compare_digest(recomputed, expected_hash)


if __name__ == "__main__":
    # Quick self-test — runs with zero external dependencies.
    sample = {"farmer_id": "FARMER0001", "finger_position": "RIGHT_THUMB", "value": 42}
    h1 = compute_package_integrity_hash(sample)
    h2 = compute_package_integrity_hash(dict(sample))  # same content, different dict instance
    print("Hash 1:", h1)
    print("Hash 2:", h2)
    assert h1 == h2, "Canonical hashing is not deterministic!"
    tampered = dict(sample)
    tampered["value"] = 43
    h3 = compute_package_integrity_hash(tampered)
    assert h3 != h1, "Hash did not change when data changed!"
    print("Tamper detection OK:", h3)
    print("SELF-TEST PASSED")
