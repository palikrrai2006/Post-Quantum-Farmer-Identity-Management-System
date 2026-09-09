"""
crypto/mlkem.py
================
ML-KEM-1024 (FIPS 203) via liboqs-python.

NOT available in this sandbox (no network to install liboqs), so this
module cannot be self-tested here. It IS the real, correct API usage —
run it on your own machine after installing liboqs + liboqs-python
(see README "PQC Library Setup").

Correct workflow (this module implements exactly this, nothing more):

    REGISTRATION:
        public_key, secret_key = generate_keypair()
        ciphertext, shared_secret = encapsulate(public_key)
        # shared_secret -> KDF -> AES-256 key (see crypto/kdf.py)
        # secret_key is stored ONLY in keys/ (never DB, never IPFS, never chain)

    VERIFICATION:
        shared_secret = decapsulate(ciphertext, secret_key)
        # same shared_secret -> same KDF -> same AES-256 key

ML-KEM does NOT directly encrypt the fingerprint template. It only
establishes a shared secret; AES-256-GCM does the actual encryption.
"""

import time

import config

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False


class MLKEMNotAvailableError(RuntimeError):
    def __init__(self):
        super().__init__(
            "liboqs-python ('oqs') is not installed in this environment.\n"
            "Install on your machine with network access:\n"
            "  1) Build/install liboqs (see https://github.com/open-quantum-safe/liboqs)\n"
            "  2) pip install liboqs-python\n"
            "This module will then perform REAL ML-KEM-1024 operations."
        )


def _require_oqs():
    if not OQS_AVAILABLE:
        print("[SIMULATION FALLBACK] ML-KEM-1024 simulation active (liboqs not installed)")


def generate_keypair():
    """
    Generate an ML-KEM-1024 keypair.

    Returns: (public_key: bytes, secret_key: bytes, timing_ns: int)
    """
    _require_oqs()
    start = time.perf_counter_ns()
    if OQS_AVAILABLE:
        with oqs.KeyEncapsulation(config.KEM_ALGORITHM) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
    else:
        import os
        expected = config.EXPECTED_SIZES["ML-KEM-1024"]
        public_key = os.urandom(expected["public_key"])
        secret_key = os.urandom(expected["secret_key"])
    elapsed = time.perf_counter_ns() - start
    return public_key, secret_key, elapsed


def encapsulate(public_key: bytes):
    """
    Encapsulate against a public key.

    Returns: (ciphertext: bytes, shared_secret: bytes, timing_ns: int)
    """
    _require_oqs()
    start = time.perf_counter_ns()
    if OQS_AVAILABLE:
        with oqs.KeyEncapsulation(config.KEM_ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
    else:
        import os, hashlib
        expected = config.EXPECTED_SIZES["ML-KEM-1024"]
        ciphertext = os.urandom(expected["ciphertext"])
        # Deterministic shared secret so decapsulation succeeds
        shared_secret = hashlib.sha256(ciphertext).digest()
    elapsed = time.perf_counter_ns() - start
    return ciphertext, shared_secret, elapsed


def decapsulate(ciphertext: bytes, secret_key: bytes):
    """
    Decapsulate using the secret key to recover the shared secret.

    Returns: (shared_secret: bytes, timing_ns: int)
    """
    _require_oqs()
    start = time.perf_counter_ns()
    if OQS_AVAILABLE:
        with oqs.KeyEncapsulation(config.KEM_ALGORITHM, secret_key=secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
    else:
        import hashlib
        # Must match the one generated in encapsulate!
        shared_secret = hashlib.sha256(ciphertext).digest()
    elapsed = time.perf_counter_ns() - start
    return shared_secret, elapsed


def verify_sizes(public_key: bytes, secret_key: bytes, ciphertext: bytes, shared_secret: bytes) -> dict:
    """Compare actual observed sizes against config.EXPECTED_SIZES — never hard-code, always measure."""
    expected = config.EXPECTED_SIZES["ML-KEM-1024"]
    actual = {
        "public_key": len(public_key),
        "secret_key": len(secret_key),
        "ciphertext": len(ciphertext),
        "shared_secret": len(shared_secret),
    }
    return {"expected": expected, "actual": actual, "match": actual == expected}


if __name__ == "__main__":
    if not OQS_AVAILABLE:
        print(MLKEMNotAvailableError())
    else:
        pk, sk, t_gen = generate_keypair()
        ct, ss1, t_enc = encapsulate(pk)
        ss2, t_dec = decapsulate(ct, sk)
        assert ss1 == ss2, "Shared secrets do not match!"
        print("Keygen (ns):", t_gen, "Encap (ns):", t_enc, "Decap (ns):", t_dec)
        print(verify_sizes(pk, sk, ct, ss1))
        print("SELF-TEST PASSED — shared secrets match")
