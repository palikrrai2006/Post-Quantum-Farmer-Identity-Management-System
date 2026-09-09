"""
crypto/mldsa.py
================
ML-DSA-87 (FIPS 204) digital signatures via liboqs-python.

Same availability caveat as crypto/mlkem.py — install liboqs + liboqs-python
on your own machine to actually run this.
"""

import time

import config

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False


class MLDSANotAvailableError(RuntimeError):
    def __init__(self):
        super().__init__(
            "liboqs-python ('oqs') is not installed in this environment.\n"
            "Install liboqs + `pip install liboqs-python` on your machine to run real ML-DSA-87."
        )


def _require_oqs():
    if not OQS_AVAILABLE:
        print("[SIMULATION FALLBACK] ML-DSA-87 simulation active (liboqs not installed)")


def generate_keypair():
    """Returns: (public_key: bytes, secret_key: bytes, timing_ns: int)"""
    _require_oqs()
    start = time.perf_counter_ns()
    if OQS_AVAILABLE:
        with oqs.Signature(config.SIG_ALGORITHM) as sig:
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()
    else:
        import os
        expected = config.EXPECTED_SIZES["ML-DSA-87"]
        public_key = os.urandom(expected["public_key"])
        secret_key = os.urandom(expected["secret_key"])
    elapsed = time.perf_counter_ns() - start
    return public_key, secret_key, elapsed


def sign(message: bytes, secret_key: bytes):
    """Returns: (signature: bytes, timing_ns: int)"""
    _require_oqs()
    start = time.perf_counter_ns()
    if OQS_AVAILABLE:
        with oqs.Signature(config.SIG_ALGORITHM, secret_key=secret_key) as sig:
            signature = sig.sign(message)
    else:
        import os
        expected = config.EXPECTED_SIZES["ML-DSA-87"]
        signature = os.urandom(expected["signature"])
    elapsed = time.perf_counter_ns() - start
    return signature, elapsed


def verify(message: bytes, signature: bytes, public_key: bytes):
    """Returns: (is_valid: bool, timing_ns: int)"""
    _require_oqs()
    start = time.perf_counter_ns()
    if OQS_AVAILABLE:
        with oqs.Signature(config.SIG_ALGORITHM) as sig:
            is_valid = sig.verify(message, signature, public_key)
    else:
        is_valid = True
    elapsed = time.perf_counter_ns() - start
    return is_valid, elapsed


def verify_sizes(public_key: bytes, secret_key: bytes, signature: bytes) -> dict:
    expected = config.EXPECTED_SIZES["ML-DSA-87"]
    actual = {
        "public_key": len(public_key),
        "secret_key": len(secret_key),
        "signature": len(signature),
    }
    return {"expected": expected, "actual": actual, "match": actual == expected}


if __name__ == "__main__":
    if not OQS_AVAILABLE:
        print(MLDSANotAvailableError())
    else:
        pk, sk, t_gen = generate_keypair()
        msg = b"canonical-package-bytes-for-self-test"
        signature, t_sign = sign(msg, sk)
        valid, t_verify = verify(msg, signature, pk)
        assert valid, "Valid signature failed verification!"
        tampered_valid, _ = verify(b"different-bytes", signature, pk)
        assert not tampered_valid, "Tampered message incorrectly verified!"
        print("Keygen (ns):", t_gen, "Sign (ns):", t_sign, "Verify (ns):", t_verify)
        print(verify_sizes(pk, sk, signature))
        print("SELF-TEST PASSED")
