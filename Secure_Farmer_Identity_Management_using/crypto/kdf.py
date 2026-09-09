"""
crypto/kdf.py
=============
HKDF-based key derivation: ML-KEM shared secret -> AES-256 key.

Uses `cryptography`'s HKDF (RFC 5869) with SHA3-256 as the underlying hash,
matching config.HASH_ALGORITHM. Registration and verification MUST call
this with identical (salt, info) to derive the same AES key from the same
shared secret — that identity is what makes decapsulation work.

Install: pip install cryptography
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import config


def derive_aes_key(shared_secret: bytes, salt: bytes, info: bytes = None) -> bytes:
    """
    Derive a 32-byte AES-256 key from an ML-KEM shared secret.

    Args:
        shared_secret: raw bytes returned by ML-KEM encapsulate()/decapsulate()
        salt: random per-record salt (must be stored so verification can reuse it;
              salt is not secret, it only needs to be consistent between the two calls)
        info: domain-separation context; defaults to config.KDF_CONTEXT_INFO

    Returns:
        32-byte key suitable for AES-256-GCM
    """
    if info is None:
        info = config.KDF_CONTEXT_INFO

    hkdf = HKDF(
        algorithm=hashes.SHA3_256(),
        length=config.AES_KEY_BYTES,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


if __name__ == "__main__":
    import os
    shared_secret = os.urandom(32)   # stand-in for a real ML-KEM shared secret
    salt = os.urandom(16)

    key_registration = derive_aes_key(shared_secret, salt)
    key_verification = derive_aes_key(shared_secret, salt)  # same inputs, called again

    print("Derived key (registration):", key_registration.hex())
    print("Derived key (verification):", key_verification.hex())
    assert key_registration == key_verification, "KDF is not deterministic for identical inputs!"
    assert len(key_registration) == config.AES_KEY_BYTES
    print("SELF-TEST PASSED — KDF deterministic, correct length:", len(key_registration), "bytes")
