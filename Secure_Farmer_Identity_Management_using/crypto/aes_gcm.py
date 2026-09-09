"""
crypto/aes_gcm.py
==================
AES-256-GCM authenticated encryption/decryption for fingerprint templates.

Install: pip install cryptography

Rules enforced here (see project spec section 16):
- A fresh cryptographically secure nonce is generated for every encryption.
- Ciphertext, nonce, and authentication tag are all returned/stored separately
  (the `cryptography` AESGCM API appends the 16-byte tag to the ciphertext;
  we split it back out so the secure_package schema can store them as
  distinct base64 fields, matching the required package format).
- Decryption failure (bad tag) raises — callers MUST treat this as
  "STOP VERIFICATION", never as a silent False.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

import config

GCM_TAG_BYTES = 16


class AESGCMAuthenticationError(Exception):
    """Raised when GCM tag verification fails during decryption. Verification MUST stop."""
    pass


def generate_nonce() -> bytes:
    return os.urandom(config.AES_NONCE_BYTES)


def encrypt_template(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> dict:
    """
    Encrypt a fingerprint template (or any plaintext bytes).

    Returns dict with:
        ciphertext (bytes, WITHOUT tag)
        nonce (bytes)
        tag (bytes, 16 bytes)
    """
    if len(key) != config.AES_KEY_BYTES:
        raise ValueError(f"AES key must be {config.AES_KEY_BYTES} bytes, got {len(key)}")

    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)

    ciphertext = ct_with_tag[:-GCM_TAG_BYTES]
    tag = ct_with_tag[-GCM_TAG_BYTES:]

    return {"ciphertext": ciphertext, "nonce": nonce, "tag": tag}


def decrypt_template(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes,
                      associated_data: bytes = b"") -> bytes:
    """
    Decrypt and authenticate. Raises AESGCMAuthenticationError on tag mismatch —
    callers must treat this as a hard stop, never fall through to "authenticated".
    """
    if len(key) != config.AES_KEY_BYTES:
        raise ValueError(f"AES key must be {config.AES_KEY_BYTES} bytes, got {len(key)}")

    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + tag
    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, associated_data)
    except InvalidTag:
        raise AESGCMAuthenticationError(
            "AES-256-GCM authentication failed — ciphertext or tag has been tampered with, "
            "or the wrong key/nonce was used. Verification MUST be rejected."
        )
    return plaintext


if __name__ == "__main__":
    key = os.urandom(config.AES_KEY_BYTES)
    plaintext = b"SIMULATED_SOURCEAFIS_TEMPLATE_BYTES_FOR_SELF_TEST"

    enc = encrypt_template(key, plaintext)
    print("Nonce:", enc["nonce"].hex())
    print("Tag:", enc["tag"].hex())
    print("Ciphertext:", enc["ciphertext"].hex())

    recovered = decrypt_template(key, enc["ciphertext"], enc["nonce"], enc["tag"])
    assert recovered == plaintext
    print("Round-trip OK.")

    # Tamper test — must raise
    tampered_ct = bytearray(enc["ciphertext"])
    tampered_ct[0] ^= 0xFF
    try:
        decrypt_template(key, bytes(tampered_ct), enc["nonce"], enc["tag"])
        print("SELF-TEST FAILED — tampered ciphertext was accepted!")
    except AESGCMAuthenticationError:
        print("Tamper correctly rejected with AESGCMAuthenticationError.")
        print("SELF-TEST PASSED")
