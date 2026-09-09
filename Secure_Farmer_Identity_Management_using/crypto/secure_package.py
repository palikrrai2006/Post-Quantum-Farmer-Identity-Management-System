"""
crypto/secure_package.py
=========================
Assembles / validates the "secure biometric package" — the single
structured object that gets SHA3-256 hashed, ML-DSA-87 signed, uploaded to
IPFS, and referenced (CID + hash) on-chain.

Full registration-side workflow implemented here (section 13/24 of spec):

    template bytes
        -> ML-KEM-1024 encapsulate(public_key) -> (kem_ciphertext, shared_secret)
        -> KDF(shared_secret, salt)             -> aes_key
        -> AES-256-GCM encrypt(aes_key, template) -> (ciphertext, nonce, tag)
        -> build package dict (base64 fields)
        -> SHA3-256(canonical(package minus signature/hash)) -> nothing yet:
           the SIGNATURE covers package-minus-signature; the HASH covers
           package-minus-hash. Order:
             1. build unsigned package
             2. sign canonical(unsigned package)          -> signature
             3. add signature field                        -> signed package
             4. hash canonical(signed package minus hash)  -> integrity_hash
        -> integrity_hash is what actually goes on-chain, alongside the CID.

Full verification-side workflow (section 26): reverse of the above, with a
hard-stop (raise) at every check — hash mismatch, bad signature, or GCM
auth failure must all reject, never silently continue.
"""

import base64
import time
from typing import Any, Dict

from crypto import hashing, aes_gcm, kdf
from crypto import mlkem, mldsa

PACKAGE_VERSION = 1


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


class PackageIntegrityError(Exception):
    """Hash mismatch — REJECT."""


class PackageSignatureError(Exception):
    """ML-DSA-87 signature invalid — REJECT."""


class PackageDecryptionError(Exception):
    """AES-256-GCM authentication failed — REJECT."""


def build_secure_package(
    farmer_id: str,
    finger_position: str,
    template_bytes: bytes,
    kem_public_key: bytes,
    dsa_secret_key: bytes,
    kdf_salt: bytes,
    metadata: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Full registration-time crypto pipeline. Returns the signed, hashed
    package ready for IPFS upload. Also returns timing info for the
    crypto performance experiments (never fabricate these numbers —
    they come from the actual calls below).
    """
    metadata = metadata or {}
    timings = {}

    kem_ciphertext, shared_secret, timings["kem_encap_ns"] = mlkem.encapsulate(kem_public_key)
    aes_key = kdf.derive_aes_key(shared_secret, kdf_salt)

    t0 = time.perf_counter_ns()
    enc = aes_gcm.encrypt_template(aes_key, template_bytes)
    timings["aes_encrypt_ns"] = time.perf_counter_ns() - t0

    unsigned_package = {
        "version": PACKAGE_VERSION,
        "farmer_id": farmer_id,
        "finger_position": finger_position,
        "encrypted_template": _b64(enc["ciphertext"]),
        "aes_nonce": _b64(enc["nonce"]),
        "aes_tag": _b64(enc["tag"]),
        "mlkem_ciphertext": _b64(kem_ciphertext),
        "kdf_salt": _b64(kdf_salt),
        "metadata": metadata,
    }

    canonical_for_signing = hashing.canonical_bytes(unsigned_package, exclude_fields=set())
    signature, timings["dsa_sign_ns"] = mldsa.sign(canonical_for_signing, dsa_secret_key)

    signed_package = dict(unsigned_package)
    signed_package["signature"] = _b64(signature)

    integrity_hash = hashing.compute_package_integrity_hash(signed_package)
    signed_package["integrity_hash"] = integrity_hash

    return signed_package, timings


def verify_secure_package(
    package: Dict[str, Any],
    expected_farmer_id: str,
    expected_finger_position: str,
    expected_integrity_hash: str,
    dsa_public_key: bytes,
    kem_secret_key: bytes,
) -> Dict[str, Any]:
    """
    Full verification-time crypto pipeline. Raises the specific error
    subclass on ANY failure — callers must not catch broadly and continue.

    Returns dict: {"template_bytes": ..., "timings": {...}} on success.
    """
    timings = {}

    if package.get("farmer_id") != expected_farmer_id:
        raise PackageIntegrityError("Package farmer_id does not match requested farmer_id")
    if package.get("finger_position") != expected_finger_position:
        raise PackageIntegrityError("Package finger_position does not match requested finger")

    recomputed_hash = hashing.compute_package_integrity_hash(package)
    if recomputed_hash != expected_integrity_hash:
        raise PackageIntegrityError(
            f"SHA3-256 mismatch: expected {expected_integrity_hash}, got {recomputed_hash}"
        )

    package_for_sig = {k: v for k, v in package.items() if k not in ("signature", "integrity_hash")}
    canonical_for_signing = hashing.canonical_bytes(package_for_sig, exclude_fields=set())
    signature = _unb64(package["signature"])

    t0 = time.perf_counter_ns()
    is_valid, timings["dsa_verify_ns"] = mldsa.verify(canonical_for_signing, signature, dsa_public_key)
    if not is_valid:
        raise PackageSignatureError("ML-DSA-87 signature verification failed")

    kem_ciphertext = _unb64(package["mlkem_ciphertext"])
    shared_secret, timings["kem_decap_ns"] = mlkem.decapsulate(kem_ciphertext, kem_secret_key)

    kdf_salt = _unb64(package["kdf_salt"])
    aes_key = kdf.derive_aes_key(shared_secret, kdf_salt)

    t0 = time.perf_counter_ns()
    try:
        template_bytes = aes_gcm.decrypt_template(
            aes_key,
            _unb64(package["encrypted_template"]),
            _unb64(package["aes_nonce"]),
            _unb64(package["aes_tag"]),
        )
    except aes_gcm.AESGCMAuthenticationError as e:
        raise PackageDecryptionError(str(e))
    timings["aes_decrypt_ns"] = time.perf_counter_ns() - t0

    return {"template_bytes": template_bytes, "timings": timings}
