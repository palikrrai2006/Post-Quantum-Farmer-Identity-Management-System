"""ML-DSA-87 (FIPS 204) digital signature utilities.

Wraps ``pqcrypto.sign.ml_dsa_87`` to sign and verify registration packages,
persist keys, and record performance metrics.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pqcrypto.sign.ml_dsa_87 import (
    PUBLIC_KEY_SIZE,
    SECRET_KEY_SIZE,
    generate_keypair as _dsa_generate_keypair,
    sign as _dsa_sign,
    verify as _dsa_verify,
)

from logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class MLDSAKeyPair:
    """Container for an ML-DSA-87 key pair and key-generation metrics."""

    public_key: bytes
    secret_key: bytes
    public_key_size_bytes: int
    secret_key_size_bytes: int
    keygen_time_seconds: float


@dataclass
class MLDSASignResult:
    """Container for an ML-DSA-87 signing operation and its metrics."""

    signature: bytes
    signature_size_bytes: int
    signing_time_seconds: float

    def to_metadata_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable summary (excludes the raw signature)."""
        return {
            "algorithm": "ML-DSA-87",
            "signature_size_bytes": self.signature_size_bytes,
            "signing_time_seconds": self.signing_time_seconds,
        }


@dataclass
class MLDSAVerifyResult:
    """Container for an ML-DSA-87 verification operation and its metrics."""

    is_valid: bool
    verification_time_seconds: float


def generate_keypair() -> MLDSAKeyPair:
    """Generate a new ML-DSA-87 public/secret key pair.

    Returns:
        An :class:`MLDSAKeyPair` containing the keys and timing metrics.
    """
    start_time = time.perf_counter()
    public_key, secret_key = _dsa_generate_keypair()
    elapsed = time.perf_counter() - start_time

    logger.info(
        "ML-DSA-87 key pair generated (pk=%d B, sk=%d B) in %.6f s.",
        len(public_key),
        len(secret_key),
        elapsed,
    )

    return MLDSAKeyPair(
        public_key=public_key,
        secret_key=secret_key,
        public_key_size_bytes=len(public_key),
        secret_key_size_bytes=len(secret_key),
        keygen_time_seconds=elapsed,
    )


def sign_package(secret_key: bytes, message: bytes) -> MLDSASignResult:
    """Sign a registration package (or its canonical byte representation).

    Args:
        secret_key: The signer's ML-DSA-87 secret key.
        message: The bytes to sign (e.g., a canonical JSON encoding of the
            registration package contents).

    Returns:
        An :class:`MLDSASignResult` with the signature and timing metrics.

    Raises:
        ValueError: If the secret key size is invalid.
    """
    if len(secret_key) != SECRET_KEY_SIZE:
        raise ValueError(f"ML-DSA-87 secret key must be {SECRET_KEY_SIZE} bytes, got {len(secret_key)}.")

    start_time = time.perf_counter()
    signature = _dsa_sign(secret_key, message)
    elapsed = time.perf_counter() - start_time

    logger.info("ML-DSA-87 signing complete (sig=%d B) in %.6f s.", len(signature), elapsed)

    return MLDSASignResult(
        signature=signature,
        signature_size_bytes=len(signature),
        signing_time_seconds=elapsed,
    )


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> MLDSAVerifyResult:
    """Verify an ML-DSA-87 signature over a registration package.

    Args:
        public_key: The signer's ML-DSA-87 public key.
        message: The original signed bytes.
        signature: The signature to verify.

    Returns:
        An :class:`MLDSAVerifyResult` indicating validity and timing.

    Raises:
        ValueError: If the public key size is invalid.
    """
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise ValueError(f"ML-DSA-87 public key must be {PUBLIC_KEY_SIZE} bytes, got {len(public_key)}.")

    start_time = time.perf_counter()
    try:
        is_valid = bool(_dsa_verify(public_key, message, signature))
    except Exception as exc:  # pqcrypto raises on malformed/invalid signatures
        logger.warning("ML-DSA-87 verification raised an exception (treated as invalid): %s", exc)
        is_valid = False
    elapsed = time.perf_counter() - start_time

    if is_valid:
        logger.info("ML-DSA-87 signature verification SUCCEEDED in %.6f s.", elapsed)
    else:
        logger.warning("ML-DSA-87 signature verification FAILED in %.6f s.", elapsed)

    return MLDSAVerifyResult(is_valid=is_valid, verification_time_seconds=elapsed)


def save_keypair(keypair: MLDSAKeyPair, public_key_path: Path, secret_key_path: Path) -> None:
    """Persist an ML-DSA-87 key pair to disk as raw binary files.

    Args:
        keypair: The key pair to save.
        public_key_path: Destination path for the public key.
        secret_key_path: Destination path for the secret key.
    """
    public_key_path = Path(public_key_path)
    secret_key_path = Path(secret_key_path)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    secret_key_path.parent.mkdir(parents=True, exist_ok=True)

    public_key_path.write_bytes(keypair.public_key)
    secret_key_path.write_bytes(keypair.secret_key)
    logger.info("ML-DSA-87 key pair saved to %s and %s.", public_key_path, secret_key_path)


def load_keypair(public_key_path: Path, secret_key_path: Path) -> tuple[bytes, bytes]:
    """Load an ML-DSA-87 key pair previously saved with ``save_keypair``.

    Args:
        public_key_path: Path to the saved public key file.
        secret_key_path: Path to the saved secret key file.

    Returns:
        A tuple of ``(public_key, secret_key)`` raw bytes.

    Raises:
        FileNotFoundError: If either key file does not exist.
    """
    public_key_path = Path(public_key_path)
    secret_key_path = Path(secret_key_path)
    if not public_key_path.exists() or not secret_key_path.exists():
        raise FileNotFoundError("ML-DSA-87 key files not found; generate keys first.")

    public_key = public_key_path.read_bytes()
    secret_key = secret_key_path.read_bytes()
    logger.info("ML-DSA-87 key pair loaded from %s and %s.", public_key_path, secret_key_path)
    return public_key, secret_key


def save_sign_metadata(result: MLDSASignResult, output_path: Path) -> None:
    """Persist ML-DSA-87 signing metrics/metadata to a JSON file.

    Args:
        result: The signing result to serialize.
        output_path: Destination JSON file path.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(result.to_metadata_dict(), handle, indent=2)
    logger.info("ML-DSA-87 signing metadata saved to %s", output_path)
