"""ML-KEM-1024 (FIPS 203) key encapsulation utilities.

Wraps the ``pqcrypto.kem.ml_kem_1024`` implementation to generate key pairs,
encapsulate/decapsulate a shared secret (used here to protect the AES-256
session key), persist keys to disk, and record performance metrics.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pqcrypto.kem.ml_kem_1024 import (
    CIPHERTEXT_SIZE,
    PUBLIC_KEY_SIZE,
    SECRET_KEY_SIZE,
    decrypt as _kem_decapsulate,
    encrypt as _kem_encapsulate,
    generate_keypair as _kem_generate_keypair,
)

from logging_utils import get_logger

logger = get_logger(__name__)

SHARED_SECRET_SIZE_BYTES = 32  # ML-KEM-1024 fixed shared-secret length


@dataclass
class MLKEMKeyPair:
    """Container for an ML-KEM-1024 key pair and key-generation metrics."""

    public_key: bytes
    secret_key: bytes
    public_key_size_bytes: int
    secret_key_size_bytes: int
    keygen_time_seconds: float


@dataclass
class MLKEMEncapsulationResult:
    """Container for ML-KEM-1024 encapsulation output and metrics."""

    kem_ciphertext: bytes
    shared_secret: bytes
    kem_ciphertext_size_bytes: int
    shared_secret_size_bytes: int
    encapsulation_time_seconds: float

    def to_metadata_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable summary (excludes raw secret bytes)."""
        return {
            "algorithm": "ML-KEM-1024",
            "kem_ciphertext_size_bytes": self.kem_ciphertext_size_bytes,
            "shared_secret_size_bytes": self.shared_secret_size_bytes,
            "encapsulation_time_seconds": self.encapsulation_time_seconds,
        }


@dataclass
class MLKEMDecapsulationResult:
    """Container for ML-KEM-1024 decapsulation output and metrics."""

    shared_secret: bytes
    decapsulation_time_seconds: float


def generate_keypair() -> MLKEMKeyPair:
    """Generate a new ML-KEM-1024 public/secret key pair.

    Returns:
        An :class:`MLKEMKeyPair` containing the keys and timing metrics.
    """
    start_time = time.perf_counter()
    public_key, secret_key = _kem_generate_keypair()
    elapsed = time.perf_counter() - start_time

    logger.info(
        "ML-KEM-1024 key pair generated (pk=%d B, sk=%d B) in %.6f s.",
        len(public_key),
        len(secret_key),
        elapsed,
    )

    return MLKEMKeyPair(
        public_key=public_key,
        secret_key=secret_key,
        public_key_size_bytes=len(public_key),
        secret_key_size_bytes=len(secret_key),
        keygen_time_seconds=elapsed,
    )


def encapsulate_aes_key(public_key: bytes) -> MLKEMEncapsulationResult:
    """Encapsulate a fresh shared secret under an ML-KEM-1024 public key.

    The resulting shared secret is used directly as (or to derive) the
    AES-256-GCM session key protecting the fingerprint template.

    Args:
        public_key: The recipient's ML-KEM-1024 public key.

    Returns:
        An :class:`MLKEMEncapsulationResult` with the KEM ciphertext, the
        shared secret, and timing metrics.

    Raises:
        ValueError: If the public key size is invalid.
    """
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise ValueError(f"ML-KEM-1024 public key must be {PUBLIC_KEY_SIZE} bytes, got {len(public_key)}.")

    start_time = time.perf_counter()
    kem_ciphertext, shared_secret = _kem_encapsulate(public_key)
    elapsed = time.perf_counter() - start_time

    logger.info(
        "ML-KEM-1024 encapsulation complete (ct=%d B, ss=%d B) in %.6f s.",
        len(kem_ciphertext),
        len(shared_secret),
        elapsed,
    )

    return MLKEMEncapsulationResult(
        kem_ciphertext=kem_ciphertext,
        shared_secret=shared_secret,
        kem_ciphertext_size_bytes=len(kem_ciphertext),
        shared_secret_size_bytes=len(shared_secret),
        encapsulation_time_seconds=elapsed,
    )


def decapsulate_aes_key(secret_key: bytes, kem_ciphertext: bytes) -> MLKEMDecapsulationResult:
    """Recover the shared secret (AES key material) from an ML-KEM-1024 ciphertext.

    Args:
        secret_key: The recipient's ML-KEM-1024 secret key.
        kem_ciphertext: The KEM ciphertext produced by ``encapsulate_aes_key``.

    Returns:
        An :class:`MLKEMDecapsulationResult` with the recovered shared secret
        and timing metrics.

    Raises:
        ValueError: If the secret key or ciphertext size is invalid.
    """
    if len(secret_key) != SECRET_KEY_SIZE:
        raise ValueError(f"ML-KEM-1024 secret key must be {SECRET_KEY_SIZE} bytes, got {len(secret_key)}.")
    if len(kem_ciphertext) != CIPHERTEXT_SIZE:
        raise ValueError(f"ML-KEM-1024 ciphertext must be {CIPHERTEXT_SIZE} bytes, got {len(kem_ciphertext)}.")

    start_time = time.perf_counter()
    shared_secret = _kem_decapsulate(secret_key, kem_ciphertext)
    elapsed = time.perf_counter() - start_time

    logger.info("ML-KEM-1024 decapsulation complete (ss=%d B) in %.6f s.", len(shared_secret), elapsed)

    return MLKEMDecapsulationResult(
        shared_secret=shared_secret,
        decapsulation_time_seconds=elapsed,
    )


def save_keypair(keypair: MLKEMKeyPair, public_key_path: Path, secret_key_path: Path) -> None:
    """Persist an ML-KEM-1024 key pair to disk as raw binary files.

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
    logger.info("ML-KEM-1024 key pair saved to %s and %s.", public_key_path, secret_key_path)


def load_keypair(public_key_path: Path, secret_key_path: Path) -> tuple[bytes, bytes]:
    """Load an ML-KEM-1024 key pair previously saved with ``save_keypair``.

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
        raise FileNotFoundError("ML-KEM-1024 key files not found; generate keys first.")

    public_key = public_key_path.read_bytes()
    secret_key = secret_key_path.read_bytes()
    logger.info("ML-KEM-1024 key pair loaded from %s and %s.", public_key_path, secret_key_path)
    return public_key, secret_key


def save_encapsulation_metadata(result: MLKEMEncapsulationResult, output_path: Path) -> None:
    """Persist ML-KEM-1024 encapsulation metrics/metadata to a JSON file.

    Args:
        result: The encapsulation result to serialize.
        output_path: Destination JSON file path.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(result.to_metadata_dict(), handle, indent=2)
    logger.info("ML-KEM-1024 encapsulation metadata saved to %s", output_path)
