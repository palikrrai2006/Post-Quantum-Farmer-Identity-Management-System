"""AES-256-GCM symmetric encryption utilities.

Provides authenticated encryption/decryption of fingerprint templates,
along with timing and size measurements suitable for IEEE-paper-ready
performance tables.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from config import AES_KEY_SIZE_BYTES, AES_NONCE_SIZE_BYTES, AES_TAG_SIZE_BYTES
from logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class AESEncryptionResult:
    """Container for AES-256-GCM encryption output and metrics."""

    ciphertext: bytes
    nonce: bytes
    tag: bytes
    plaintext_size_bytes: int
    ciphertext_size_bytes: int
    nonce_size_bytes: int
    key_size_bytes: int
    tag_size_bytes: int
    encryption_time_seconds: float

    def to_metadata_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable summary (excludes raw secret bytes)."""
        data = asdict(self)
        data.pop("ciphertext")
        data.pop("nonce")
        data.pop("tag")
        data["nonce_hex"] = self.nonce.hex()
        data["tag_hex"] = self.tag.hex()
        return data


@dataclass
class AESDecryptionResult:
    """Container for AES-256-GCM decryption output and metrics."""

    plaintext: bytes
    decryption_time_seconds: float
    plaintext_size_bytes: int


def generate_aes_key() -> bytes:
    """Generate a cryptographically secure random AES-256 key.

    Returns:
        A 32-byte (256-bit) random key.
    """
    key = get_random_bytes(AES_KEY_SIZE_BYTES)
    logger.info("Generated new AES-256 key (%d bytes).", len(key))
    return key


def encrypt_bytes(plaintext: bytes, key: bytes) -> AESEncryptionResult:
    """Encrypt raw bytes using AES-256-GCM.

    Args:
        plaintext: The data to encrypt (e.g., a fingerprint template).
        key: A 32-byte AES-256 key.

    Returns:
        An :class:`AESEncryptionResult` with ciphertext, nonce, tag, and metrics.

    Raises:
        ValueError: If the key is not exactly 32 bytes.
    """
    if len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"AES key must be {AES_KEY_SIZE_BYTES} bytes, got {len(key)}.")

    nonce = get_random_bytes(AES_NONCE_SIZE_BYTES)
    start_time = time.perf_counter()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_SIZE_BYTES)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    elapsed = time.perf_counter() - start_time

    logger.info(
        "AES-256-GCM encryption complete: %d bytes -> %d bytes in %.6f s.",
        len(plaintext),
        len(ciphertext),
        elapsed,
    )

    return AESEncryptionResult(
        ciphertext=ciphertext,
        nonce=nonce,
        tag=tag,
        plaintext_size_bytes=len(plaintext),
        ciphertext_size_bytes=len(ciphertext),
        nonce_size_bytes=len(nonce),
        key_size_bytes=len(key),
        tag_size_bytes=len(tag),
        encryption_time_seconds=elapsed,
    )


def decrypt_bytes(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> AESDecryptionResult:
    """Decrypt and authenticate AES-256-GCM ciphertext.

    Args:
        ciphertext: The encrypted data.
        key: A 32-byte AES-256 key.
        nonce: The 12-byte nonce used during encryption.
        tag: The 16-byte authentication tag produced during encryption.

    Returns:
        An :class:`AESDecryptionResult` with recovered plaintext and metrics.

    Raises:
        ValueError: If the authentication tag does not verify (tampering or
            wrong key/nonce).
    """
    start_time = time.perf_counter()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_SIZE_BYTES)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        logger.error("AES-256-GCM authentication failed: %s", exc)
        raise ValueError("AES-GCM authentication tag verification failed.") from exc
    elapsed = time.perf_counter() - start_time

    logger.info(
        "AES-256-GCM decryption complete: %d bytes -> %d bytes in %.6f s.",
        len(ciphertext),
        len(plaintext),
        elapsed,
    )

    return AESDecryptionResult(
        plaintext=plaintext,
        decryption_time_seconds=elapsed,
        plaintext_size_bytes=len(plaintext),
    )


def encrypt_template_file(template_path: Path, key: bytes, output_path: Path) -> AESEncryptionResult:
    """Encrypt a fingerprint template file and persist the ciphertext to disk.

    Args:
        template_path: Path to the plaintext template (.txt) file.
        key: A 32-byte AES-256 key.
        output_path: Destination path for the encrypted (.enc) file.

    Returns:
        The :class:`AESEncryptionResult` describing the operation.

    Raises:
        FileNotFoundError: If ``template_path`` does not exist.
    """
    template_path = Path(template_path)
    if not template_path.exists():
        raise FileNotFoundError(f"Template file not found: {template_path}")

    plaintext = template_path.read_bytes()
    result = encrypt_bytes(plaintext, key)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Layout: [nonce (12 bytes)] [tag (16 bytes)] [ciphertext (variable)]
    with output_path.open("wb") as handle:
        handle.write(result.nonce)
        handle.write(result.tag)
        handle.write(result.ciphertext)

    logger.info("Encrypted template written to %s", output_path)
    return result


def decrypt_template_file(encrypted_path: Path, key: bytes) -> AESDecryptionResult:
    """Decrypt a fingerprint template (.enc) file produced by ``encrypt_template_file``.

    Args:
        encrypted_path: Path to the encrypted (.enc) file.
        key: A 32-byte AES-256 key.

    Returns:
        The :class:`AESDecryptionResult` describing the operation, including
        the recovered plaintext template bytes.

    Raises:
        FileNotFoundError: If ``encrypted_path`` does not exist.
        ValueError: If the file is malformed or authentication fails.
    """
    encrypted_path = Path(encrypted_path)
    if not encrypted_path.exists():
        raise FileNotFoundError(f"Encrypted template file not found: {encrypted_path}")

    raw = encrypted_path.read_bytes()
    if len(raw) < AES_NONCE_SIZE_BYTES + AES_TAG_SIZE_BYTES:
        raise ValueError("Encrypted file is too short to contain a valid nonce and tag.")

    nonce = raw[:AES_NONCE_SIZE_BYTES]
    tag = raw[AES_NONCE_SIZE_BYTES : AES_NONCE_SIZE_BYTES + AES_TAG_SIZE_BYTES]
    ciphertext = raw[AES_NONCE_SIZE_BYTES + AES_TAG_SIZE_BYTES :]

    return decrypt_bytes(ciphertext, key, nonce, tag)


def save_aes_metadata(result: AESEncryptionResult, output_path: Path) -> None:
    """Persist AES encryption metrics/metadata to a JSON file.

    Args:
        result: The encryption result to serialize.
        output_path: Destination JSON file path.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(result.to_metadata_dict(), handle, indent=2)
    logger.info("AES metadata saved to %s", output_path)
