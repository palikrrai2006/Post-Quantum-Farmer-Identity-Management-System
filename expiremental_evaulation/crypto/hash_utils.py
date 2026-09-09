"""SHA3-256 hashing utilities for fingerprint template integrity verification."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from logging_utils import get_logger

logger = get_logger(__name__)

_CHUNK_SIZE_BYTES = 65536


@dataclass
class HashResult:
    """Container for a SHA3-256 hashing operation and its metrics."""

    digest_hex: str
    input_size_bytes: int
    hash_time_seconds: float

    def to_metadata_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of this result."""
        return {
            "algorithm": "SHA3-256",
            "digest_hex": self.digest_hex,
            "input_size_bytes": self.input_size_bytes,
            "hash_time_seconds": self.hash_time_seconds,
        }


def hash_template(template_bytes: bytes) -> HashResult:
    """Compute the SHA3-256 digest of in-memory template bytes.

    Args:
        template_bytes: The fingerprint template data to hash.

    Returns:
        A :class:`HashResult` containing the hex digest and timing metrics.
    """
    start_time = time.perf_counter()
    digest = hashlib.sha3_256(template_bytes).hexdigest()
    elapsed = time.perf_counter() - start_time

    logger.info("SHA3-256 hash computed over %d bytes in %.6f s.", len(template_bytes), elapsed)
    return HashResult(
        digest_hex=digest,
        input_size_bytes=len(template_bytes),
        hash_time_seconds=elapsed,
    )


def hash_file(file_path: Path) -> HashResult:
    """Compute the SHA3-256 digest of a file's contents using streamed reads.

    Args:
        file_path: Path to the file to hash.

    Returns:
        A :class:`HashResult` containing the hex digest and timing metrics.

    Raises:
        FileNotFoundError: If ``file_path`` does not exist.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found for hashing: {file_path}")

    hasher = hashlib.sha3_256()
    total_size = 0
    start_time = time.perf_counter()
    with file_path.open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK_SIZE_BYTES)
            if not chunk:
                break
            hasher.update(chunk)
            total_size += len(chunk)
    elapsed = time.perf_counter() - start_time

    logger.info("SHA3-256 hash computed over file %s (%d bytes) in %.6f s.", file_path, total_size, elapsed)
    return HashResult(
        digest_hex=hasher.hexdigest(),
        input_size_bytes=total_size,
        hash_time_seconds=elapsed,
    )


def verify_hash(template_bytes: bytes, expected_digest_hex: str) -> bool:
    """Verify that template bytes match an expected SHA3-256 digest.

    Args:
        template_bytes: The data to verify.
        expected_digest_hex: The previously computed hex digest to compare against.

    Returns:
        ``True`` if the computed digest matches ``expected_digest_hex``, else ``False``.
    """
    computed = hashlib.sha3_256(template_bytes).hexdigest()
    is_valid = computed == expected_digest_hex.lower()
    if is_valid:
        logger.info("SHA3-256 hash verification succeeded.")
    else:
        logger.warning("SHA3-256 hash verification FAILED. Expected %s, got %s.", expected_digest_hex, computed)
    return is_valid


def save_hash_metadata(result: HashResult, output_path: Path) -> None:
    """Persist hashing metrics/metadata to a JSON file.

    Args:
        result: The hashing result to serialize.
        output_path: Destination JSON file path.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(result.to_metadata_dict(), handle, indent=2)
    logger.info("Hash metadata saved to %s", output_path)
