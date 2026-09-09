"""End-to-end verification workflow.

Retrieves a farmer's registration package via the on-chain CID anchor,
verifies the ML-DSA-87 signature, recovers the AES-256 key via ML-KEM-1024
decapsulation, decrypts and SHA3-256-verifies the stored template, then
delegates template-vs-template comparison to the existing SourceAFIS
matching pipeline (``biometric_module``), which is NOT reimplemented here.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from config import (
    KEYS_DIR,
    MLDSA_PUBLIC_KEY_FILE,
    PACKAGES_DIR,
    PKG_KEY_FILE,
    PKG_METADATA_FILE,
    PKG_SIGNATURE_FILE,
    PKG_TEMPLATE_FILE,
    SOURCEAFIS_MATCH_THRESHOLD,
)
from crypto import aes_utils, hash_utils, key_manager, mldsa_utils, mlkem_utils
from logging_utils import get_logger
from storage import blockchain_utils, ipfs_utils

logger = get_logger(__name__)


@dataclass
class VerificationMetrics:
    """Aggregated timing metrics for a single verification run."""

    blockchain_read_time_seconds: float = 0.0
    ipfs_download_time_seconds: float = 0.0
    mldsa_verification_time_seconds: float = 0.0
    mlkem_decapsulation_time_seconds: float = 0.0
    aes_decryption_time_seconds: float = 0.0
    sha3_verification_time_seconds: float = 0.0
    matching_time_seconds: float = 0.0
    verification_time_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return a flat, JSON-serializable dictionary of all metrics."""
        return {
            "blockchain_read_time_seconds": self.blockchain_read_time_seconds,
            "ipfs_download_time_seconds": self.ipfs_download_time_seconds,
            "mldsa_verification_time_seconds": self.mldsa_verification_time_seconds,
            "mlkem_decapsulation_time_seconds": self.mlkem_decapsulation_time_seconds,
            "aes_decryption_time_seconds": self.aes_decryption_time_seconds,
            "sha3_verification_time_seconds": self.sha3_verification_time_seconds,
            "matching_time_seconds": self.matching_time_seconds,
            "verification_time_seconds": self.verification_time_seconds,
        }


@dataclass
class VerificationResult:
    """Final output of the verification workflow."""

    farmer_id: str
    signature_valid: bool
    hash_valid: bool
    match_score: float
    accepted: bool
    metrics: VerificationMetrics
    failure_reason: str | None = field(default=None)


def _recover_aes_key(key_kem_path: Path, mlkem_secret_key: bytes) -> tuple[bytes, float]:
    """Decapsulate the ML-KEM-1024 shared secret and recover the AES-256 key.

    Args:
        key_kem_path: Path to the package's ``key.kem`` file, laid out as
            ``[4-byte length][kem_ciphertext][protected_aes_key]``.
        mlkem_secret_key: The system's ML-KEM-1024 secret key.

    Returns:
        A tuple of ``(recovered_aes_key, decapsulation_time_seconds)``.
    """
    raw = key_kem_path.read_bytes()
    ct_length = int.from_bytes(raw[:4], "big")
    kem_ciphertext = raw[4 : 4 + ct_length]
    protected_aes_key = raw[4 + ct_length :]

    decap_result = mlkem_utils.decapsulate_aes_key(mlkem_secret_key, kem_ciphertext)
    recovered_aes_key = bytes(a ^ b for a, b in zip(protected_aes_key, decap_result.shared_secret))
    return recovered_aes_key, decap_result.decapsulation_time_seconds


def verify_user(farmer_id: str, live_template_path: Path) -> VerificationResult:
    """Run the complete verification workflow for a single farmer.

    Args:
        farmer_id: Unique identifier of the farmer to verify (e.g. "FRM001").
        live_template_path: Path to the freshly captured, SourceAFIS-extracted
            fingerprint template (.txt) for the live verification attempt.

    Returns:
        A :class:`VerificationResult` describing whether the attempt was
        accepted, along with the match score and full timing metrics.
    """
    live_template_path = Path(live_template_path)
    if not live_template_path.exists():
        raise FileNotFoundError(f"Live fingerprint template not found: {live_template_path}")

    overall_start = time.perf_counter()
    metrics = VerificationMetrics()

    # 1. Retrieve the CID anchored on-chain for this farmer.
    read_result = blockchain_utils.read_cid_from_blockchain(farmer_id)
    metrics.blockchain_read_time_seconds = read_result.read_time_seconds

    # 2. Download the registration package from IPFS.
    download_dir = PACKAGES_DIR / f"{farmer_id}_retrieved"
    download_result = ipfs_utils.download_directory(read_result.cid, download_dir)
    metrics.ipfs_download_time_seconds = download_result.download_time_seconds

    package_dir = download_dir / farmer_id
    metadata_path = package_dir / PKG_METADATA_FILE
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    template_enc_path = package_dir / PKG_TEMPLATE_FILE
    key_kem_path = package_dir / PKG_KEY_FILE
    signature_path = package_dir / PKG_SIGNATURE_FILE

    # 3. Verify the ML-DSA-87 signature over the package contents.
    mldsa_public_key = MLDSA_PUBLIC_KEY_FILE.read_bytes() if MLDSA_PUBLIC_KEY_FILE.exists() else b""
    if not mldsa_public_key:
        raise FileNotFoundError(f"ML-DSA-87 public key not found at {MLDSA_PUBLIC_KEY_FILE}")

    metadata_for_signing = dict(metadata)
    metadata_for_signing["ipfs_cid"] = None
    metadata_for_signing["blockchain_transaction_hash"] = None
    metadata_for_signing.pop("signature_size_bytes", None)
    canonical_message = (
        json.dumps(metadata_for_signing, sort_keys=True).encode("utf-8")
        + template_enc_path.read_bytes()
        + key_kem_path.read_bytes()
    )
    signature = signature_path.read_bytes()
    verify_result = mldsa_utils.verify_signature(mldsa_public_key, canonical_message, signature)
    metrics.mldsa_verification_time_seconds = verify_result.verification_time_seconds

    if not verify_result.is_valid:
        metrics.verification_time_seconds = time.perf_counter() - overall_start
        logger.warning("Signature verification failed for farmer_id=%s; rejecting.", farmer_id)
        return VerificationResult(
            farmer_id=farmer_id,
            signature_valid=False,
            hash_valid=False,
            match_score=0.0,
            accepted=False,
            metrics=metrics,
            failure_reason="ML-DSA-87 signature verification failed.",
        )

    # 4. Recover the AES key via ML-KEM-1024 decapsulation.
    _, mlkem_secret_key = key_manager.get_or_create_mlkem_keys()
    recovered_aes_key, decap_time = _recover_aes_key(key_kem_path, mlkem_secret_key)
    metrics.mlkem_decapsulation_time_seconds = decap_time

    # 5. Decrypt the stored template with AES-256-GCM.
    decryption_result = aes_utils.decrypt_template_file(template_enc_path, recovered_aes_key)
    metrics.aes_decryption_time_seconds = decryption_result.decryption_time_seconds
    stored_template_bytes = decryption_result.plaintext

    # 6. Verify the SHA3-256 hash of the recovered template.
    hash_start = time.perf_counter()
    hash_valid = hash_utils.verify_hash(stored_template_bytes, metadata["sha3_hash"])
    metrics.sha3_verification_time_seconds = time.perf_counter() - hash_start

    if not hash_valid:
        metrics.verification_time_seconds = time.perf_counter() - overall_start
        logger.warning("Hash verification failed for farmer_id=%s; rejecting.", farmer_id)
        return VerificationResult(
            farmer_id=farmer_id,
            signature_valid=True,
            hash_valid=False,
            match_score=0.0,
            accepted=False,
            metrics=metrics,
            failure_reason="SHA3-256 hash verification failed.",
        )

    # 7. Write the recovered plaintext template to a temp file and compare
    #    against the live template using the EXISTING SourceAFIS matcher.
    #    This module does not reimplement biometric matching; it calls into
    #    the project's existing `biometric_module`.
    recovered_template_path = download_dir / "recovered_template.txt"
    recovered_template_path.write_bytes(stored_template_bytes)

    match_start = time.perf_counter()
    match_score = _match_with_sourceafis(recovered_template_path, live_template_path)
    metrics.matching_time_seconds = time.perf_counter() - match_start

    accepted = match_score >= SOURCEAFIS_MATCH_THRESHOLD
    metrics.verification_time_seconds = time.perf_counter() - overall_start

    logger.info(
        "Verification complete for farmer_id=%s: score=%.4f threshold=%.4f accepted=%s in %.6f s.",
        farmer_id,
        match_score,
        SOURCEAFIS_MATCH_THRESHOLD,
        accepted,
        metrics.verification_time_seconds,
    )

    return VerificationResult(
        farmer_id=farmer_id,
        signature_valid=True,
        hash_valid=True,
        match_score=match_score,
        accepted=accepted,
        metrics=metrics,
    )


def _match_with_sourceafis(template_a_path: Path, template_b_path: Path) -> float:
    """Delegate fingerprint template comparison to the existing SourceAFIS pipeline.

    This project already has a working SourceAFIS-based matcher (per the
    existing biometric pipeline). Import it here rather than reimplementing
    any matching logic. Adjust the import below to match the actual module
    and function name used elsewhere in the project (e.g. ``biometric_module``).

    Args:
        template_a_path: Path to the first (recovered/stored) template file.
        template_b_path: Path to the second (live) template file.

    Returns:
        The SourceAFIS similarity score as a float.

    Raises:
        ImportError: If the existing biometric matching module cannot be found.
    """
    try:
        from biometric_module import match_templates  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ImportError(
            "Could not import 'match_templates' from the existing 'biometric_module'. "
            "Update the import in verification/verify_user.py to point at your "
            "project's existing SourceAFIS matching function."
        ) from exc

    return float(match_templates(str(template_a_path), str(template_b_path)))
