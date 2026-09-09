"""End-to-end registration workflow.

Assumes SourceAFIS has already produced a plaintext fingerprint template
(.txt) file. This module performs SHA3-256 hashing, AES-256-GCM encryption,
ML-KEM-1024 encapsulation of the AES key, ML-DSA-87 signing, registration
package assembly, IPFS upload, and blockchain anchoring, returning a full
set of performance metrics for IEEE-paper reporting.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import (
    ALGO_HASH,
    ALGO_KEM,
    ALGO_SIGNATURE,
    ALGO_SYMMETRIC,
    PACKAGES_DIR,
    PKG_KEY_FILE,
    PKG_METADATA_FILE,
    PKG_SIGNATURE_FILE,
    PKG_TEMPLATE_FILE,
)
from crypto import aes_utils, hash_utils, key_manager, mldsa_utils, mlkem_utils
from logging_utils import get_logger
from blockchain.web3_utils import BlockchainManager
from storage import ipfs_utils

logger = get_logger(__name__)


@dataclass
class RegistrationMetrics:
    """Aggregated timing metrics for a single registration run."""

    sha3_time_seconds: float = 0.0
    aes_encryption_time_seconds: float = 0.0
    mlkem_keygen_time_seconds: float = 0.0
    mlkem_encapsulation_time_seconds: float = 0.0
    mldsa_keygen_time_seconds: float = 0.0
    mldsa_signing_time_seconds: float = 0.0
    ipfs_upload_time_seconds: float = 0.0
    blockchain_write_time_seconds: float = 0.0
    registration_time_seconds: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a flat, JSON-serializable dictionary of all metrics."""
        data = {
            "sha3_time_seconds": self.sha3_time_seconds,
            "aes_encryption_time_seconds": self.aes_encryption_time_seconds,
            "mlkem_keygen_time_seconds": self.mlkem_keygen_time_seconds,
            "mlkem_encapsulation_time_seconds": self.mlkem_encapsulation_time_seconds,
            "mldsa_keygen_time_seconds": self.mldsa_keygen_time_seconds,
            "mldsa_signing_time_seconds": self.mldsa_signing_time_seconds,
            "ipfs_upload_time_seconds": self.ipfs_upload_time_seconds,
            "blockchain_write_time_seconds": self.blockchain_write_time_seconds,
            "registration_time_seconds": self.registration_time_seconds,
        }
        data.update(self.extra)
        return data


@dataclass
class RegistrationResult:
    """Final output of the registration workflow."""

    farmer_id: str
    template_id: str
    package_directory: Path
    ipfs_cid: str
    blockchain_transaction_hash: str
    metrics: RegistrationMetrics


def _build_metadata(
    farmer_id: str,
    template_id: str,
    template_hash_hex: str,
    nonce_hex: str,
    ciphertext_size_bytes: int,
    metrics: RegistrationMetrics,
) -> dict[str, Any]:
    """Construct the ``metadata.json`` contents for a registration package.

    Args:
        farmer_id: Unique farmer/user identifier.
        template_id: Identifier of the source fingerprint template (e.g. "101_1").
        template_hash_hex: SHA3-256 hex digest of the plaintext template.
        nonce_hex: Hex-encoded AES-GCM nonce used for encryption.
        ciphertext_size_bytes: Size of the encrypted template in bytes.
        metrics: Timing metrics gathered so far in the workflow.

    Returns:
        A dictionary ready for JSON serialization.
    """
    return {
        "user_id": farmer_id,
        "template_id": template_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "algorithms_used": {
            "symmetric": ALGO_SYMMETRIC,
            "hash": ALGO_HASH,
            "kem": ALGO_KEM,
            "signature": ALGO_SIGNATURE,
        },
        "sha3_hash": template_hash_hex,
        "nonce_hex": nonce_hex,
        "ciphertext_size_bytes": ciphertext_size_bytes,
        "execution_times": metrics.to_dict(),
        "ipfs_cid": None,
        "blockchain_transaction_hash": None,
    }


def register_user(farmer_id: str, template_id: str, template_path: Path) -> RegistrationResult:
    """Run the complete registration workflow for a single farmer.

    Args:
        farmer_id: Unique identifier for the farmer being registered (e.g. "FRM001").
        template_id: Identifier of the SourceAFIS-extracted template (e.g. "101_1").
        template_path: Path to the plaintext fingerprint template (.txt) file
            produced by the existing SourceAFIS pipeline.

    Returns:
        A :class:`RegistrationResult` with the package location, IPFS CID,
        blockchain transaction hash, and full timing metrics.

    Raises:
        FileNotFoundError: If ``template_path`` does not exist.
    """
    template_path = Path(template_path)
    if not template_path.exists():
        raise FileNotFoundError(f"Fingerprint template not found: {template_path}")

    overall_start = time.perf_counter()
    metrics = RegistrationMetrics()

    package_dir = PACKAGES_DIR / farmer_id
    package_dir.mkdir(parents=True, exist_ok=True)

    # 1. Read template and compute SHA3-256 hash.
    plaintext_template = template_path.read_bytes()
    hash_result = hash_utils.hash_template(plaintext_template)
    metrics.sha3_time_seconds = hash_result.hash_time_seconds

    # 2. Generate random AES key, encrypt template with AES-256-GCM.
    template_enc_path = package_dir / PKG_TEMPLATE_FILE
    aes_key = aes_utils.generate_aes_key()
    aes_result = aes_utils.encrypt_bytes(plaintext_template, aes_key)
    metrics.aes_encryption_time_seconds = aes_result.encryption_time_seconds
    with template_enc_path.open("wb") as handle:
        handle.write(aes_result.nonce)
        handle.write(aes_result.tag)
        handle.write(aes_result.ciphertext)

    # 3. Load (or create) ML-KEM-1024 system keys and encapsulate the AES key.
    system_keys = key_manager.load_system_keys()
    kem_result = mlkem_utils.encapsulate_aes_key(system_keys.mlkem_public_key)
    metrics.mlkem_encapsulation_time_seconds = kem_result.encapsulation_time_seconds
    # Use the encapsulated shared secret to one-time-pad protect the AES key
    # (XOR), so the secret never travels in the clear and the AES key is
    # independently recoverable upon decapsulation.
    protected_aes_key = bytes(a ^ b for a, b in zip(aes_key, kem_result.shared_secret))
    key_kem_path = package_dir / PKG_KEY_FILE
    with key_kem_path.open("wb") as handle:
        handle.write(len(kem_result.kem_ciphertext).to_bytes(4, "big"))
        handle.write(kem_result.kem_ciphertext)
        handle.write(protected_aes_key)

    # 4. Load (or create) ML-DSA-87 system keys and sign the package.
    metadata = _build_metadata(
        farmer_id=farmer_id,
        template_id=template_id,
        template_hash_hex=hash_result.digest_hex,
        nonce_hex=aes_result.nonce.hex(),
        ciphertext_size_bytes=aes_result.ciphertext_size_bytes,
        metrics=metrics,
    )
    canonical_message = json.dumps(metadata, sort_keys=True).encode("utf-8") + template_enc_path.read_bytes() + (
        package_dir / PKG_KEY_FILE
    ).read_bytes()
    sign_result = mldsa_utils.sign_package(system_keys.mldsa_secret_key, canonical_message)
    metrics.mldsa_signing_time_seconds = sign_result.signing_time_seconds
    signature_path = package_dir / PKG_SIGNATURE_FILE
    signature_path.write_bytes(sign_result.signature)

    # 5. Finalize metadata.json with signature info and write to disk.
    metadata["execution_times"] = metrics.to_dict()
    metadata["signature_size_bytes"] = sign_result.signature_size_bytes
    metadata_path = package_dir / PKG_METADATA_FILE
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    # 6. Upload the assembled registration package to IPFS.
    upload_result = ipfs_utils.upload_directory(package_dir)
    metrics.ipfs_upload_time_seconds = upload_result.upload_time_seconds

    # 7. Anchor the CID and an integrity hash of the package on-chain.
    package_hash = hash_utils.hash_file(template_enc_path).digest_hex
    write_result = blockchain_utils.write_cid_to_blockchain(farmer_id, upload_result.cid, package_hash)
    metrics.blockchain_write_time_seconds = write_result.write_time_seconds

    # Update metadata.json with final on-chain references.
    metadata["ipfs_cid"] = upload_result.cid
    metadata["blockchain_transaction_hash"] = write_result.transaction_hash
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    metrics.registration_time_seconds = time.perf_counter() - overall_start

    logger.info(
        "Registration complete for farmer_id=%s template_id=%s cid=%s tx=%s in %.6f s.",
        farmer_id,
        template_id,
        upload_result.cid,
        write_result.transaction_hash,
        metrics.registration_time_seconds,
    )

    return RegistrationResult(
        farmer_id=farmer_id,
        template_id=template_id,
        package_directory=package_dir,
        ipfs_cid=upload_result.cid,
        blockchain_transaction_hash=write_result.transaction_hash,
        metrics=metrics,
    )
