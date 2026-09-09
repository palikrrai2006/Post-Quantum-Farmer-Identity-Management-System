"""
registration/register_fingerprint.py
======================================
Full per-finger enrollment pipeline (spec section 24):

  image -> preprocessing -> SourceAFIS template
        -> ML-KEM encapsulate -> KDF -> AES-256-GCM encrypt
        -> ML-DSA-87 sign -> SHA3-256 integrity hash
        -> IPFS upload -> blockchain anchor (CID + hash)
        -> record metadata in SQLite

Enforces:
  - duplicate finger_position rejected
  - MAX_FINGERPRINTS respected
  - partial-failure safety (section 25): if IPFS succeeds but blockchain
    fails, the fingerprint is NOT marked REGISTERED in the DB.
"""

import os

import config
from crypto import mlkem, mldsa, secure_package
from biometric import template_extraction
from storage import ipfs_utils, local_store
from blockchain import blockchain_utils
from services import farmer_service, audit_service


class DuplicateFingerError(Exception):
    pass


class FingerLimitExceededError(Exception):
    pass


class RegistrationTransactionError(Exception):
    """Raised on partial failure (e.g. IPFS ok, blockchain failed) so the caller can
    surface a clear retry/cleanup path instead of silently marking success."""


def _ensure_farmer_keys(farmer_id: str):
    """Generate ML-KEM + ML-DSA keypairs for this farmer on first enrollment only."""
    if local_store.farmer_has_keypairs(farmer_id):
        return local_store.load_keypairs(farmer_id)

    kem_pk, kem_sk, _ = mlkem.generate_keypair()
    dsa_pk, dsa_sk, _ = mldsa.generate_keypair()
    local_store.save_keypairs(farmer_id, kem_pk, kem_sk, dsa_pk, dsa_sk)
    return {
        "kem_public_key": kem_pk, "kem_secret_key": kem_sk,
        "dsa_public_key": dsa_pk, "dsa_secret_key": dsa_sk,
    }


def enroll_fingerprint(farmer_id: str, finger_position: str, image_path: str,
                        registration_center_id: int, operator_user_id: int) -> dict:
    if finger_position not in config.VALID_FINGER_POSITIONS:
        raise ValueError(f"Invalid finger position: {finger_position}")

    if farmer_service.finger_already_enrolled(farmer_id, finger_position):
        raise DuplicateFingerError(f"{finger_position} is already registered for {farmer_id}")

    if not farmer_service.can_enroll_another_finger(farmer_id):
        raise FingerLimitExceededError(
            f"{farmer_id} already has {config.MAX_FINGERPRINTS} fingerprints (maximum reached)"
        )

    keys = _ensure_farmer_keys(farmer_id)

    extraction = template_extraction.extract_template_from_image(image_path)
    template_bytes = extraction["template_bytes"]

    kdf_salt = os.urandom(16)
    package, crypto_timings = secure_package.build_secure_package(
        farmer_id=farmer_id,
        finger_position=finger_position,
        template_bytes=template_bytes,
        kem_public_key=keys["kem_public_key"],
        dsa_secret_key=keys["dsa_secret_key"],
        kdf_salt=kdf_salt,
        metadata={"registration_center_id": registration_center_id},
    )

    ipfs_result = ipfs_utils.upload_package(package)
    cid = ipfs_result["cid"]

    try:
        chain_result = blockchain_utils.store_fingerprint_record(
            farmer_id, finger_position, cid, package["integrity_hash"]
        )
    except Exception as e:
        # Partial failure: IPFS succeeded, blockchain did not. Do NOT record as REGISTERED.
        audit_service.log_action(
            user_id=operator_user_id, role="REGISTRATION_CENTER_OPERATOR",
            action=f"FINGERPRINT_ENROLL_PARTIAL_FAILURE:{finger_position}",
            target_farmer_id=farmer_id, result="FAILED",
        )
        raise RegistrationTransactionError(
            f"IPFS upload succeeded (CID {cid}) but blockchain anchoring failed: {e}. "
            f"Safe to retry — no DB record was created."
        )

    farmer_service.record_fingerprint_metadata(
        farmer_id=farmer_id, finger_position=finger_position, ipfs_cid=cid,
        integrity_hash=package["integrity_hash"], blockchain_tx_hash=chain_result["tx_hash"],
        registration_center_id=registration_center_id, registered_by=operator_user_id,
    )

    status, count = farmer_service.update_registration_status(farmer_id)

    audit_service.log_action(
        user_id=operator_user_id, role="REGISTRATION_CENTER_OPERATOR",
        action=f"FINGERPRINT_ENROLLED:{finger_position}", target_farmer_id=farmer_id, result="SUCCESS",
    )

    return {
        "farmer_id": farmer_id,
        "finger_position": finger_position,
        "ipfs_cid": cid,
        "integrity_hash": package["integrity_hash"],
        "blockchain_tx_hash": chain_result["tx_hash"],
        "registration_status": status,
        "fingerprint_count": count,
        "timings": {**crypto_timings, "ipfs_upload_ns": ipfs_result["upload_time_ns"],
                    "blockchain_storage_ns": chain_result["storage_time_ns"]},
    }
