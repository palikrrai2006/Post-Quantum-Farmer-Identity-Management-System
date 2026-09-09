"""
verification/verify_farmer.py
===============================
Full verification pipeline (spec section 26/27):

  farmer_id + finger_position + new fingerprint image
    -> blockchain lookup (CID + integrity hash)
    -> IPFS download
    -> SHA3-256 check -> ML-DSA-87 signature check -> ML-KEM decapsulate
       -> KDF -> AES-256-GCM decrypt  (registered template recovered)
    -> new image -> preprocessing -> SourceAFIS template
    -> SourceAFIS match(registered, new) -> score >= threshold?

Any failure at any stage is a hard REJECT — never a silent pass-through.
Supports 1-of-N (normal) and 2-of-N (high security) policies.
"""

import config
from biometric import template_extraction, fingerprint_matcher
from crypto import secure_package
from storage import ipfs_utils, local_store
from blockchain import blockchain_utils
from services import audit_service


class VerificationRejected(Exception):
    """Base class for any rejection reason — callers should catch this and
    report IDENTITY VERIFICATION FAILED without leaking which stage failed
    to end users (the specific reason still goes to the audit/server log)."""


def verify_single_finger(farmer_id: str, finger_position: str, new_image_path: str,
                          requesting_user_id: int, requesting_role: str) -> dict:
    try:
        chain_record = blockchain_utils.retrieve_fingerprint_record(farmer_id, finger_position)
    except Exception as e:
        _reject(requesting_user_id, requesting_role, farmer_id, finger_position, f"BLOCKCHAIN_LOOKUP_FAILED: {e}")

    if chain_record["status"] != 0:  # 0 == Status.REGISTERED in the Solidity enum
        _reject(requesting_user_id, requesting_role, farmer_id, finger_position, "RECORD_REVOKED")

    try:
        download = ipfs_utils.download_package(chain_record["ipfs_cid"])
    except Exception as e:
        _reject(requesting_user_id, requesting_role, farmer_id, finger_position, f"IPFS_DOWNLOAD_FAILED: {e}")

    package = download["package"]
    keys = local_store.load_keypairs(farmer_id)

    try:
        decrypted = secure_package.verify_secure_package(
            package=package,
            expected_farmer_id=farmer_id,
            expected_finger_position=finger_position,
            expected_integrity_hash=chain_record["integrity_hash"],
            dsa_public_key=keys["dsa_public_key"],
            kem_secret_key=keys["kem_secret_key"],
        )
    except secure_package.PackageIntegrityError as e:
        _reject(requesting_user_id, requesting_role, farmer_id, finger_position, f"HASH_MISMATCH: {e}")
    except secure_package.PackageSignatureError as e:
        _reject(requesting_user_id, requesting_role, farmer_id, finger_position, f"SIGNATURE_INVALID: {e}")
    except secure_package.PackageDecryptionError as e:
        _reject(requesting_user_id, requesting_role, farmer_id, finger_position, f"AES_GCM_AUTH_FAILED: {e}")

    registered_template = decrypted["template_bytes"]

    new_extraction = template_extraction.extract_template_from_image(new_image_path)
    new_template = new_extraction["template_bytes"]

    match_result = fingerprint_matcher.match_fingerprints(registered_template, new_template)

    result = {
        "farmer_id": farmer_id,
        "finger_position": finger_position,
        "score": match_result["score"],
        "threshold": match_result["threshold"],
        "authenticated": match_result["authenticated"],
    }

    audit_service.log_action(
        user_id=requesting_user_id, role=requesting_role,
        action=f"BIOMETRIC_VERIFICATION:{finger_position}", target_farmer_id=farmer_id,
        result="SUCCESS" if result["authenticated"] else "FAILED",
    )

    if not result["authenticated"]:
        raise VerificationRejected("IDENTITY VERIFICATION FAILED — score below threshold")

    return result


def verify_multi_finger(farmer_id: str, finger_positions: list, image_paths: dict,
                         requesting_user_id: int, requesting_role: str,
                         required_count: int = None) -> dict:
    """
    2-of-N (or configurable N-of-N) high-security verification. ALL listed
    fingers in finger_positions must independently pass verify_single_finger.
    """
    required_count = required_count or config.HIGH_SECURITY_FINGER_COUNT
    if len(finger_positions) < required_count:
        raise ValueError(f"Need at least {required_count} finger positions, got {len(finger_positions)}")

    results = []
    passed = 0
    for pos in finger_positions:
        try:
            r = verify_single_finger(farmer_id, pos, image_paths[pos], requesting_user_id, requesting_role)
            results.append(r)
            passed += 1
        except VerificationRejected as e:
            results.append({"finger_position": pos, "authenticated": False, "error": str(e)})

    authenticated = passed >= required_count
    audit_service.log_action(
        user_id=requesting_user_id, role=requesting_role,
        action=f"HIGH_SECURITY_VERIFICATION({passed}/{required_count})", target_farmer_id=farmer_id,
        result="SUCCESS" if authenticated else "FAILED",
    )
    return {"farmer_id": farmer_id, "authenticated": authenticated, "results": results,
            "passed": passed, "required": required_count}


def _reject(user_id, role, farmer_id, finger_position, reason):
    audit_service.log_action(
        user_id=user_id, role=role, action=f"VERIFICATION_REJECTED:{finger_position}:{reason}",
        target_farmer_id=farmer_id, result="FAILED",
    )
    raise VerificationRejected(reason)
