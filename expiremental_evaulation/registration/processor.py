import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
import config
from crypto import aes_utils, hash_utils, mlkem_utils, mldsa_utils
from storage import ipfs_utils
from blockchain.web3_utils import BlockchainManager

logger = logging.getLogger(__name__)

@dataclass
class RegistrationResult:
    user_id: str
    cid: str
    tx_hash: str
    time_ms_prep: float
    time_ms_extract: float
    time_ms_hash: float
    time_ms_kem: float
    time_ms_aes: float
    time_ms_dsa: float
    time_ms_upload: float
    time_ms_blockchain: float
    time_ms_total: float
    package_size_bytes: int
    success: bool

def register_template(
    user_id: str,
    template_bytes: bytes,
    prep_time: float = 0.0,
    extract_time: float = 0.0
) -> RegistrationResult:
    """
    Registers a user fingerprint template by generating unique per-user 
    post-quantum key pairs and encrypting/signing accordingly.
    """
    
    # 1. Create per-user key directory
    user_key_dir = Path(config.KEYS_DIR) / user_id
    user_key_dir.mkdir(parents=True, exist_ok=True)

    package_dir = Path(config.PACKAGES_DIR) / user_id
    package_dir.mkdir(parents=True, exist_ok=True)

    t_total_start = time.perf_counter()

    try:
        # ---------------- SHA3 ----------------
        t0 = time.perf_counter()
        hash_res = hash_utils.hash_template(template_bytes)
        hash_time = (time.perf_counter() - t0) * 1000

        # ---------------- ML-KEM ----------------
        t0 = time.perf_counter()
        # Generate per-user KEM key pair
        kem_keys = mlkem_utils.generate_keypair()
        mlkem_utils.save_keypair(
            kem_keys,
            user_key_dir / "mlkem_public.key",
            user_key_dir / "mlkem_secret.key"
        )
        kem_encap = mlkem_utils.encapsulate_aes_key(kem_keys.public_key)
        kem_time = (time.perf_counter() - t0) * 1000

        # ---------------- AES ----------------
        t0 = time.perf_counter()
        aes_res = aes_utils.encrypt_bytes(
            template_bytes,
            kem_encap.shared_secret
        )
        aes_time = (time.perf_counter() - t0) * 1000

        # ---------------- Metadata ----------------
        metadata = {
            "user_id": user_id,
            "fingerprint_hash": hash_res.digest_hex,
            "hash_algorithm": "SHA3-256",
            "kem_algorithm": "ML-KEM-1024",
            "aes_algorithm": "AES-256-GCM",
            "signature_algorithm": "ML-DSA-87",
            "aes_nonce": aes_res.nonce.hex(),
            "aes_tag": aes_res.tag.hex()
        }
        metadata_bytes = json.dumps(metadata).encode("utf-8")

        # ---------------- ML-DSA ----------------
        t0 = time.perf_counter()
        # Generate per-user DSA key pair
        dsa_keys = mldsa_utils.generate_keypair()
        mldsa_utils.save_keypair(
            dsa_keys,
            user_key_dir / "mldsa_public.key",
            user_key_dir / "mldsa_secret.key"
        )
        payload = (
            aes_res.ciphertext +
            kem_encap.kem_ciphertext +
            metadata_bytes
        )
        dsa_res = mldsa_utils.sign_package(dsa_keys.secret_key, payload)
        dsa_time = (time.perf_counter() - t0) * 1000

        # ---------------- Write Package ----------------
        (package_dir / config.PKG_TEMPLATE_FILE).write_bytes(aes_res.ciphertext)
        (package_dir / config.PKG_KEY_FILE).write_bytes(kem_encap.kem_ciphertext)
        (package_dir / config.PKG_METADATA_FILE).write_bytes(metadata_bytes)
        (package_dir / config.PKG_SIGNATURE_FILE).write_bytes(dsa_res.signature)

        # ---------------- IPFS ----------------
        upload_res = ipfs_utils.upload_package(package_dir)

        # ---------------- Blockchain ----------------
        t0 = time.perf_counter()
        bc = BlockchainManager()
        tx_hash = bc.store_cid(user_id, upload_res.cid)
        blockchain_time = (time.perf_counter() - t0) * 1000

        total_time = (time.perf_counter() - t_total_start) * 1000

        return RegistrationResult(
            user_id=user_id,
            cid=upload_res.cid,
            tx_hash=tx_hash,
            time_ms_prep=prep_time,
            time_ms_extract=extract_time,
            time_ms_hash=hash_time,
            time_ms_kem=kem_time,
            time_ms_aes=aes_time,
            time_ms_dsa=dsa_time,
            time_ms_upload=upload_res.upload_time_milliseconds,
            time_ms_blockchain=blockchain_time,
            time_ms_total=total_time,
            package_size_bytes=upload_res.package_size_bytes,
            success=True
        )

    except Exception as e:
        logger.error(f"Workflow Failed: {e}")
        raise