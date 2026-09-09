import json
import time
import shutil
from dataclasses import dataclass
from pathlib import Path
import config
from crypto import aes_utils, hash_utils, mlkem_utils, mldsa_utils
from storage import ipfs_utils
from blockchain.web3_utils import BlockchainManager
from backend.sourceafis_bridge import match_templates

@dataclass
class VerificationResult:
    user_id: str
    is_signature_valid: bool
    is_hash_valid: bool
    match_score: float
    authenticated: bool
    time_ms_dsa: float
    time_ms_kem: float
    time_ms_aes: float
    time_ms_hash: float
    time_ms_match: float
    time_ms_total: float

def verify_template(user_id: str, live_template_bytes: bytes) -> VerificationResult:
    start_time = time.perf_counter()
    bm = BlockchainManager()
    
    # 1. Retrieve & Download
    cid = bm.get_cid(user_id)
    if not cid:
        raise ValueError(f"User '{user_id}' is not registered.")
        
    # Use per-user temporary directory for verification
    package_path = Path(config.PACKAGES_DIR) / f"verify_{user_id}"
    
    # Download package (explicitly using output_directory as required by the API)
    ipfs_utils.download_package(cid, package_path)
    
    if not package_path.exists():
        raise FileNotFoundError("Downloaded package not found.")
        
    try:
        # 2. Load package components
        ciphertext = (package_path / config.PKG_TEMPLATE_FILE).read_bytes()
        kem_ct = (package_path / config.PKG_KEY_FILE).read_bytes()
        metadata_bytes = (package_path / config.PKG_METADATA_FILE).read_bytes()
        metadata = json.loads(metadata_bytes.decode("utf-8"))
        signature = (package_path / config.PKG_SIGNATURE_FILE).read_bytes()
        
        # 3. Load Per-User Keys
        user_key_dir = Path(config.KEYS_DIR) / user_id
        dsa_public, _ = mldsa_utils.load_keypair(
            user_key_dir / "mldsa_public.key",
            user_key_dir / "mldsa_secret.key"
        )
        _, kem_secret = mlkem_utils.load_keypair(
            user_key_dir / "mlkem_public.key",
            user_key_dir / "mlkem_secret.key"
        )

        # 4. Cryptographic Verification
        # Verify Signature (Timed)
        t0 = time.perf_counter()
        payload = ciphertext + kem_ct + metadata_bytes
        sig_res = mldsa_utils.verify_signature(dsa_public, payload, signature)
        is_sig_valid = sig_res.is_valid
        time_ms_dsa = (time.perf_counter() - t0) * 1000
        
        # Decapsulate (Timed)
        t0 = time.perf_counter()
        kem_res = mlkem_utils.decapsulate_aes_key(kem_secret, kem_ct)
        shared_secret = kem_res.shared_secret
        time_ms_kem = (time.perf_counter() - t0) * 1000
        
        # Decrypt (Timed)
        t0 = time.perf_counter()
        aes_res = aes_utils.decrypt_bytes(
            ciphertext,
            shared_secret,
            nonce=bytes.fromhex(metadata["aes_nonce"]),
            tag=bytes.fromhex(metadata["aes_tag"])
        )
        decrypted_template = aes_res.plaintext
        time_ms_aes = (time.perf_counter() - t0) * 1000
        
       # Verify Hash (Timed)
        t0 = time.perf_counter()

        is_hash_valid = hash_utils.verify_hash(
            decrypted_template,
            metadata["fingerprint_hash"]
        )

        time_ms_hash = (time.perf_counter() - t0) * 1000
        
        # 5. Biometric Matching (Timed)
        t0 = time.perf_counter()
        match_score = match_templates(live_template_bytes, decrypted_template)
        time_ms_match = (time.perf_counter() - t0) * 1000
        
        # 6. Final Decision
        authenticated = (
            is_sig_valid and
            is_hash_valid and
            match_score >= config.SOURCEAFIS_MATCH_THRESHOLD
        )
        
        return VerificationResult(
            user_id=user_id,
            is_signature_valid=is_sig_valid,
            is_hash_valid=is_hash_valid,
            match_score=match_score,
            authenticated=authenticated,
            time_ms_dsa=time_ms_dsa,
            time_ms_kem=time_ms_kem,
            time_ms_aes=time_ms_aes,
            time_ms_hash=time_ms_hash,
            time_ms_match=time_ms_match,
            time_ms_total=(time.perf_counter() - start_time) * 1000
        )
    
    finally:
        # Cleanup temporary verification directory
        if package_path.exists():
            shutil.rmtree(package_path, ignore_errors=True)