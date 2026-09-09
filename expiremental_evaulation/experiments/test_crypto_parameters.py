"""
experiments/test_crypto_parameters.py

This script measures and records the byte sizes of cryptographic parameters
for the post-quantum secure authentication system.

Usage:
    python -m experiments.test_crypto_parameters
"""

import csv
import json
import logging
from pathlib import Path
from typing import Dict, Any

# Assuming the project root is in PYTHONPATH
from crypto import aes_utils, hash_utils, mlkem_utils, mldsa_utils

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def measure_and_save() -> None:
    """Measures cryptographic parameters and saves them to disk."""
    results: Dict[str, Any] = {}
    sample_template = b"dummy_fingerprint_template_data_12345678"
    
    try:
        # 1. AES-256-GCM
        key = aes_utils.generate_aes_key()
        aes_result = aes_utils.encrypt_bytes(sample_template, key)
        results.update({
            "AES key size (bytes)": len(key),
            "Nonce size": len(aes_result.nonce),
            "Authentication tag size": len(aes_result.tag),
            "Plaintext size": len(sample_template),
            "Ciphertext size": len(aes_result.ciphertext)
        })

        # 2. SHA3-256
        hash_result = hash_utils.hash_template(sample_template)
        # Convert hex digest string back to raw bytes to measure structural byte length
        digest_bytes = bytes.fromhex(hash_result.digest_hex)
        results["SHA3-256 digest size"] = len(digest_bytes)

        # 3. ML-KEM-1024
        kem_keypair = mlkem_utils.generate_keypair()
        kem_encap = mlkem_utils.encapsulate_aes_key(kem_keypair.public_key)
        results.update({
            "KEM Public key size": len(kem_keypair.public_key),
            "KEM Secret key size": len(kem_keypair.secret_key),
            "KEM ciphertext size": len(kem_encap.kem_ciphertext),
            "Shared secret size": len(kem_encap.shared_secret)
        })

        # 4. ML-DSA-87
        dsa_keypair = mldsa_utils.generate_keypair()
        dsa_result = mldsa_utils.sign_package(dsa_keypair.secret_key, sample_template)
        results.update({
            "DSA Public key size": len(dsa_keypair.public_key),
            "DSA Secret key size": len(dsa_keypair.secret_key),
            "Signature size": len(dsa_result.signature)
        })

        # Print IEEE-style Table
        print("\n" + "="*47)
        print(f" {'IEEE Cryptographic Parameter Table':^45} ")
        print("="*47)
        print(f"{'Parameter':<30} | {'Size (Bytes)':<12}")
        print("-" * 47)
        for k, v in results.items():
            print(f"{k:<30} | {v:<12}")
        print("="*47 + "\n")

        # Save files using pathlib
        output_dir = Path("results")
        output_dir.mkdir(exist_ok=True)
        
        # Save CSV
        with open(output_dir / "crypto_parameter_sizes.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Parameter", "Size (Bytes)"])
            for k, v in results.items():
                writer.writerow([k, v])
        
        # Save JSON
        with open(output_dir / "crypto_parameter_sizes.json", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
            
        logging.info("Results successfully written to results/ directory.")

    except Exception as e:
        logging.error(f"An error occurred during measurement: {e}")
        raise

if __name__ == "__main__":
    measure_and_save()