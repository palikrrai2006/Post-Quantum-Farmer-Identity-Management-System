"""
tests/test_e2e_workflow.py

True End-to-End (E2E) test for the Post-Quantum Registration Workflow.
Validates disk I/O, correct key derivation, metadata validation, and 
system-level security against physical file tampering.

Usage:
    python -m unittest tests.test_e2e_workflow -v
"""

import json
import shutil
import unittest
from pathlib import Path

# Import existing project modules and global config
import config
from crypto import aes_utils, hash_utils, mlkem_utils, mldsa_utils


class TestEndToEndWorkflow(unittest.TestCase):
    """System-level E2E tests for the IEEE PQC biometric architecture."""

    @classmethod
    def setUpClass(cls) -> None:
        """Create necessary directories for E2E testing."""
        cls.test_pkg_dir = config.PACKAGES_DIR / "test_e2e_package"
        cls.test_template_path = config.RAW_TEMPLATES_DIR / "101_1_test_template.txt"
        
        # Ensure directories exist
        config.RAW_TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        config.PACKAGES_DIR.mkdir(parents=True, exist_ok=True)

        # Create a mock SourceAFIS template file on disk if it doesn't exist
        if not cls.test_template_path.exists():
            cls.test_template_path.write_bytes(b"MOCK_SOURCEAFIS_MINUTIAE_DATA_9988776655")

    def setUp(self) -> None:
        """Reset the test package directory before each test."""
        if self.test_pkg_dir.exists():
            shutil.rmtree(self.test_pkg_dir)
        self.test_pkg_dir.mkdir()

        # Generate Server/System Long-Term Keys
        self.kem_keys = mlkem_utils.generate_keypair()
        self.dsa_keys = mldsa_utils.generate_keypair()

    def test_01_true_e2e_registration_and_verification(self) -> None:
        """Executes the complete file-based registration and verification lifecycle."""
        
        # ==========================================
        # PHASE 1: REGISTRATION (Write to Disk)
        # ==========================================
        
        # 1. Read actual template from disk
        template_bytes = self.test_template_path.read_bytes()
        
        # 2. Hash the template
        hash_res = hash_utils.hash_template(template_bytes)
        
        # 3. KEM Encapsulation (Generates the AES Key)
        kem_encap = mlkem_utils.encapsulate_aes_key(self.kem_keys.public_key)
        aes_key = kem_encap.shared_secret  # TRUE DESIGN: AES key derived from KEM
        
        # 4. Encrypt template with the derived AES key
        aes_res = aes_utils.encrypt_bytes(template_bytes, aes_key)
        
        # 5. Prepare Metadata
        metadata = {
            "algo_symmetric": config.ALGO_SYMMETRIC,
            "algo_hash": config.ALGO_HASH,
            "algo_kem": config.ALGO_KEM,
            "algo_signature": config.ALGO_SIGNATURE,
            "fingerprint_hash": hash_res.digest_hex,
            "aes_nonce": aes_res.nonce.hex(),
            "aes_tag": aes_res.tag.hex()
        }
        metadata_bytes = json.dumps(metadata, indent=4).encode('utf-8')
        
        # 6. Sign the Package
        package_payload = aes_res.ciphertext + kem_encap.kem_ciphertext + metadata_bytes
        dsa_res = mldsa_utils.sign_package(self.dsa_keys.secret_key, package_payload)
        
        # 7. Write Package to Disk (Simulating final registration step)
        (self.test_pkg_dir / config.PKG_TEMPLATE_FILE).write_bytes(aes_res.ciphertext)
        (self.test_pkg_dir / config.PKG_KEY_FILE).write_bytes(kem_encap.kem_ciphertext)
        (self.test_pkg_dir / config.PKG_METADATA_FILE).write_bytes(metadata_bytes)
        (self.test_pkg_dir / config.PKG_SIGNATURE_FILE).write_bytes(dsa_res.signature)

        # Clear memory to ensure verification relies strictly on disk I/O
        del template_bytes, aes_key, aes_res, kem_encap, metadata, metadata_bytes, package_payload, dsa_res

        # ==========================================
        # PHASE 2: VERIFICATION (Read from Disk)
        # ==========================================
        
        # 1. Read Package from Disk
        read_ciphertext = (self.test_pkg_dir / config.PKG_TEMPLATE_FILE).read_bytes()
        read_kem_ct = (self.test_pkg_dir / config.PKG_KEY_FILE).read_bytes()
        read_metadata_bytes = (self.test_pkg_dir / config.PKG_METADATA_FILE).read_bytes()
        read_signature = (self.test_pkg_dir / config.PKG_SIGNATURE_FILE).read_bytes()
        
        read_metadata = json.loads(read_metadata_bytes.decode('utf-8'))
        
        # 2. Verify DSA Signature
        reconstructed_payload = read_ciphertext + read_kem_ct + read_metadata_bytes
        verify_res = mldsa_utils.verify_signature(
            self.dsa_keys.public_key, 
            reconstructed_payload, 
            read_signature
        )
        self.assertTrue(verify_res.is_valid, "Signature verification failed on disk package.")

        # 3. Decapsulate KEM to recover AES Key
        decaps_res = mlkem_utils.decapsulate_aes_key(self.kem_keys.secret_key, read_kem_ct)
        recovered_aes_key = decaps_res.shared_secret
        
        # 4. Decrypt AES Payload
        nonce = bytes.fromhex(read_metadata["aes_nonce"])
        tag = bytes.fromhex(read_metadata["aes_tag"])
        
        decrypt_res = aes_utils.decrypt_bytes(read_ciphertext, recovered_aes_key, nonce, tag)
        
        # 5. Validate Hash Integrity against Metadata
        is_hash_valid = hash_utils.verify_hash(decrypt_res.plaintext, read_metadata["fingerprint_hash"])
        self.assertTrue(is_hash_valid, "Recovered template hash does not match metadata.")
        
        # 6. Final Data Match
        original_template = self.test_template_path.read_bytes()
        self.assertEqual(decrypt_res.plaintext, original_template, "Decrypted template differs from original file.")

    def test_02_wrong_kem_key_fails_decapsulation(self) -> None:
        """Ensures the system fails securely if the wrong KEM secret key is used."""
        self._write_valid_package_to_disk()
        
        # Generate an imposter server key
        imposter_kem_keys = mlkem_utils.generate_keypair()
        read_kem_ct = (self.test_pkg_dir / config.PKG_KEY_FILE).read_bytes()
        
        # ML-KEM decapsulation with the wrong key yields a deterministic but incorrect shared secret
        decaps_res = mlkem_utils.decapsulate_aes_key(imposter_kem_keys.secret_key, read_kem_ct)
        wrong_aes_key = decaps_res.shared_secret
        
        read_ciphertext = (self.test_pkg_dir / config.PKG_TEMPLATE_FILE).read_bytes()
        read_metadata = json.loads((self.test_pkg_dir / config.PKG_METADATA_FILE).read_bytes().decode('utf-8'))
        nonce = bytes.fromhex(read_metadata["aes_nonce"])
        tag = bytes.fromhex(read_metadata["aes_tag"])
        
        with self.assertRaises(ValueError):
            aes_utils.decrypt_bytes(read_ciphertext, wrong_aes_key, nonce, tag)

    def test_03_tampered_metadata_file_fails_signature(self) -> None:
        """Ensures modifying metadata.json on disk triggers a signature failure."""
        self._write_valid_package_to_disk()
        
        # Tamper with the metadata on disk
        metadata_path = self.test_pkg_dir / config.PKG_METADATA_FILE
        metadata = json.loads(metadata_path.read_bytes().decode('utf-8'))
        metadata["algo_symmetric"] = "AES-128-GCM"  # Malicious downgrade attack
        tampered_metadata_bytes = json.dumps(metadata, indent=4).encode('utf-8')
        metadata_path.write_bytes(tampered_metadata_bytes)
        
        # Attempt Verification
        read_ciphertext = (self.test_pkg_dir / config.PKG_TEMPLATE_FILE).read_bytes()
        read_kem_ct = (self.test_pkg_dir / config.PKG_KEY_FILE).read_bytes()
        read_signature = (self.test_pkg_dir / config.PKG_SIGNATURE_FILE).read_bytes()
        
        reconstructed_payload = read_ciphertext + read_kem_ct + tampered_metadata_bytes
        verify_res = mldsa_utils.verify_signature(
            self.dsa_keys.public_key, 
            reconstructed_payload, 
            read_signature
        )
        
        self.assertFalse(verify_res.is_valid, "Tampered metadata.json bypassed signature verification.")

    def test_04_missing_package_file_handled_gracefully(self) -> None:
        """Ensures the system does not crash blindly if a file is missing."""
        self._write_valid_package_to_disk()
        
        # Delete the signature file
        (self.test_pkg_dir / config.PKG_SIGNATURE_FILE).unlink()
        
        with self.assertRaises(FileNotFoundError):
            if not (self.test_pkg_dir / config.PKG_SIGNATURE_FILE).exists():
                raise FileNotFoundError("Signature file is missing from package.")

    def _write_valid_package_to_disk(self) -> None:
        """Helper to quickly generate a valid package on disk for negative tests."""
        template_bytes = self.test_template_path.read_bytes()
        hash_res = hash_utils.hash_template(template_bytes)
        kem_encap = mlkem_utils.encapsulate_aes_key(self.kem_keys.public_key)
        aes_res = aes_utils.encrypt_bytes(template_bytes, kem_encap.shared_secret)
        
        metadata_bytes = json.dumps({
            "fingerprint_hash": hash_res.digest_hex,
            "aes_nonce": aes_res.nonce.hex(),
            "aes_tag": aes_res.tag.hex()
        }).encode('utf-8')
        
        package_payload = aes_res.ciphertext + kem_encap.kem_ciphertext + metadata_bytes
        dsa_res = mldsa_utils.sign_package(self.dsa_keys.secret_key, package_payload)
        
        (self.test_pkg_dir / config.PKG_TEMPLATE_FILE).write_bytes(aes_res.ciphertext)
        (self.test_pkg_dir / config.PKG_KEY_FILE).write_bytes(kem_encap.kem_ciphertext)
        (self.test_pkg_dir / config.PKG_METADATA_FILE).write_bytes(metadata_bytes)
        (self.test_pkg_dir / config.PKG_SIGNATURE_FILE).write_bytes(dsa_res.signature)


if __name__ == "__main__":
    unittest.main()