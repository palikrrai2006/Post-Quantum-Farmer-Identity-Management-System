import argparse
import os
import sys
import time

# Ensure project root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
from preprocessing.Preprocessing import preprocess_fingerprint
from backend.sourceafis_bridge import extract_template
from verification.processor import verify_template, VerificationResult


def run_verification(image_path: str, user_id: str) -> VerificationResult:

    processed_img = f"temp_verify_{user_id}.tif"

    try:
        total_start = time.perf_counter()

        # -----------------------------
        # Preprocessing
        # -----------------------------
        t0 = time.perf_counter()

        prep_result = preprocess_fingerprint(
            image_path,
            processed_img
        )

        prep_time = prep_result["metrics"].get(
            "preprocessing_time_ms",
            0.0
        )

        # -----------------------------
        # Template Extraction
        # -----------------------------
        t0 = time.perf_counter()

        live_template = extract_template(processed_img)

        extract_time = (time.perf_counter() - t0) * 1000

        # -----------------------------
        # Verification
        # -----------------------------
        result = verify_template(
            user_id,
            live_template
        )

        total_time = (time.perf_counter() - total_start) * 1000

        # -----------------------------
        # Report
        # -----------------------------
        print("\n" + "=" * 45)
        print("POST-QUANTUM FINGERPRINT VERIFICATION")
        print("=" * 45)

        print(f"User ID        : {result.user_id}")
        print(f"Signature      : {'VALID' if result.is_signature_valid else 'INVALID'}")
        print(f"Hash           : {'VALID' if result.is_hash_valid else 'INVALID'}")
        print(f"Match Score    : {result.match_score:.2f}")
        print(f"Threshold      : {config.SOURCEAFIS_MATCH_THRESHOLD}")
        print(f"Authentication : {'SUCCESS' if result.authenticated else 'FAILED'}")

        print("\nTiming Summary")

        print(f"Preprocessing : {prep_time:.2f} ms")
        print(f"Extraction    : {extract_time:.2f} ms")
        print(f"ML-DSA Verify : {result.time_ms_dsa:.2f} ms")
        print(f"ML-KEM        : {result.time_ms_kem:.2f} ms")
        print(f"AES Decrypt   : {result.time_ms_aes:.2f} ms")
        print(f"SHA3 Verify   : {result.time_ms_hash:.2f} ms")
        print(f"SourceAFIS    : {result.time_ms_match:.2f} ms")
        print(f"TOTAL         : {total_time:.2f} ms")

        print("=" * 45)

        return result

    finally:
        if os.path.exists(processed_img):
            os.remove(processed_img)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="End-to-End PQ Fingerprint Verification"
    )

    parser.add_argument(
        "image_path",
        help="Path to fingerprint image"
    )

    parser.add_argument(
        "user_id",
        help="Registered User ID"
    )

    args = parser.parse_args()

    run_verification(
        args.image_path,
        args.user_id
    )