import argparse
import sys
import os
import time
import logging

# Ensure project root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from preprocessing.Preprocessing import preprocess_fingerprint
from backend.sourceafis_bridge import extract_template
from registration.processor import register_template

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("E2ERegistration")


def run_registration(image_path, user_id):

    print("\n" + "=" * 42)
    print("POST-QUANTUM FINGERPRINT REGISTRATION")
    print("=" * 42 + "\n")

    processed_img_path = f"temp_{user_id}_proc.tif"

    try:

        # ==================================================
        # 1. PREPROCESSING
        # ==================================================

        print("Loading and Preprocessing fingerprint image...")

        prep_result = preprocess_fingerprint(
            image_path,
            processed_img_path
        )

        prep_time = prep_result["metrics"].get(
            "preprocessing_time_ms",
            0.0
        )

        print(f"✓ Completed in {prep_time:.4f} ms")

        # ==================================================
        # 2. TEMPLATE EXTRACTION
        # ==================================================

        print("\nExtracting SourceAFIS template...")

        t0 = time.perf_counter()

        template_bytes = extract_template(processed_img_path)

        extract_time = (
            time.perf_counter() - t0
        ) * 1000

        print(f"✓ Template extracted in {extract_time:.4f} ms")

        # ==================================================
        # 3. CRYPTOGRAPHIC WORKFLOW
        # ==================================================

        print("\nRunning Cryptographic Workflow...")

        result = register_template(
            user_id=user_id,
            template_bytes=template_bytes,
            prep_time=prep_time,
            extract_time=extract_time
        )

        print("✓ Completed")

        # ==================================================
        # 4. FINAL OUTPUT
        # ==================================================

        print("\n" + "=" * 42)
        print("REGISTRATION SUCCESSFUL")
        print("=" * 42)

        print(f"User ID    : {result.user_id}")
        print(f"CID        : {result.cid}")
        print(f"TX Hash    : {result.tx_hash}")

        print("\nTiming Summary")

        print(f"Preprocessing : {result.time_ms_prep:.2f} ms")
        print(f"Extraction    : {result.time_ms_extract:.2f} ms")
        print(f"SHA3          : {result.time_ms_hash:.2f} ms")
        print(f"ML-KEM        : {result.time_ms_kem:.2f} ms")
        print(f"AES           : {result.time_ms_aes:.2f} ms")
        print(f"ML-DSA        : {result.time_ms_dsa:.2f} ms")
        print(f"IPFS          : {result.time_ms_upload:.2f} ms")
        print(f"Blockchain    : {result.time_ms_blockchain:.2f} ms")
        print(f"TOTAL         : {result.time_ms_total:.2f} ms")

        return result

    except Exception as e:

        logger.error(f"Registration failed: {e}")

        raise

    finally:

        if os.path.exists(processed_img_path):
            os.remove(processed_img_path)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="End-to-End PQ Fingerprint Registration"
    )

    parser.add_argument(
        "image_path",
        help="Path to fingerprint image"
    )

    parser.add_argument(
        "user_id",
        help="User Identifier"
    )

    args = parser.parse_args()

    run_registration(
        args.image_path,
        args.user_id
    )