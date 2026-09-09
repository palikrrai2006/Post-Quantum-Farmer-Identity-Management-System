"""
registration/batch_register.py

Batch End-to-End Registration
"""

import csv
import time
from pathlib import Path

from e2e_reg import run_registration
from blockchain.web3_utils import BlockchainManager

# =====================================================
# CONFIGURATION
# =====================================================

DATASET_DIR = Path("dataset\SOCOFing\Real")

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

RESULTS_FILE = RESULTS_DIR / "registration_results.csv"

CHECK_BLOCKCHAIN = True

# =====================================================


def batch_register():

    bm = BlockchainManager()

    images = sorted(DATASET_DIR.glob("*.BMP"))

    processed_users = set()

    csv_rows = []

    success = 0
    failed = 0
    skipped = 0

    batch_start = time.perf_counter()

    print("\n")
    print("=" * 60)
    print("POST-QUANTUM BATCH REGISTRATION")
    print("=" * 60)
    print(f"Dataset : {DATASET_DIR}")
    print(f"Images  : {len(images)}")
    print("=" * 60)

    for index, image_path in enumerate(images, start=1):

        user_id = image_path.stem.split("_")[0]

        # -----------------------------------------
        # Register only first fingerprint per user
        # -----------------------------------------

        if user_id in processed_users:
            continue

        processed_users.add(user_id)

        # -----------------------------------------
        # Blockchain duplicate check
        # -----------------------------------------

        if CHECK_BLOCKCHAIN:

            try:
                cid = bm.get_cid(user_id)

                if cid:
                    print(f"[{index}/{len(images)}] {user_id} already registered")

                    skipped += 1

                    continue

            except Exception:
                pass

        print(f"[{index}/{len(images)}] Registering {user_id} ({image_path.name})")

        try:

            result = run_registration(str(image_path), user_id)

            if result is None:
                raise RuntimeError("run_registration() returned None")

            csv_rows.append({

                "user_id": user_id,

                "image": image_path.name,

                "cid": result.cid,

                "preprocessing_ms": result.time_ms_prep,

                "template_ms": result.time_ms_extract,

                "hash_ms": result.time_ms_hash,

                "kem_ms": result.time_ms_kem,

                "aes_ms": result.time_ms_aes,

                "dsa_ms": result.time_ms_dsa,

                "ipfs_ms": result.time_ms_upload,

                "blockchain_ms": result.time_ms_blockchain,

                "total_ms": result.time_ms_total,

                "status": "SUCCESS"

            })

            success += 1

        except Exception as e:

            print(f"FAILED : {user_id}")

            print(e)

            csv_rows.append({

                "user_id": user_id,

                "image": image_path.name,

                "cid": "",

                "preprocessing_ms": "",

                "template_ms": "",

                "hash_ms": "",

                "kem_ms": "",

                "aes_ms": "",

                "dsa_ms": "",

                "ipfs_ms": "",

                "blockchain_ms": "",

                "total_ms": "",

                "status": f"FAILED : {e}"

            })

            failed += 1

    # =====================================================
    # Save CSV
    # =====================================================

    headers = [

        "user_id",

        "image",

        "cid",

        "preprocessing_ms",

        "template_ms",

        "hash_ms",

        "kem_ms",

        "aes_ms",

        "dsa_ms",

        "ipfs_ms",

        "blockchain_ms",

        "total_ms",

        "status"

    ]

    with open(RESULTS_FILE, "w", newline="") as file:

        writer = csv.DictWriter(file, fieldnames=headers)

        writer.writeheader()

        writer.writerows(csv_rows)

    # =====================================================
    # Statistics
    # =====================================================

    batch_time = time.perf_counter() - batch_start

    successful = [

        row["total_ms"]

        for row in csv_rows

        if row["status"] == "SUCCESS"

    ]

    if successful:

        average = sum(successful) / len(successful)

    else:

        average = 0

    throughput = success / batch_time if batch_time > 0 else 0

    print("\n")
    print("=" * 60)
    print("BATCH REGISTRATION FINISHED")
    print("=" * 60)
    print(f"Successful : {success}")
    print(f"Failed     : {failed}")
    print(f"Skipped    : {skipped}")
    print(f"Average    : {average:.2f} ms")
    print(f"Throughput : {throughput:.2f} registrations/sec")
    print(f"CSV Saved  : {RESULTS_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    batch_register()