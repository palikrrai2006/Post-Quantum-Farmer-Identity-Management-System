"""
registration/batch_register_socofing.py

Batch End-to-End Registration for SOCOFing Dataset

Registers each REAL fingerprint as a unique biometric identity.

Example SOCOFing filename:
1__M_Left_index_finger.BMP

Registration ID:
1__M_Left_index_finger

This prevents different fingers of the same subject from overwriting
each other on the blockchain.
"""

import csv
import time
from pathlib import Path

from registration.e2e_reg import run_registration
from blockchain.web3_utils import BlockchainManager


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_DIR = Path("dataset/SOCOFing/Real")

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

RESULTS_FILE = RESULTS_DIR / "socofing_registration_results.csv"

# Check blockchain before registration
CHECK_BLOCKCHAIN = True

# Set to None to register all 6000 fingerprints
# For testing, use 10 or 100
MAX_FINGERPRINTS = None


# ============================================================
# BATCH REGISTRATION
# ============================================================

def batch_register():

    print("\nInitializing blockchain connection...")

    bm = BlockchainManager()

    # SOCOFing files may use BMP or bmp
    images = sorted(
        list(DATASET_DIR.glob("*.BMP")) +
        list(DATASET_DIR.glob("*.bmp"))
    )

    # Remove possible duplicates
    images = list(dict.fromkeys(images))

    if MAX_FINGERPRINTS is not None:
        images = images[:MAX_FINGERPRINTS]

    print("\n")
    print("=" * 70)
    print("SOCOFING POST-QUANTUM BATCH REGISTRATION")
    print("=" * 70)
    print(f"Dataset Path       : {DATASET_DIR}")
    print(f"Fingerprints Found : {len(images)}")
    print(f"Blockchain Check   : {CHECK_BLOCKCHAIN}")
    print("=" * 70)

    if not images:
        print("\nERROR: No SOCOFing fingerprint images found.")
        print(f"Check dataset path: {DATASET_DIR.resolve()}")
        return

    csv_rows = []

    success = 0
    failed = 0
    skipped = 0

    batch_start = time.perf_counter()


    # ========================================================
    # PROCESS EVERY FINGERPRINT
    # ========================================================

    for index, image_path in enumerate(images, start=1):

        # ----------------------------------------------------
        # IMPORTANT:
        # Use full filename stem as registration ID.
        #
        # Example:
        # 1__M_Left_index_finger.BMP
        #
        # registration_id:
        # 1__M_Left_index_finger
        # ----------------------------------------------------

        registration_id = image_path.stem

        # Subject ID is first part
        subject_id = image_path.stem.split("__")[0]

        print(
            f"\n[{index}/{len(images)}] "
            f"Subject={subject_id} "
            f"Fingerprint={registration_id}"
        )


        # ====================================================
        # BLOCKCHAIN DUPLICATE CHECK
        # ====================================================

        if CHECK_BLOCKCHAIN:

            try:

                existing_cid = bm.get_cid(registration_id)

                if existing_cid:

                    print(
                        f"SKIPPED: {registration_id} "
                        f"already registered"
                    )

                    skipped += 1

                    csv_rows.append({

                        "subject_id": subject_id,
                        "registration_id": registration_id,
                        "image": image_path.name,

                        "cid": existing_cid,

                        "preprocessing_ms": "",
                        "template_ms": "",
                        "hash_ms": "",
                        "kem_ms": "",
                        "aes_ms": "",
                        "dsa_ms": "",
                        "ipfs_ms": "",
                        "blockchain_ms": "",
                        "total_ms": "",

                        "status": "SKIPPED_ALREADY_REGISTERED"

                    })

                    continue

            except Exception:

                # get_cid() throws an exception if user
                # does not exist in the smart contract.
                # In that case, continue registration.

                pass


        # ====================================================
        # REGISTRATION
        # ====================================================

        try:

            result = run_registration(
                str(image_path),
                registration_id
            )

            if result is None:

                raise RuntimeError(
                    "run_registration() returned None"
                )


            csv_rows.append({

                "subject_id":
                    subject_id,

                "registration_id":
                    registration_id,

                "image":
                    image_path.name,

                "cid":
                    result.cid,

                "preprocessing_ms":
                    result.time_ms_prep,

                "template_ms":
                    result.time_ms_extract,

                "hash_ms":
                    result.time_ms_hash,

                "kem_ms":
                    result.time_ms_kem,

                "aes_ms":
                    result.time_ms_aes,

                "dsa_ms":
                    result.time_ms_dsa,

                "ipfs_ms":
                    result.time_ms_upload,

                "blockchain_ms":
                    result.time_ms_blockchain,

                "total_ms":
                    result.time_ms_total,

                "status":
                    "SUCCESS"

            })


            success += 1

            print(
                f"SUCCESS: {registration_id}"
            )


        except Exception as e:

            print(
                f"FAILED: {registration_id}"
            )

            print(
                f"ERROR: {e}"
            )


            csv_rows.append({

                "subject_id":
                    subject_id,

                "registration_id":
                    registration_id,

                "image":
                    image_path.name,

                "cid":
                    "",

                "preprocessing_ms":
                    "",

                "template_ms":
                    "",

                "hash_ms":
                    "",

                "kem_ms":
                    "",

                "aes_ms":
                    "",

                "dsa_ms":
                    "",

                "ipfs_ms":
                    "",

                "blockchain_ms":
                    "",

                "total_ms":
                    "",

                "status":
                    f"FAILED: {e}"

            })


            failed += 1


    # ========================================================
    # SAVE CSV
    # ========================================================

    headers = [

        "subject_id",

        "registration_id",

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


    with open(
        RESULTS_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=headers
        )

        writer.writeheader()

        writer.writerows(
            csv_rows
        )


    # ========================================================
    # FINAL STATISTICS
    # ========================================================

    batch_time = (
        time.perf_counter()
        -
        batch_start
    )


    successful_times = [

        float(row["total_ms"])

        for row in csv_rows

        if (
            row["status"] == "SUCCESS"
            and row["total_ms"] != ""
        )

    ]


    if successful_times:

        average_time = (
            sum(successful_times)
            /
            len(successful_times)
        )

    else:

        average_time = 0


    throughput = (

        success / batch_time

        if batch_time > 0

        else 0

    )


    # ========================================================
    # SUMMARY
    # ========================================================

    print("\n")
    print("=" * 70)
    print("SOCOFING BATCH REGISTRATION FINISHED")
    print("=" * 70)

    print(
        f"Total Fingerprints : {len(images)}"
    )

    print(
        f"Successful         : {success}"
    )

    print(
        f"Failed             : {failed}"
    )

    print(
        f"Skipped            : {skipped}"
    )

    print(
        f"Average Time       : {average_time:.2f} ms"
    )

    print(
        f"Execution Time     : {batch_time:.2f} sec"
    )

    print(
        f"Throughput         : {throughput:.2f} registrations/sec"
    )

    print(
        f"CSV Saved          : {RESULTS_FILE}"
    )

    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    batch_register()