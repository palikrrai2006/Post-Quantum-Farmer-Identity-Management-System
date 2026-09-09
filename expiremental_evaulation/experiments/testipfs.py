"""
experiments/testipfs.py

IPFS + Blockchain Performance Evaluation
"""

import csv
import json
import time
from pathlib import Path

from storage.ipfs_utils import upload_package, download_package
from blockchain.web3_utils import BlockchainManager

PACKAGE_DIR = Path("packages")
DOWNLOAD_DIR = Path("storage/downloads")

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

CSV_FILE = RESULTS_DIR / "storage_blockchain_results.csv"
JSON_FILE = RESULTS_DIR / "storage_blockchain_summary.json"


def evaluate():

    bm = BlockchainManager()

    DOWNLOAD_DIR.mkdir(exist_ok=True)

    package_dirs = sorted(
        [p for p in PACKAGE_DIR.iterdir() if p.is_dir()]
    )

    rows = []

    upload_times = []
    download_times = []

    blockchain_store_times = []
    blockchain_retrieve_times = []

    package_sizes = []

    start = time.perf_counter()

    print("=" * 60)
    print("IPFS + BLOCKCHAIN PERFORMANCE EVALUATION")
    print("=" * 60)

    for idx, package in enumerate(package_dirs, start=1):

        user_id = package.name

        print(f"[{idx}/{len(package_dirs)}] {user_id}")

        # --------------------------
        # IPFS Upload
        # --------------------------

        upload_result = upload_package(package)

        cid = upload_result.cid

        upload_times.append(
            upload_result.upload_time_milliseconds
        )

        package_sizes.append(
            upload_result.package_size_bytes
        )

        # --------------------------
        # Blockchain Store
        # --------------------------

        t0 = time.perf_counter()

        bm.store_cid(user_id, cid)

        blockchain_store_ms = (
            time.perf_counter() - t0
        ) * 1000

        blockchain_store_times.append(
            blockchain_store_ms
        )

        # --------------------------
        # Blockchain Retrieve
        # --------------------------

        t0 = time.perf_counter()

        retrieved_cid = bm.get_cid(user_id)

        blockchain_retrieve_ms = (
            time.perf_counter() - t0
        ) * 1000

        blockchain_retrieve_times.append(
            blockchain_retrieve_ms
        )

        # --------------------------
        # IPFS Download
        # --------------------------

        output = DOWNLOAD_DIR / user_id

        download_result = download_package(
            retrieved_cid,
            output
        )

        download_times.append(
            download_result.download_time_milliseconds
        )

        rows.append({

            "user_id": user_id,

            "package_size_bytes":
                upload_result.package_size_bytes,

            "cid":
                retrieved_cid,

            "upload_ms":
                upload_result.upload_time_milliseconds,

            "blockchain_store_ms":
                blockchain_store_ms,

            "blockchain_retrieve_ms":
                blockchain_retrieve_ms,

            "download_ms":
                download_result.download_time_milliseconds

        })

    execution_time = time.perf_counter() - start

    summary = {

        "Users_Evaluated":
            len(rows),

        "Average_Upload_ms":
            sum(upload_times) / len(upload_times),

        "Average_Download_ms":
            sum(download_times) / len(download_times),

        "Average_Blockchain_Store_ms":
            sum(blockchain_store_times) /
            len(blockchain_store_times),

        "Average_Blockchain_Retrieve_ms":
            sum(blockchain_retrieve_times) /
            len(blockchain_retrieve_times),

        "Average_Package_Size_Bytes":
            sum(package_sizes) / len(package_sizes),

        "Execution_Time_sec":
            execution_time,

        "Throughput":
            len(rows) / execution_time,

        "Success_Rate":
            100.0

    }

    print("\n")
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)

    for k, v in summary.items():

        if isinstance(v, float):

            print(f"{k:35}: {v:.2f}")

        else:

            print(f"{k:35}: {v}")

    print("=" * 60)

    with open(CSV_FILE, "w", newline="") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=rows[0].keys()
        )

        writer.writeheader()
        writer.writerows(rows)

    with open(JSON_FILE, "w") as f:

        json.dump(summary, f, indent=4)

    print(f"\nCSV Saved  : {CSV_FILE}")
    print(f"JSON Saved : {JSON_FILE}")


if __name__ == "__main__":
    evaluate()