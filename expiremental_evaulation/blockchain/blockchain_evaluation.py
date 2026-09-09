import csv
import json
import time
from pathlib import Path

import config
from blockchain.web3_utils import BlockchainManager

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

CSV_FILE = RESULTS_DIR / "blockchain_results.csv"
SUMMARY_FILE = RESULTS_DIR / "blockchain_summary.json"


def blockchain_evaluation():

    bm = BlockchainManager()

    package_root = Path(config.PACKAGES_DIR)

    # ---------------------------------------------------
    # Only registered user folders (101,102,...)
    # Ignore verify_xxx, temp, downloads, etc.
    # ---------------------------------------------------
    users = sorted(
        [
            d.name
            for d in package_root.iterdir()
            if d.is_dir() and d.name.isdigit()
        ]
    )

    rows = []

    retrieval_times = []

    success = 0
    failed = 0

    batch_start = time.perf_counter()

    print("=" * 60)
    print("BLOCKCHAIN PERFORMANCE EVALUATION")
    print("=" * 60)

    for idx, user in enumerate(users, start=1):

        try:

            t0 = time.perf_counter()

            cid = bm.get_cid(user)

            retrieval_ms = (time.perf_counter() - t0) * 1000

            retrieval_times.append(retrieval_ms)

            rows.append(
                {
                    "user_id": user,
                    "cid": cid,
                    "retrieval_time_ms": round(retrieval_ms, 4),
                    "status": "SUCCESS",
                }
            )

            success += 1

            print(
                f"[{idx}/{len(users)}] "
                f"User {user:<5} "
                f"{retrieval_ms:8.2f} ms"
            )

        except Exception as e:

            failed += 1

            rows.append(
                {
                    "user_id": user,
                    "cid": "",
                    "retrieval_time_ms": "",
                    "status": str(e),
                }
            )

            print(f"[FAILED] {user}: {e}")

    batch_time = time.perf_counter() - batch_start

    avg_retrieval = (
        sum(retrieval_times) / len(retrieval_times)
        if retrieval_times else 0
    )

    throughput = (
        success / batch_time
        if batch_time > 0 else 0
    )

    summary = {

        "Registered_Users": len(users),

        "Users_Evaluated": success,

        "Failed": failed,

        "Average_Retrieval_Time_ms": avg_retrieval,

        "Minimum_Retrieval_Time_ms":
            min(retrieval_times) if retrieval_times else 0,

        "Maximum_Retrieval_Time_ms":
            max(retrieval_times) if retrieval_times else 0,

        "Success_Rate_percent":
            (success / len(users) * 100)
            if users else 0,

        "Execution_Time_sec": batch_time,

        "Throughput_requests_per_sec": throughput

    }

    # ---------------- CSV ----------------

    with open(CSV_FILE, "w", newline="") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "user_id",
                "cid",
                "retrieval_time_ms",
                "status",
            ],
        )

        writer.writeheader()

        writer.writerows(rows)

    # ---------------- JSON ----------------

    with open(SUMMARY_FILE, "w") as f:

        json.dump(summary, f, indent=4)

    # ---------------- Console ----------------

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    for key, value in summary.items():

        if isinstance(value, float):

            print(f"{key:30}: {value:.2f}")

        else:

            print(f"{key:30}: {value}")

    print("=" * 60)

    print(f"\nCSV Saved  : {CSV_FILE}")
    print(f"JSON Saved : {SUMMARY_FILE}")


if __name__ == "__main__":
    blockchain_evaluation()