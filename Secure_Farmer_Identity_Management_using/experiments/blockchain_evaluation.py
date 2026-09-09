"""
experiments/blockchain_evaluation.py
======================================
Measures REAL blockchain (Ganache) storage/retrieval performance for
config.BLOCKCHAIN_EXPERIMENT_SIZES. Every timing/tx value comes from an
actual call to blockchain/blockchain_utils.py against a running Ganache
instance with the FarmerIdentity contract deployed — nothing simulated.

Run:
    python -m experiments.blockchain_evaluation
"""

import csv
import os
import hashlib

import config
from blockchain import blockchain_utils


def run_experiment(n: int):
    storage_times, retrieval_times = [], []
    successes = 0

    for i in range(n):
        farmer_id = f"LOADTEST{i:05d}"
        finger_position = "RIGHT_THUMB"
        cid = f"bafy_loadtest_{i}"  # placeholder CID string for load-test purposes only
        integrity_hash = hashlib.sha3_256(f"loadtest-{i}".encode()).hexdigest()

        try:
            store_result = blockchain_utils.store_fingerprint_record(farmer_id, finger_position, cid, integrity_hash)
            storage_times.append(store_result["storage_time_ns"])

            retrieval = blockchain_utils.retrieve_fingerprint_record(farmer_id, finger_position)
            retrieval_times.append(retrieval["retrieval_time_ns"])
            successes += 1
        except blockchain_utils.BlockchainUnavailableError as e:
            return {"error": str(e), "n": n}

    total_time_ns = sum(storage_times) + sum(retrieval_times)
    return {
        "n": n,
        "users_evaluated": successes,
        "avg_storage_time_ns": sum(storage_times) / len(storage_times) if storage_times else 0,
        "avg_retrieval_time_ns": sum(retrieval_times) / len(retrieval_times) if retrieval_times else 0,
        "execution_time_ns": total_time_ns,
        "throughput_ops_per_sec": (2 * successes) / (total_time_ns / 1e9) if total_time_ns else 0,
        "success_rate": successes / n if n else 0,
    }


def run_all(sizes=None):
    sizes = sizes or config.BLOCKCHAIN_EXPERIMENT_SIZES
    results = []
    for n in sizes:
        print(f"Running blockchain experiment for n={n}...")
        r = run_experiment(n)
        results.append(r)
        print(" ", r)
        if "error" in r:
            print("Stopping further sizes — blockchain unavailable.")
            break

    out_path = os.path.join(config.RESULTS_TABLES_DIR, "blockchain_results.csv")
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["n", "users_evaluated", "avg_storage_time_ns", "avg_retrieval_time_ns",
                          "execution_time_ns", "throughput_ops_per_sec", "success_rate", "error"])
        for r in results:
            if "error" in r:
                writer.writerow([r["n"], "", "", "", "", "", "", r["error"]])
            else:
                writer.writerow([r["n"], r["users_evaluated"], r["avg_storage_time_ns"],
                                  r["avg_retrieval_time_ns"], r["execution_time_ns"],
                                  r["throughput_ops_per_sec"], r["success_rate"], ""])
    print(f"Wrote {out_path}")
    return results


if __name__ == "__main__":
    run_all()
