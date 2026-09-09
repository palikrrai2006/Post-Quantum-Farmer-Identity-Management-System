"""
experiments/benchmark_registration_flow.py

IEEE Publication-Quality Benchmarking Suite for the Post-Quantum Registration Workflow.
Executes batch trials (10, 20, 30, 40, 50) to measure scalability, latency, and throughput.

Usage:
    python -m experiments.benchmark_registration_flow
"""

import csv
import json
import logging
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List

import config
from crypto import aes_utils, hash_utils, mlkem_utils, mldsa_utils
try:
    from logging_utils import get_logger
    logger = get_logger(__name__)
except ImportError:
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    logger = logging.getLogger(__name__)

# --- Configuration ---
BATCH_SIZES = [10, 20, 30, 40, 50]

@dataclass
class TrialMetrics:
    """Stores telemetry for a single execution of the registration workflow."""
    batch_size: int
    trial_id: int
    time_sha3_hash: float = 0.0
    time_kem_keygen: float = 0.0
    time_kem_encap: float = 0.0
    time_aes_encrypt: float = 0.0
    time_dsa_keygen: float = 0.0
    time_dsa_sign: float = 0.0
    time_package_creation: float = 0.0
    time_total_registration: float = 0.0

def compute_statistics(data: List[float]) -> Dict[str, float]:
    """Computes IEEE-standard descriptive statistics for a dataset."""
    if not data:
        return {}
    
    n = len(data)
    mean_val = statistics.mean(data)
    min_val = min(data)
    max_val = max(data)
    
    if n > 1:
        median_val = statistics.median(data)
        std_dev = statistics.stdev(data)
        variance = statistics.variance(data)
    else:
        median_val = mean_val
        std_dev = 0.0
        variance = 0.0

    return {
        "Mean": mean_val,
        "Median": median_val,
        "Min": min_val,
        "Max": max_val,
        "StdDev": std_dev,
        "Variance": variance
    }

def run_single_registration(trial_id: int, batch_size: int, template_bytes: bytes) -> TrialMetrics:
    """Executes the authentic registration workflow once and captures telemetry."""
    metrics = TrialMetrics(batch_size=batch_size, trial_id=trial_id)
    t_start_total = time.perf_counter()

    # 1. SHA3-256 Hash
    t0 = time.perf_counter()
    hash_res = hash_utils.hash_template(template_bytes)
    metrics.time_sha3_hash = time.perf_counter() - t0

    # 2. ML-KEM-1024 Key Generation
    t0 = time.perf_counter()
    kem_keys = mlkem_utils.generate_keypair()
    metrics.time_kem_keygen = time.perf_counter() - t0

    # 3. ML-KEM-1024 Encapsulation (Yields AES Key)
    t0 = time.perf_counter()
    kem_encap = mlkem_utils.encapsulate_aes_key(kem_keys.public_key)
    aes_key = kem_encap.shared_secret
    metrics.time_kem_encap = time.perf_counter() - t0

    # 4. AES-256-GCM Encryption
    t0 = time.perf_counter()
    aes_res = aes_utils.encrypt_bytes(template_bytes, aes_key)
    metrics.time_aes_encrypt = time.perf_counter() - t0

    # 5. ML-DSA-87 Key Generation
    t0 = time.perf_counter()
    dsa_keys = mldsa_utils.generate_keypair()
    metrics.time_dsa_keygen = time.perf_counter() - t0

    # 6. Registration Package Creation (Metadata formatting)
    t0 = time.perf_counter()
    metadata = {
        "algo_symmetric": config.ALGO_SYMMETRIC,
        "algo_hash": config.ALGO_HASH,
        "algo_kem": config.ALGO_KEM,
        "algo_signature": config.ALGO_SIGNATURE,
        "fingerprint_hash": hash_res.digest_hex,
        "aes_nonce": aes_res.nonce.hex(),
        "aes_tag": aes_res.tag.hex()
    }
    metadata_bytes = json.dumps(metadata).encode('utf-8')
    package_payload = aes_res.ciphertext + kem_encap.kem_ciphertext + metadata_bytes
    metrics.time_package_creation = time.perf_counter() - t0

    # 7. ML-DSA-87 Signature Generation
    t0 = time.perf_counter()
    _ = mldsa_utils.sign_package(dsa_keys.secret_key, package_payload)
    metrics.time_dsa_sign = time.perf_counter() - t0

    metrics.time_total_registration = time.perf_counter() - t_start_total
    return metrics

def run_benchmarks() -> None:
    """Executes the batch runs and compiles statistics."""
    template_path = config.RAW_TEMPLATES_DIR / "101_1_test_template.txt"
    if not template_path.exists():
        logger.warning(f"Template not found at {template_path}. Generating dummy for benchmark.")
        template_path.parent.mkdir(parents=True, exist_ok=True)
        template_path.write_bytes(b"MOCK_SOURCEAFIS_MINUTIAE_DATA" * 50)
    
    template_bytes = template_path.read_bytes()
    
    all_trials: List[TrialMetrics] = []
    batch_summaries: List[Dict[str, Any]] = []
    detailed_statistics: Dict[str, Any] = {}

    for size in BATCH_SIZES:
        logger.info(f"Running benchmark batch size: {size}")
        batch_trials = []
        
        t_batch_start = time.perf_counter()
        for i in range(1, size + 1):
            metrics = run_single_registration(trial_id=i, batch_size=size, template_bytes=template_bytes)
            batch_trials.append(metrics)
            all_trials.append(metrics)
        t_batch_total = time.perf_counter() - t_batch_start

        # Calculate statistics for this specific batch
        metrics_map = {
            "SHA3 Hash": [t.time_sha3_hash for t in batch_trials],
            "KEM KeyGen": [t.time_kem_keygen for t in batch_trials],
            "KEM Encap": [t.time_kem_encap for t in batch_trials],
            "AES Encrypt": [t.time_aes_encrypt for t in batch_trials],
            "DSA KeyGen": [t.time_dsa_keygen for t in batch_trials],
            "DSA Sign": [t.time_dsa_sign for t in batch_trials],
            "Package Creation": [t.time_package_creation for t in batch_trials],
            "Total Time": [t.time_total_registration for t in batch_trials],
        }

        batch_stats = {}
        for step, data in metrics_map.items():
            batch_stats[step] = compute_statistics(data)
            
        detailed_statistics[f"Batch_{size}"] = batch_stats

        batch_summaries.append({
            "Batch_Size": size,
            "Total_Time_Seconds": t_batch_total,
            "Average_Time_Per_Template": t_batch_total / size,
            "Throughput_Templates_Per_Second": size / t_batch_total
        })

    export_results(all_trials, detailed_statistics, batch_summaries)

def export_results(
    all_trials: List[TrialMetrics], 
    detailed_statistics: Dict[str, Any], 
    batch_summaries: List[Dict[str, Any]]
) -> None:
    """Writes the compiled data to IEEE-ready CSV and JSON files."""
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. registration_trials.csv
    trials_csv = config.RESULTS_DIR / "registration_trials.csv"
    with open(trials_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=asdict(all_trials[0]).keys())
        writer.writeheader()
        for t in all_trials:
            writer.writerow(asdict(t))

    # 2. registration_statistics.csv (Flattened for tabular viewing)
    stats_csv = config.RESULTS_DIR / "registration_statistics.csv"
    with open(stats_csv, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ["Batch_Size", "Step", "Mean", "Median", "Min", "Max", "StdDev", "Variance"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for batch_key, steps in detailed_statistics.items():
            batch_size = batch_key.split("_")[1]
            for step, stats in steps.items():
                row = {"Batch_Size": batch_size, "Step": step}
                row.update(stats)
                writer.writerow(row)

    # 3. registration_batch_summary.csv
    batch_csv = config.RESULTS_DIR / "registration_batch_summary.csv"
    with open(batch_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=batch_summaries[0].keys())
        writer.writeheader()
        writer.writerows(batch_summaries)

    # 4. registration_summary.json (Contains all data structures natively)
    summary_json = config.RESULTS_DIR / "registration_summary.json"
    full_summary = {
        "Batch_Summaries": batch_summaries,
        "Detailed_Statistics": detailed_statistics
    }
    with open(summary_json, 'w', encoding='utf-8') as f:
        json.dump(full_summary, f, indent=4)

    logger.info(f"Benchmarking complete. Files saved to {config.RESULTS_DIR}")

if __name__ == "__main__":
    run_benchmarks()