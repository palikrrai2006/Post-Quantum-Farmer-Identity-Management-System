"""
experiments/benchmark_registration_flow.py

IEEE Publication-Quality Benchmarking Suite for the Post-Quantum Registration Workflow.
Executes batch trials strictly using real SourceAFIS template data and physical file I/O.
Measures latency in milliseconds (ms) and storage overhead in bytes.
Outputs standard CSV/JSON datasets and generates a terminal summary table.

Usage:
    python -m experiments.benchmark_registration_flow
"""

import csv
import json
import logging
import statistics
import time
import shutil
from dataclasses import asdict, dataclass
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
BENCHMARK_PKG_DIR = config.PACKAGES_DIR / "benchmark_tmp_pkg"

@dataclass
class TrialMetrics:
    """Stores telemetry for a single execution of the registration workflow."""
    batch_size: int
    trial_id: int
    
    # Latency Metrics (Milliseconds)
    time_ms_sha3_hash: float = 0.0
    time_ms_kem_keygen: float = 0.0
    time_ms_kem_encap: float = 0.0
    time_ms_aes_encrypt: float = 0.0
    time_ms_dsa_keygen: float = 0.0
    time_ms_dsa_sign: float = 0.0
    time_ms_package_creation: float = 0.0
    time_ms_total_registration: float = 0.0
    
    # Storage Metrics (Bytes)
    size_bytes_template_enc: int = 0
    size_bytes_kem_ciphertext: int = 0
    size_bytes_signature: int = 0
    size_bytes_metadata: int = 0
    size_bytes_total_package: int = 0


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
    """Executes the authentic registration workflow with actual file I/O."""
    metrics = TrialMetrics(batch_size=batch_size, trial_id=trial_id)
    t_start_total = time.perf_counter()

    # 1. SHA3-256 Hash
    t0 = time.perf_counter()
    hash_res = hash_utils.hash_template(template_bytes)
    metrics.time_ms_sha3_hash = (time.perf_counter() - t0) * 1000

    # 2. ML-KEM-1024 Key Generation
    t0 = time.perf_counter()
    kem_keys = mlkem_utils.generate_keypair()
    metrics.time_ms_kem_keygen = (time.perf_counter() - t0) * 1000

    # 3. ML-KEM-1024 Encapsulation (Yields AES Key)
    t0 = time.perf_counter()
    kem_encap = mlkem_utils.encapsulate_aes_key(kem_keys.public_key)
    aes_key = kem_encap.shared_secret
    metrics.time_ms_kem_encap = (time.perf_counter() - t0) * 1000
    metrics.size_bytes_kem_ciphertext = len(kem_encap.kem_ciphertext)

    # 4. AES-256-GCM Encryption
    t0 = time.perf_counter()
    aes_res = aes_utils.encrypt_bytes(template_bytes, aes_key)
    metrics.time_ms_aes_encrypt = (time.perf_counter() - t0) * 1000
    metrics.size_bytes_template_enc = len(aes_res.nonce) + len(aes_res.tag) + len(aes_res.ciphertext)

    # 5. ML-DSA-87 Key Generation
    t0 = time.perf_counter()
    dsa_keys = mldsa_utils.generate_keypair()
    metrics.time_ms_dsa_keygen = (time.perf_counter() - t0) * 1000

    # 6. Metadata Formatting & Signature Generation
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
    metrics.size_bytes_metadata = len(metadata_bytes)

    package_payload = aes_res.ciphertext + kem_encap.kem_ciphertext + metadata_bytes
    
    t0 = time.perf_counter()
    dsa_res = mldsa_utils.sign_package(dsa_keys.secret_key, package_payload)
    metrics.time_ms_dsa_sign = (time.perf_counter() - t0) * 1000
    metrics.size_bytes_signature = len(dsa_res.signature)

    # 7. Physical Package Creation (File I/O)
    t0 = time.perf_counter()
    if BENCHMARK_PKG_DIR.exists():
        shutil.rmtree(BENCHMARK_PKG_DIR)
    BENCHMARK_PKG_DIR.mkdir(parents=True)
    
    (BENCHMARK_PKG_DIR / config.PKG_TEMPLATE_FILE).write_bytes(aes_res.ciphertext)
    (BENCHMARK_PKG_DIR / config.PKG_KEY_FILE).write_bytes(kem_encap.kem_ciphertext)
    (BENCHMARK_PKG_DIR / config.PKG_METADATA_FILE).write_bytes(metadata_bytes)
    (BENCHMARK_PKG_DIR / config.PKG_SIGNATURE_FILE).write_bytes(dsa_res.signature)
    metrics.time_ms_package_creation = (time.perf_counter() - t0) * 1000

    metrics.size_bytes_total_package = (
        metrics.size_bytes_template_enc +
        metrics.size_bytes_kem_ciphertext +
        metrics.size_bytes_signature +
        metrics.size_bytes_metadata
    )

    metrics.time_ms_total_registration = (time.perf_counter() - t_start_total) * 1000
    return metrics


def run_benchmarks() -> None:
    """Executes the batch runs and compiles statistics."""
    template_path = config.RAW_TEMPLATES_DIR / "101_1_test_template.txt"
    
    if not template_path.exists():
        raise FileNotFoundError(
            f"CRITICAL: Real SourceAFIS template not found at {template_path}. "
            "Academic benchmarks require empirical data. Ensure preprocessing is complete."
        )
    
    template_bytes = template_path.read_bytes()
    
    all_trials: List[TrialMetrics] = []
    batch_summaries: List[Dict[str, Any]] = []
    detailed_statistics: Dict[str, Any] = {}
    size_statistics: Dict[str, Any] = {}

    for size in BATCH_SIZES:
        logger.info(f"Running benchmark batch size: {size}")
        batch_trials = []
        
        t_batch_start = time.perf_counter()
        for i in range(1, size + 1):
            metrics = run_single_registration(trial_id=i, batch_size=size, template_bytes=template_bytes)
            batch_trials.append(metrics)
            all_trials.append(metrics)
        t_batch_total_seconds = time.perf_counter() - t_batch_start

        # Calculate Latency Statistics
        metrics_map = {
            "SHA3 Hash (ms)": [t.time_ms_sha3_hash for t in batch_trials],
            "KEM KeyGen (ms)": [t.time_ms_kem_keygen for t in batch_trials],
            "KEM Encap (ms)": [t.time_ms_kem_encap for t in batch_trials],
            "AES Encrypt (ms)": [t.time_ms_aes_encrypt for t in batch_trials],
            "DSA KeyGen (ms)": [t.time_ms_dsa_keygen for t in batch_trials],
            "DSA Sign (ms)": [t.time_ms_dsa_sign for t in batch_trials],
            "Package Creation I/O (ms)": [t.time_ms_package_creation for t in batch_trials],
            "Total Time (ms)": [t.time_ms_total_registration for t in batch_trials],
        }

        # Calculate Storage Statistics
        size_map = {
            "Encrypted Template (Bytes)": [t.size_bytes_template_enc for t in batch_trials],
            "KEM Ciphertext (Bytes)": [t.size_bytes_kem_ciphertext for t in batch_trials],
            "DSA Signature (Bytes)": [t.size_bytes_signature for t in batch_trials],
            "Metadata (Bytes)": [t.size_bytes_metadata for t in batch_trials],
            "Total Package (Bytes)": [t.size_bytes_total_package for t in batch_trials],
        }

        batch_stats = {step: compute_statistics(data) for step, data in metrics_map.items()}
        batch_sizes = {comp: compute_statistics(data) for comp, data in size_map.items()}
            
        detailed_statistics[f"Batch_{size}"] = batch_stats
        size_statistics[f"Batch_{size}"] = batch_sizes

        batch_summaries.append({
            "Batch_Size": size,
            "Total_Time_Seconds": t_batch_total_seconds,
            "Average_Time_Per_Template_ms": (t_batch_total_seconds / size) * 1000,
            "Throughput_Templates_Per_Second": size / t_batch_total_seconds
        })

    # Cleanup temporary benchmark directory
    if BENCHMARK_PKG_DIR.exists():
        shutil.rmtree(BENCHMARK_PKG_DIR)

    export_results(all_trials, detailed_statistics, size_statistics, batch_summaries)


def export_results(
    all_trials: List[TrialMetrics], 
    detailed_statistics: Dict[str, Any], 
    size_statistics: Dict[str, Any],
    batch_summaries: List[Dict[str, Any]]
) -> None:
    """Writes the compiled data to IEEE-ready CSV and JSON files and prints a summary table."""
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. registration_trials.csv
    trials_csv = config.RESULTS_DIR / "registration_trials.csv"
    with open(trials_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=asdict(all_trials[0]).keys())
        writer.writeheader()
        for t in all_trials:
            writer.writerow(asdict(t))

    # 2. registration_statistics.csv
    stats_csv = config.RESULTS_DIR / "registration_statistics.csv"
    with open(stats_csv, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ["Batch_Size", "Metric", "Mean", "Median", "Min", "Max", "StdDev", "Variance"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for batch_key, steps in detailed_statistics.items():
            batch_size = batch_key.split("_")[1]
            for step, stats in steps.items():
                row = {"Batch_Size": batch_size, "Metric": step}
                row.update(stats)
                writer.writerow(row)
                
        for batch_key, comps in size_statistics.items():
            batch_size = batch_key.split("_")[1]
            for comp, stats in comps.items():
                row = {"Batch_Size": batch_size, "Metric": comp}
                row.update(stats)
                writer.writerow(row)

    # 3. registration_batch_summary.csv
    batch_csv = config.RESULTS_DIR / "registration_batch_summary.csv"
    with open(batch_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=batch_summaries[0].keys())
        writer.writeheader()
        writer.writerows(batch_summaries)

    # 4. registration_summary.json
    summary_json = config.RESULTS_DIR / "registration_summary.json"
    full_summary = {
        "Batch_Summaries": batch_summaries,
        "Latency_Statistics": detailed_statistics,
        "Storage_Statistics": size_statistics
    }
    with open(summary_json, 'w', encoding='utf-8') as f:
        json.dump(full_summary, f, indent=4)

    logger.info(f"Files saved to {config.RESULTS_DIR}")

    # =========================================================================
    # TERMINAL OUTPUT: IEEE-Style Summary Tables
    # =========================================================================
    
    print("\n" + "="*85)
    print(f"{'IEEE Post-Quantum Registration Benchmark - Scalability Summary':^85}")
    print("="*85)
    print(f"{'Batch Size':<12} | {'Total Time (s)':<18} | {'Avg Time/Template (ms)':<25} | {'Throughput (req/s)':<20}")
    print("-" * 85)
    for summary in batch_summaries:
        print(f"{summary['Batch_Size']:<12} | "
              f"{summary['Total_Time_Seconds']:<18.4f} | "
              f"{summary['Average_Time_Per_Template_ms']:<25.4f} | "
              f"{summary['Throughput_Templates_Per_Second']:<20.2f}")
    
    # Grab the storage stats for the largest batch to display the package overhead footprint
    largest_batch_key = f"Batch_{BATCH_SIZES[-1]}"
    if largest_batch_key in size_statistics:
        print("\n" + "="*85)
        print(f"{'IEEE Post-Quantum Registration Benchmark - Storage Overhead (Bytes)':^85}")
        print("="*85)
        print(f"{'Component':<35} | {'Mean Size (Bytes)':<20} | {'Max Size (Bytes)':<20}")
        print("-" * 85)
        
        largest_batch_sizes = size_statistics[largest_batch_key]
        for comp, stats in largest_batch_sizes.items():
            print(f"{comp:<35} | {stats['Mean']:<20.0f} | {stats['Max']:<20.0f}")
            
    print("="*85 + "\n")


if __name__ == "__main__":
    run_benchmarks()