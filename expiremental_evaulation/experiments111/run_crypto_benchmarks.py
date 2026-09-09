"""Benchmark harness for the cryptographic module.

Runs repeated trials of each cryptographic primitive (SHA3-256, AES-256-GCM,
ML-KEM-1024, ML-DSA-87) over representative SourceAFIS template sizes and
writes CSV/JSON results suitable for IEEE Access tables and graphs.

This script exercises the crypto primitives directly; it does not require a
running IPFS daemon or blockchain node (see ``registration/register_user.py``
and ``verification/verify_user.py`` for the full end-to-end workflow, which
does require those services).
"""

from __future__ import annotations

import csv
import json
import statistics
from pathlib import Path

from config import RESULTS_DIR
from crypto import aes_utils, hash_utils, mldsa_utils, mlkem_utils
from logging_utils import get_logger

logger = get_logger(__name__)

DEFAULT_BATCHES = [10, 20, 30, 40, 50]
DEFAULT_TEMPLATE_SIZE_BYTES = 1024  # representative SourceAFIS template size


def _run_trials(trial_count: int, template_size_bytes: int) -> list[dict[str, float]]:
    """Execute one full set of crypto operations per trial and collect timings.

    Args:
        trial_count: Number of independent trials to run.
        template_size_bytes: Size of the synthetic template payload per trial.

    Returns:
        A list of per-trial timing dictionaries (one dict per trial).
    """
    from Crypto.Random import get_random_bytes

    rows: list[dict[str, float]] = []

    for trial_index in range(trial_count):
        template_bytes = get_random_bytes(template_size_bytes)

        hash_result = hash_utils.hash_template(template_bytes)

        aes_key = aes_utils.generate_aes_key()
        aes_enc_result = aes_utils.encrypt_bytes(template_bytes, aes_key)
        aes_dec_result = aes_utils.decrypt_bytes(
            aes_enc_result.ciphertext, aes_key, aes_enc_result.nonce, aes_enc_result.tag
        )

        kem_keypair = mlkem_utils.generate_keypair()
        kem_encap_result = mlkem_utils.encapsulate_aes_key(kem_keypair.public_key)
        kem_decap_result = mlkem_utils.decapsulate_aes_key(kem_keypair.secret_key, kem_encap_result.kem_ciphertext)

        dsa_keypair = mldsa_utils.generate_keypair()
        sign_result = mldsa_utils.sign_package(dsa_keypair.secret_key, template_bytes)
        verify_result = mldsa_utils.verify_signature(dsa_keypair.public_key, template_bytes, sign_result.signature)

        rows.append(
            {
                "trial": trial_index + 1,
                "template_size_bytes": template_size_bytes,
                "sha3_time_seconds": hash_result.hash_time_seconds,
                "aes_encryption_time_seconds": aes_enc_result.encryption_time_seconds,
                "aes_decryption_time_seconds": aes_dec_result.decryption_time_seconds,
                "mlkem_keygen_time_seconds": kem_keypair.keygen_time_seconds,
                "mlkem_encapsulation_time_seconds": kem_encap_result.encapsulation_time_seconds,
                "mlkem_decapsulation_time_seconds": kem_decap_result.decapsulation_time_seconds,
                "mldsa_keygen_time_seconds": dsa_keypair.keygen_time_seconds,
                "mldsa_signing_time_seconds": sign_result.signing_time_seconds,
                "mldsa_verification_time_seconds": verify_result.verification_time_seconds,
                "mlkem_public_key_size_bytes": kem_keypair.public_key_size_bytes,
                "mlkem_secret_key_size_bytes": kem_keypair.secret_key_size_bytes,
                "mlkem_ciphertext_size_bytes": kem_encap_result.kem_ciphertext_size_bytes,
                "mldsa_public_key_size_bytes": dsa_keypair.public_key_size_bytes,
                "mldsa_secret_key_size_bytes": dsa_keypair.secret_key_size_bytes,
                "mldsa_signature_size_bytes": sign_result.signature_size_bytes,
                "aes_ciphertext_size_bytes": aes_enc_result.ciphertext_size_bytes,
            }
        )

        if not verify_result.is_valid:
            logger.error("Trial %d: ML-DSA-87 verification unexpectedly failed.", trial_index + 1)

    return rows


def _write_csv(rows: list[dict[str, float]], output_path: Path) -> None:
    """Write per-trial benchmark rows to a CSV file.

    Args:
        rows: The list of per-trial timing/size dictionaries.
        output_path: Destination CSV file path.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys())
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    logger.info("Per-trial benchmark CSV written to %s", output_path)


def _calculate_summary(rows: list[dict[str, float]]) -> dict[str, dict[str, float]]:
    """Calculate mean/stdev/min/max summary statistics for a given set of rows."""
    numeric_fields = [key for key in rows[0] if key != "trial"]
    summary: dict[str, dict[str, float]] = {}
    for field_name in numeric_fields:
        values = [row[field_name] for row in rows]
        summary[field_name] = {
            "mean": statistics.mean(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
            "min": min(values),
            "max": max(values),
        }
    return summary


def _write_summary(summary: dict[str, dict[str, float]], output_path: Path) -> None:
    """Write summary statistics to a JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
    logger.info("Benchmark summary JSON written to %s", output_path)


def _print_final_table(batch_summaries: dict[int, dict[str, dict[str, float]]]) -> None:
    """Print a comprehensive Markdown-style table summarizing mean execution times across all batches."""
    fields_to_show = [
        ("SHA3 Hash", "sha3_time_seconds"),
        ("AES Encrypt", "aes_encryption_time_seconds"),
        ("AES Decrypt", "aes_decryption_time_seconds"),
        ("ML-KEM Keygen", "mlkem_keygen_time_seconds"),
        ("ML-KEM Encap", "mlkem_encapsulation_time_seconds"),
        ("ML-KEM Decap", "mlkem_decapsulation_time_seconds"),
        ("ML-DSA Keygen", "mldsa_keygen_time_seconds"),
        ("ML-DSA Sign", "mldsa_signing_time_seconds"),
        ("ML-DSA Verify", "mldsa_verification_time_seconds"),
    ]

    print("\n" + "=" * 115)
    print("      FINAL BENCHMARK SUMMARY TABLE (Mean Execution Times in Seconds)")
    print("=" * 115)
    
    # Header
    header_str = f"{'Cryptographic Primitive':<25}"
    for batch in sorted(batch_summaries.keys()):
        header_str += f" | Batch {batch:<5}"
    print(header_str)
    print("-" * 115)

    # Rows
    for display_name, field_key in fields_to_show:
        row_str = f"{display_name:<25}"
        for batch in sorted(batch_summaries.keys()):
            mean_val = batch_summaries[batch][field_key]["mean"]
            row_str += f" | {mean_val:.6f}s"
        print(row_str)
        
    print("=" * 115 + "\n")


def _write_final_table_csv(batch_summaries: dict[int, dict[str, dict[str, float]]], output_path: Path) -> None:
    """Save the final summary table to a single CSV file for easy graphing/reporting."""
    fields_to_show = [
        ("SHA3 Hash", "sha3_time_seconds"),
        ("AES Encrypt", "aes_encryption_time_seconds"),
        ("AES Decrypt", "aes_decryption_time_seconds"),
        ("ML-KEM Keygen", "mlkem_keygen_time_seconds"),
        ("ML-KEM Encap", "mlkem_encapsulation_time_seconds"),
        ("ML-KEM Decap", "mlkem_decapsulation_time_seconds"),
        ("ML-DSA Keygen", "mldsa_keygen_time_seconds"),
        ("ML-DSA Sign", "mldsa_signing_time_seconds"),
        ("ML-DSA Verify", "mldsa_verification_time_seconds"),
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    batches = sorted(batch_summaries.keys())
    
    # Create header row dynamically based on the batches
    header = ["Cryptographic Primitive"] + [f"Batch_{b}_Mean_Seconds" for b in batches]

    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        
        for display_name, field_key in fields_to_show:
            row = [display_name]
            for batch in batches:
                mean_val = batch_summaries[batch][field_key]["mean"]
                row.append(f"{mean_val:.6f}")
            writer.writerow(row)
            
    logger.info("Combined summary table CSV written to %s", output_path)


def run_benchmarks(batches: list[int] | None = None, template_size_bytes: int = DEFAULT_TEMPLATE_SIZE_BYTES) -> None:
    """Run the full crypto benchmark suite across multiple batch sizes, save results, and output a summary table.

    Args:
        batches: List of independent trial counts to run.
        template_size_bytes: Size of the synthetic template payload per trial.
    """
    if batches is None:
        batches = DEFAULT_BATCHES

    # Dictionary to keep track of summaries for the final table display
    all_batch_summaries: dict[int, dict[str, dict[str, float]]] = {}

    for trial_count in batches:
        logger.info("Starting crypto benchmark suite: %d trials, %d-byte templates.", trial_count, template_size_bytes)
        rows = _run_trials(trial_count, template_size_bytes)
        
        csv_path = RESULTS_DIR / f"crypto_benchmark_trials_{trial_count}.csv"
        json_path = RESULTS_DIR / f"crypto_benchmark_summary_{trial_count}.json"
        
        _write_csv(rows, csv_path)
        
        summary = _calculate_summary(rows)
        _write_summary(summary, json_path)
        
        all_batch_summaries[trial_count] = summary
        logger.info("Crypto benchmark suite for %d trials complete.", trial_count)

    # Output the summary table to the console
    _print_final_table(all_batch_summaries)
    
    # Save the consolidated table to a single CSV
    final_csv_path = RESULTS_DIR / "crypto_benchmark_final_summary.csv"
    _write_final_table_csv(all_batch_summaries, final_csv_path)


if __name__ == "__main__":
    run_benchmarks()