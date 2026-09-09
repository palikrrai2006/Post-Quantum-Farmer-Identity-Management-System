"""
experiments/crypto_evaluation.py
==================================
Benchmarks SHA3-256, AES-256-GCM, ML-KEM-1024, ML-DSA-87 with warm-up +
repeated iterations. Every number is measured with time.perf_counter_ns()
from actual calls — nothing here is a placeholder.

ML-KEM/ML-DSA sections require liboqs-python installed (see README);
if unavailable they are skipped with a clear message rather than faked.

Run:
    python -m experiments.crypto_evaluation
"""

import csv
import os
import statistics
import time

import config
from crypto import hashing, aes_gcm, kdf
from crypto import mlkem, mldsa


def _stats(samples_ns):
    return {
        "mean_ns": statistics.mean(samples_ns),
        "median_ns": statistics.median(samples_ns),
        "stdev_ns": statistics.stdev(samples_ns) if len(samples_ns) > 1 else 0.0,
        "min_ns": min(samples_ns),
        "max_ns": max(samples_ns),
        "n": len(samples_ns),
    }


def benchmark_sha3(iterations, warmup):
    payload = os.urandom(4096)
    for _ in range(warmup):
        hashing.sha3_256_hash(payload)
    samples = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        hashing.sha3_256_hash(payload)
        samples.append(time.perf_counter_ns() - t0)
    return _stats(samples)


def benchmark_aes_gcm(iterations, warmup):
    key = os.urandom(config.AES_KEY_BYTES)
    payload = os.urandom(4096)

    for _ in range(warmup):
        enc = aes_gcm.encrypt_template(key, payload)
        aes_gcm.decrypt_template(key, enc["ciphertext"], enc["nonce"], enc["tag"])

    enc_samples, dec_samples = [], []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        enc = aes_gcm.encrypt_template(key, payload)
        enc_samples.append(time.perf_counter_ns() - t0)

        t0 = time.perf_counter_ns()
        aes_gcm.decrypt_template(key, enc["ciphertext"], enc["nonce"], enc["tag"])
        dec_samples.append(time.perf_counter_ns() - t0)

    return {"encrypt": _stats(enc_samples), "decrypt": _stats(dec_samples)}


def benchmark_mlkem(iterations, warmup):
    if not mlkem.OQS_AVAILABLE:
        return None
    for _ in range(warmup):
        pk, sk, _ = mlkem.generate_keypair()
        ct, ss, _ = mlkem.encapsulate(pk)
        mlkem.decapsulate(ct, sk)

    keygen, encap, decap = [], [], []
    for _ in range(iterations):
        pk, sk, t1 = mlkem.generate_keypair()
        ct, ss1, t2 = mlkem.encapsulate(pk)
        ss2, t3 = mlkem.decapsulate(ct, sk)
        assert ss1 == ss2
        keygen.append(t1); encap.append(t2); decap.append(t3)

    return {"keygen": _stats(keygen), "encapsulate": _stats(encap), "decapsulate": _stats(decap)}


def benchmark_mldsa(iterations, warmup):
    if not mldsa.OQS_AVAILABLE:
        return None
    msg = os.urandom(1024)
    for _ in range(warmup):
        pk, sk, _ = mldsa.generate_keypair()
        sig, _ = mldsa.sign(msg, sk)
        mldsa.verify(msg, sig, pk)

    keygen, sign_t, verify_t = [], [], []
    for _ in range(iterations):
        pk, sk, t1 = mldsa.generate_keypair()
        sig, t2 = mldsa.sign(msg, sk)
        valid, t3 = mldsa.verify(msg, sig, pk)
        assert valid
        keygen.append(t1); sign_t.append(t2); verify_t.append(t3)

    return {"keygen": _stats(keygen), "sign": _stats(sign_t), "verify": _stats(verify_t)}


def run_all(iterations=None, warmup=None):
    iterations = iterations or config.CRYPTO_BENCHMARK_ITERATIONS
    warmup = warmup or config.CRYPTO_BENCHMARK_WARMUP

    results = {
        "sha3_256": benchmark_sha3(iterations, warmup),
        "aes_256_gcm": benchmark_aes_gcm(iterations, warmup),
        "ml_kem_1024": benchmark_mlkem(iterations, warmup),
        "ml_dsa_87": benchmark_mldsa(iterations, warmup),
    }

    out_path = os.path.join(config.RESULTS_TABLES_DIR, "crypto_results.csv")
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["algorithm", "operation", "mean_ns", "median_ns", "stdev_ns", "min_ns", "max_ns", "n"])
        for algo, ops in results.items():
            if ops is None:
                writer.writerow([algo, "SKIPPED_NOT_INSTALLED", "", "", "", "", "", ""])
                continue
            if "mean_ns" in ops:  # single-op result (sha3)
                writer.writerow([algo, "hash", ops["mean_ns"], ops["median_ns"], ops["stdev_ns"], ops["min_ns"], ops["max_ns"], ops["n"]])
            else:
                for op_name, s in ops.items():
                    writer.writerow([algo, op_name, s["mean_ns"], s["median_ns"], s["stdev_ns"], s["min_ns"], s["max_ns"], s["n"]])

    print(f"Wrote {out_path}")
    return results


if __name__ == "__main__":
    results = run_all()
    for algo, ops in results.items():
        print(f"\n{algo}:")
        if ops is None:
            print("  SKIPPED — liboqs-python not installed in this environment")
        else:
            print(" ", ops)
