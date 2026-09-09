"""
experiments/rsa_pqc_comparison.py
===================================
RSA-2048-OAEP vs ML-KEM-1024 (key establishment), and
RSA-2048-PSS vs ML-DSA-87 (signatures).

RSA benchmarks run for real right now (cryptography is available).
ML-KEM/ML-DSA benchmarks require liboqs-python (see README) and are
honestly skipped, never faked, if unavailable.

Run:
    python -m experiments.rsa_pqc_comparison
"""

import csv
import os
import statistics
import time

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

import config
from crypto import mlkem, mldsa


def _stats(samples_ns):
    return {
        "mean_ns": statistics.mean(samples_ns), "median_ns": statistics.median(samples_ns),
        "stdev_ns": statistics.stdev(samples_ns) if len(samples_ns) > 1 else 0.0,
        "min_ns": min(samples_ns), "max_ns": max(samples_ns), "n": len(samples_ns),
    }


def benchmark_rsa_oaep(iterations, warmup):
    message = os.urandom(32)  # RSA-OAEP with 2048-bit key can only encrypt small payloads directly

    def keygen():
        t0 = time.perf_counter_ns()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return key, time.perf_counter_ns() - t0

    for _ in range(warmup):
        key, _ = keygen()
        ct = key.public_key().encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                              algorithm=hashes.SHA256(), label=None))
        key.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    keygen_t, enc_t, dec_t, sizes = [], [], [], {}
    for _ in range(iterations):
        key, t1 = keygen()
        pub = key.public_key()

        t0 = time.perf_counter_ns()
        ct = pub.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                algorithm=hashes.SHA256(), label=None))
        t2 = time.perf_counter_ns() - t0

        t0 = time.perf_counter_ns()
        key.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        t3 = time.perf_counter_ns() - t0

        keygen_t.append(t1); enc_t.append(t2); dec_t.append(t3)
        sizes = {
            "public_key_bytes": len(pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
            "private_key_bytes": len(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
            "ciphertext_bytes": len(ct),
        }

    return {"keygen": _stats(keygen_t), "encrypt": _stats(enc_t), "decrypt": _stats(dec_t), "sizes": sizes}


def benchmark_rsa_pss(iterations, warmup):
    message = os.urandom(1024)

    def keygen():
        t0 = time.perf_counter_ns()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return key, time.perf_counter_ns() - t0

    pss_padding = lambda: padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

    for _ in range(warmup):
        key, _ = keygen()
        sig = key.sign(message, pss_padding(), hashes.SHA256())
        key.public_key().verify(sig, message, pss_padding(), hashes.SHA256())

    keygen_t, sign_t, verify_t, sizes = [], [], [], {}
    for _ in range(iterations):
        key, t1 = keygen()
        pub = key.public_key()

        t0 = time.perf_counter_ns()
        sig = key.sign(message, pss_padding(), hashes.SHA256())
        t2 = time.perf_counter_ns() - t0

        t0 = time.perf_counter_ns()
        pub.verify(sig, message, pss_padding(), hashes.SHA256())
        t3 = time.perf_counter_ns() - t0

        keygen_t.append(t1); sign_t.append(t2); verify_t.append(t3)
        sizes = {
            "public_key_bytes": len(pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
            "private_key_bytes": len(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
            "signature_bytes": len(sig),
        }

    return {"keygen": _stats(keygen_t), "sign": _stats(sign_t), "verify": _stats(verify_t), "sizes": sizes}


def run_all(iterations=None, warmup=None):
    iterations = iterations or 30  # RSA-2048 keygen is slow; keep this experiment tractable
    warmup = warmup or 3

    rsa_oaep = benchmark_rsa_oaep(iterations, warmup)
    rsa_pss = benchmark_rsa_pss(iterations, warmup)
    mlkem_results = None
    mldsa_results = None

    if mlkem.OQS_AVAILABLE:
        keygen_t, encap_t, decap_t = [], [], []
        for _ in range(iterations):
            pk, sk, t1 = mlkem.generate_keypair()
            ct, ss, t2 = mlkem.encapsulate(pk)
            _, t3 = mlkem.decapsulate(ct, sk)
            keygen_t.append(t1); encap_t.append(t2); decap_t.append(t3)
        mlkem_results = {
            "keygen": _stats(keygen_t), "encapsulate": _stats(encap_t), "decapsulate": _stats(decap_t),
            "sizes": {"public_key_bytes": len(pk), "private_key_bytes": len(sk), "ciphertext_bytes": len(ct)},
        }

    if mldsa.OQS_AVAILABLE:
        msg = os.urandom(1024)
        keygen_t, sign_t, verify_t = [], [], []
        for _ in range(iterations):
            pk, sk, t1 = mldsa.generate_keypair()
            sig, t2 = mldsa.sign(msg, sk)
            _, t3 = mldsa.verify(msg, sig, pk)
            keygen_t.append(t1); sign_t.append(t2); verify_t.append(t3)
        mldsa_results = {
            "keygen": _stats(keygen_t), "sign": _stats(sign_t), "verify": _stats(verify_t),
            "sizes": {"public_key_bytes": len(pk), "private_key_bytes": len(sk), "signature_bytes": len(sig)},
        }

    out_path = os.path.join(config.RESULTS_TABLES_DIR, "rsa_pqc_results.csv")
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "algorithm", "operation", "mean_ns", "median_ns", "stdev_ns", "min_ns", "max_ns", "n"])

        def write_ops(category, algo, ops):
            if ops is None:
                writer.writerow([category, algo, "SKIPPED_NOT_INSTALLED", "", "", "", "", "", ""])
                return
            for op_name, s in ops.items():
                if op_name == "sizes":
                    continue
                writer.writerow([category, algo, op_name, s["mean_ns"], s["median_ns"], s["stdev_ns"], s["min_ns"], s["max_ns"], s["n"]])

        write_ops("key_establishment", "RSA-2048-OAEP", rsa_oaep)
        write_ops("key_establishment", "ML-KEM-1024", mlkem_results)
        write_ops("signature", "RSA-2048-PSS", rsa_pss)
        write_ops("signature", "ML-DSA-87", mldsa_results)

    print(f"Wrote {out_path}")
    print("\nRSA-2048-OAEP sizes:", rsa_oaep["sizes"])
    print("RSA-2048-PSS sizes:", rsa_pss["sizes"])
    print("ML-KEM-1024:", "SKIPPED" if mlkem_results is None else mlkem_results["sizes"])
    print("ML-DSA-87:", "SKIPPED" if mldsa_results is None else mldsa_results["sizes"])

    return {"rsa_oaep": rsa_oaep, "rsa_pss": rsa_pss, "mlkem": mlkem_results, "mldsa": mldsa_results}


if __name__ == "__main__":
    run_all()
    print(
        "\nNote: RSA-2048-OAEP and ML-KEM-1024 are not the same cryptographic primitive — "
        "RSA-OAEP directly encrypts a payload, ML-KEM establishes a shared secret via "
        "encapsulation. This comparison contrasts classical vs. post-quantum key-establishment "
        "approaches, not a like-for-like algorithm swap. PQC's larger keys/ciphertexts/signatures "
        "trade storage and bandwidth for resistance to Shor's-algorithm-class quantum attacks."
    )
