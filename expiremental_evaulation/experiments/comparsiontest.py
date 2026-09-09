"""
experiments/rsa_vs_pqc.py

Complete Classical vs Post-Quantum Cryptography Benchmark

Comparison 1: Key Establishment
    RSA-2048-OAEP vs ML-KEM-1024

Comparison 2: Digital Signatures
    RSA-2048-PSS vs ML-DSA-87

Metrics:
    - Key generation time
    - Encryption / Encapsulation time
    - Decryption / Decapsulation time
    - Signing time
    - Verification time
    - Public key size
    - Private/secret key size
    - Ciphertext size
    - Signature size
    - Correctness

Outputs:
    results/rsa_vs_pqc_detailed.csv
    results/rsa_vs_pqc_summary.csv
    results/rsa_vs_pqc_summary.json
"""

import csv
import json
import statistics
import time
from pathlib import Path

# ============================================================
# RSA IMPORTS
# ============================================================

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# ============================================================
# POST-QUANTUM IMPORT
# ============================================================

import oqs


# ============================================================
# CONFIGURATION
# ============================================================

ITERATIONS = 1000

RSA_KEY_SIZE = 2048

MLKEM_ALGORITHM = "ML-KEM-1024"

MLDSA_ALGORITHM = "ML-DSA-87"


# ============================================================
# RESULTS DIRECTORY
# ============================================================

RESULTS_DIR = Path("results")

RESULTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)


DETAILED_CSV = (
    RESULTS_DIR
    / "rsa_vs_pqc_detailed.csv"
)


SUMMARY_CSV = (
    RESULTS_DIR
    / "rsa_vs_pqc_summary.csv"
)


SUMMARY_JSON = (
    RESULTS_DIR
    / "rsa_vs_pqc_summary.json"
)


# ============================================================
# TEST DATA
# ============================================================

# 32-byte symmetric key / shared secret
RSA_SECRET = b"A" * 32


# Message used for digital signatures
MESSAGE = (

    b"Post-Quantum Secure Fingerprint Authentication "
    b"using ML-KEM ML-DSA Blockchain and IPFS"

)


# ============================================================
# STATISTICS
# ============================================================

def calculate_stats(values):

    if not values:

        return {

            "average_ms": 0,

            "median_ms": 0,

            "minimum_ms": 0,

            "maximum_ms": 0,

            "std_ms": 0

        }


    return {

        "average_ms":
            statistics.mean(values),

        "median_ms":
            statistics.median(values),

        "minimum_ms":
            min(values),

        "maximum_ms":
            max(values),

        "std_ms":
            statistics.stdev(values)
            if len(values) > 1
            else 0

    }


# ============================================================
# 1. RSA-2048 OAEP
# ============================================================

def benchmark_rsa_oaep():

    print("\n")

    print("=" * 80)

    print(
        "RSA-2048 OAEP KEY TRANSPORT BENCHMARK"
    )

    print("=" * 80)


    keygen_times = []

    encrypt_times = []

    decrypt_times = []

    rows = []


    public_key_size = 0

    private_key_size = 0

    ciphertext_size = 0


    for iteration in range(
        1,
        ITERATIONS + 1
    ):


        # ====================================================
        # KEY GENERATION
        # ====================================================

        start = time.perf_counter_ns()


        private_key = RSA.generate(
            RSA_KEY_SIZE
        )


        end = time.perf_counter_ns()


        keygen_ms = (

            end - start

        ) / 1_000_000


        keygen_times.append(
            keygen_ms
        )


        public_key = (
            private_key.publickey()
        )


        # ====================================================
        # KEY SIZE
        # ====================================================

        public_key_bytes = (
            public_key.export_key(
                format="DER"
            )
        )


        private_key_bytes = (
            private_key.export_key(
                format="DER"
            )
        )


        public_key_size = len(
            public_key_bytes
        )


        private_key_size = len(
            private_key_bytes
        )


        # ====================================================
        # RSA-OAEP ENCRYPTION
        # ====================================================

        encrypt_cipher = (

            PKCS1_OAEP.new(

                public_key,

                hashAlgo=SHA256

            )

        )


        start = time.perf_counter_ns()


        ciphertext = (

            encrypt_cipher.encrypt(
                RSA_SECRET
            )

        )


        end = time.perf_counter_ns()


        encrypt_ms = (

            end - start

        ) / 1_000_000


        encrypt_times.append(
            encrypt_ms
        )


        ciphertext_size = len(
            ciphertext
        )


        # ====================================================
        # RSA-OAEP DECRYPTION
        # ====================================================

        decrypt_cipher = (

            PKCS1_OAEP.new(

                private_key,

                hashAlgo=SHA256

            )

        )


        start = time.perf_counter_ns()


        recovered_secret = (

            decrypt_cipher.decrypt(
                ciphertext
            )

        )


        end = time.perf_counter_ns()


        decrypt_ms = (

            end - start

        ) / 1_000_000


        decrypt_times.append(
            decrypt_ms
        )


        success = (

            recovered_secret
            ==
            RSA_SECRET

        )


        rows.append({

            "comparison":
                "Key Establishment",

            "algorithm":
                "RSA-2048-OAEP",

            "iteration":
                iteration,

            "keygen_ms":
                keygen_ms,

            "encrypt_encaps_ms":
                encrypt_ms,

            "decrypt_decaps_ms":
                decrypt_ms,

            "sign_ms":
                "",

            "verify_ms":
                "",

            "public_key_bytes":
                public_key_size,

            "private_key_bytes":
                private_key_size,

            "ciphertext_bytes":
                ciphertext_size,

            "signature_bytes":
                "",

            "success":
                success

        })


        print(

            f"[RSA-OAEP {iteration:3}/{ITERATIONS}] "

            f"KeyGen={keygen_ms:8.3f} ms | "

            f"Encrypt={encrypt_ms:8.3f} ms | "

            f"Decrypt={decrypt_ms:8.3f} ms | "

            f"Success={success}"

        )


    summary = {

        "comparison":
            "Key Establishment",

        "algorithm":
            "RSA-2048-OAEP",

        "keygen":
            calculate_stats(
                keygen_times
            ),

        "operation1_name":
            "Encryption",

        "operation1":
            calculate_stats(
                encrypt_times
            ),

        "operation2_name":
            "Decryption",

        "operation2":
            calculate_stats(
                decrypt_times
            ),

        "public_key_bytes":
            public_key_size,

        "private_key_bytes":
            private_key_size,

        "output_size_bytes":
            ciphertext_size,

        "success_count":
            sum(
                row["success"]
                for row in rows
            )

    }


    return rows, summary


# ============================================================
# 2. ML-KEM-1024
# ============================================================

def benchmark_mlkem():

    print("\n")

    print("=" * 80)

    print(
        "ML-KEM-1024 KEY ESTABLISHMENT BENCHMARK"
    )

    print("=" * 80)


    keygen_times = []

    encaps_times = []

    decaps_times = []

    rows = []


    public_key_size = 0

    private_key_size = 0

    ciphertext_size = 0


    for iteration in range(
        1,
        ITERATIONS + 1
    ):


        with oqs.KeyEncapsulation(
            MLKEM_ALGORITHM
        ) as kem:


            # =================================================
            # KEY GENERATION
            # =================================================

            start = (
                time.perf_counter_ns()
            )


            public_key = (
                kem.generate_keypair()
            )


            end = (
                time.perf_counter_ns()
            )


            keygen_ms = (

                end - start

            ) / 1_000_000


            keygen_times.append(
                keygen_ms
            )


            secret_key = (
                kem.export_secret_key()
            )


            public_key_size = len(
                public_key
            )


            private_key_size = len(
                secret_key
            )


            # =================================================
            # ENCAPSULATION
            # =================================================

            start = (
                time.perf_counter_ns()
            )


            ciphertext, shared_secret_sender = (

                kem.encap_secret(
                    public_key
                )

            )


            end = (
                time.perf_counter_ns()
            )


            encaps_ms = (

                end - start

            ) / 1_000_000


            encaps_times.append(
                encaps_ms
            )


            ciphertext_size = len(
                ciphertext
            )


            # =================================================
            # DECAPSULATION
            # =================================================

            start = (
                time.perf_counter_ns()
            )


            shared_secret_receiver = (

                kem.decap_secret(
                    ciphertext
                )

            )


            end = (
                time.perf_counter_ns()
            )


            decaps_ms = (

                end - start

            ) / 1_000_000


            decaps_times.append(
                decaps_ms
            )


            success = (

                shared_secret_sender
                ==
                shared_secret_receiver

            )


            rows.append({

                "comparison":
                    "Key Establishment",

                "algorithm":
                    "ML-KEM-1024",

                "iteration":
                    iteration,

                "keygen_ms":
                    keygen_ms,

                "encrypt_encaps_ms":
                    encaps_ms,

                "decrypt_decaps_ms":
                    decaps_ms,

                "sign_ms":
                    "",

                "verify_ms":
                    "",

                "public_key_bytes":
                    public_key_size,

                "private_key_bytes":
                    private_key_size,

                "ciphertext_bytes":
                    ciphertext_size,

                "signature_bytes":
                    "",

                "success":
                    success

            })


            print(

                f"[ML-KEM {iteration:3}/{ITERATIONS}] "

                f"KeyGen={keygen_ms:8.3f} ms | "

                f"Encaps={encaps_ms:8.3f} ms | "

                f"Decaps={decaps_ms:8.3f} ms | "

                f"Success={success}"

            )


    summary = {

        "comparison":
            "Key Establishment",

        "algorithm":
            "ML-KEM-1024",

        "keygen":
            calculate_stats(
                keygen_times
            ),

        "operation1_name":
            "Encapsulation",

        "operation1":
            calculate_stats(
                encaps_times
            ),

        "operation2_name":
            "Decapsulation",

        "operation2":
            calculate_stats(
                decaps_times
            ),

        "public_key_bytes":
            public_key_size,

        "private_key_bytes":
            private_key_size,

        "output_size_bytes":
            ciphertext_size,

        "success_count":
            sum(
                row["success"]
                for row in rows
            )

    }


    return rows, summary


# ============================================================
# 3. RSA-2048 PSS
# ============================================================

def benchmark_rsa_pss():

    print("\n")

    print("=" * 80)

    print(
        "RSA-2048 PSS DIGITAL SIGNATURE BENCHMARK"
    )

    print("=" * 80)


    keygen_times = []

    sign_times = []

    verify_times = []

    rows = []


    public_key_size = 0

    private_key_size = 0

    signature_size = 0


    for iteration in range(
        1,
        ITERATIONS + 1
    ):


        # ====================================================
        # KEY GENERATION
        # ====================================================

        start = (
            time.perf_counter_ns()
        )


        private_key = RSA.generate(
            RSA_KEY_SIZE
        )


        end = (
            time.perf_counter_ns()
        )


        keygen_ms = (

            end - start

        ) / 1_000_000


        keygen_times.append(
            keygen_ms
        )


        public_key = (
            private_key.publickey()
        )


        # ====================================================
        # KEY SIZE
        # ====================================================

        public_key_size = len(

            public_key.export_key(
                format="DER"
            )

        )


        private_key_size = len(

            private_key.export_key(
                format="DER"
            )

        )


        # ====================================================
        # HASH MESSAGE
        # ====================================================

        message_hash = (
            SHA256.new(
                MESSAGE
            )
        )


        # ====================================================
        # SIGN
        # ====================================================

        signer = pss.new(
            private_key
        )


        start = (
            time.perf_counter_ns()
        )


        signature = (
            signer.sign(
                message_hash
            )
        )


        end = (
            time.perf_counter_ns()
        )


        sign_ms = (

            end - start

        ) / 1_000_000


        sign_times.append(
            sign_ms
        )


        signature_size = len(
            signature
        )


        # ====================================================
        # VERIFY
        # ====================================================

        verify_hash = (
            SHA256.new(
                MESSAGE
            )
        )


        verifier = pss.new(
            public_key
        )


        start = (
            time.perf_counter_ns()
        )


        try:

            verifier.verify(

                verify_hash,

                signature

            )


            success = True


        except (
            ValueError,
            TypeError
        ):

            success = False


        end = (
            time.perf_counter_ns()
        )


        verify_ms = (

            end - start

        ) / 1_000_000


        verify_times.append(
            verify_ms
        )


        rows.append({

            "comparison":
                "Digital Signature",

            "algorithm":
                "RSA-2048-PSS",

            "iteration":
                iteration,

            "keygen_ms":
                keygen_ms,

            "encrypt_encaps_ms":
                "",

            "decrypt_decaps_ms":
                "",

            "sign_ms":
                sign_ms,

            "verify_ms":
                verify_ms,

            "public_key_bytes":
                public_key_size,

            "private_key_bytes":
                private_key_size,

            "ciphertext_bytes":
                "",

            "signature_bytes":
                signature_size,

            "success":
                success

        })


        print(

            f"[RSA-PSS {iteration:3}/{ITERATIONS}] "

            f"KeyGen={keygen_ms:8.3f} ms | "

            f"Sign={sign_ms:8.3f} ms | "

            f"Verify={verify_ms:8.3f} ms | "

            f"Success={success}"

        )


    summary = {

        "comparison":
            "Digital Signature",

        "algorithm":
            "RSA-2048-PSS",

        "keygen":
            calculate_stats(
                keygen_times
            ),

        "operation1_name":
            "Signing",

        "operation1":
            calculate_stats(
                sign_times
            ),

        "operation2_name":
            "Verification",

        "operation2":
            calculate_stats(
                verify_times
            ),

        "public_key_bytes":
            public_key_size,

        "private_key_bytes":
            private_key_size,

        "output_size_bytes":
            signature_size,

        "success_count":
            sum(
                row["success"]
                for row in rows
            )

    }


    return rows, summary


# ============================================================
# 4. ML-DSA-87
# ============================================================

def benchmark_mldsa():

    print("\n")

    print("=" * 80)

    print(
        "ML-DSA-87 DIGITAL SIGNATURE BENCHMARK"
    )

    print("=" * 80)


    keygen_times = []

    sign_times = []

    verify_times = []

    rows = []


    public_key_size = 0

    private_key_size = 0

    signature_size = 0


    for iteration in range(
        1,
        ITERATIONS + 1
    ):


        with oqs.Signature(
            MLDSA_ALGORITHM
        ) as signer:


            # =================================================
            # KEY GENERATION
            # =================================================

            start = (
                time.perf_counter_ns()
            )


            public_key = (
                signer.generate_keypair()
            )


            end = (
                time.perf_counter_ns()
            )


            keygen_ms = (

                end - start

            ) / 1_000_000


            keygen_times.append(
                keygen_ms
            )


            secret_key = (
                signer.export_secret_key()
            )


            public_key_size = len(
                public_key
            )


            private_key_size = len(
                secret_key
            )


            # =================================================
            # SIGN
            # =================================================

            start = (
                time.perf_counter_ns()
            )


            signature = (
                signer.sign(
                    MESSAGE
                )
            )


            end = (
                time.perf_counter_ns()
            )


            sign_ms = (

                end - start

            ) / 1_000_000


            sign_times.append(
                sign_ms
            )


            signature_size = len(
                signature
            )


            # =================================================
            # VERIFY
            # =================================================

            start = (
                time.perf_counter_ns()
            )


            success = (

                signer.verify(

                    MESSAGE,

                    signature,

                    public_key

                )

            )


            end = (
                time.perf_counter_ns()
            )


            verify_ms = (

                end - start

            ) / 1_000_000


            verify_times.append(
                verify_ms
            )


            rows.append({

                "comparison":
                    "Digital Signature",

                "algorithm":
                    "ML-DSA-87",

                "iteration":
                    iteration,

                "keygen_ms":
                    keygen_ms,

                "encrypt_encaps_ms":
                    "",

                "decrypt_decaps_ms":
                    "",

                "sign_ms":
                    sign_ms,

                "verify_ms":
                    verify_ms,

                "public_key_bytes":
                    public_key_size,

                "private_key_bytes":
                    private_key_size,

                "ciphertext_bytes":
                    "",

                "signature_bytes":
                    signature_size,

                "success":
                    success

            })


            print(

                f"[ML-DSA {iteration:3}/{ITERATIONS}] "

                f"KeyGen={keygen_ms:8.3f} ms | "

                f"Sign={sign_ms:8.3f} ms | "

                f"Verify={verify_ms:8.3f} ms | "

                f"Success={success}"

            )


    summary = {

        "comparison":
            "Digital Signature",

        "algorithm":
            "ML-DSA-87",

        "keygen":
            calculate_stats(
                keygen_times
            ),

        "operation1_name":
            "Signing",

        "operation1":
            calculate_stats(
                sign_times
            ),

        "operation2_name":
            "Verification",

        "operation2":
            calculate_stats(
                verify_times
            ),

        "public_key_bytes":
            public_key_size,

        "private_key_bytes":
            private_key_size,

        "output_size_bytes":
            signature_size,

        "success_count":
            sum(
                row["success"]
                for row in rows
            )

    }


    return rows, summary


# ============================================================
# MAIN
# ============================================================

def main():

    print("\n")

    print("=" * 90)

    print(
        "CLASSICAL RSA vs POST-QUANTUM CRYPTOGRAPHY BENCHMARK"
    )

    print("=" * 90)

    print(
        f"Iterations : {ITERATIONS}"
    )

    print()

    print(
        "Key Establishment:"
    )

    print(
        "RSA-2048-OAEP vs ML-KEM-1024"
    )

    print()

    print(
        "Digital Signature:"
    )

    print(
        "RSA-2048-PSS vs ML-DSA-87"
    )

    print("=" * 90)


    experiment_start = (
        time.perf_counter()
    )


    # ========================================================
    # RUN ALL BENCHMARKS
    # ========================================================

    rsa_oaep_rows, rsa_oaep_summary = (
        benchmark_rsa_oaep()
    )


    mlkem_rows, mlkem_summary = (
        benchmark_mlkem()
    )


    rsa_pss_rows, rsa_pss_summary = (
        benchmark_rsa_pss()
    )


    mldsa_rows, mldsa_summary = (
        benchmark_mldsa()
    )


    # ========================================================
    # COMBINE ROWS
    # ========================================================

    all_rows = (

        rsa_oaep_rows

        +

        mlkem_rows

        +

        rsa_pss_rows

        +

        mldsa_rows

    )


    summaries = [

        rsa_oaep_summary,

        mlkem_summary,

        rsa_pss_summary,

        mldsa_summary

    ]


    # ========================================================
    # SAVE DETAILED CSV
    # ========================================================

    detailed_fields = [

        "comparison",

        "algorithm",

        "iteration",

        "keygen_ms",

        "encrypt_encaps_ms",

        "decrypt_decaps_ms",

        "sign_ms",

        "verify_ms",

        "public_key_bytes",

        "private_key_bytes",

        "ciphertext_bytes",

        "signature_bytes",

        "success"

    ]


    with open(

        DETAILED_CSV,

        "w",

        newline="",

        encoding="utf-8"

    ) as file:


        writer = csv.DictWriter(

            file,

            fieldnames=detailed_fields

        )


        writer.writeheader()


        writer.writerows(
            all_rows
        )


    # ========================================================
    # CREATE SUMMARY ROWS
    # ========================================================

    summary_rows = []


    for summary in summaries:


        summary_rows.append({

            "comparison":
                summary[
                    "comparison"
                ],

            "algorithm":
                summary[
                    "algorithm"
                ],

            "avg_keygen_ms":
                summary[
                    "keygen"
                ][
                    "average_ms"
                ],

            "median_keygen_ms":
                summary[
                    "keygen"
                ][
                    "median_ms"
                ],

            "std_keygen_ms":
                summary[
                    "keygen"
                ][
                    "std_ms"
                ],

            "operation1":
                summary[
                    "operation1_name"
                ],

            "avg_operation1_ms":
                summary[
                    "operation1"
                ][
                    "average_ms"
                ],

            "median_operation1_ms":
                summary[
                    "operation1"
                ][
                    "median_ms"
                ],

            "operation2":
                summary[
                    "operation2_name"
                ],

            "avg_operation2_ms":
                summary[
                    "operation2"
                ][
                    "average_ms"
                ],

            "median_operation2_ms":
                summary[
                    "operation2"
                ][
                    "median_ms"
                ],

            "public_key_bytes":
                summary[
                    "public_key_bytes"
                ],

            "private_key_bytes":
                summary[
                    "private_key_bytes"
                ],

            "ciphertext_or_signature_bytes":
                summary[
                    "output_size_bytes"
                ],

            "success_count":
                summary[
                    "success_count"
                ]

        })


    # ========================================================
    # SAVE SUMMARY CSV
    # ========================================================

    with open(

        SUMMARY_CSV,

        "w",

        newline="",

        encoding="utf-8"

    ) as file:


        writer = csv.DictWriter(

            file,

            fieldnames=
                summary_rows[0].keys()

        )


        writer.writeheader()


        writer.writerows(
            summary_rows
        )


    # ========================================================
    # SAVE JSON
    # ========================================================

    final_json = {

        "iterations":
            ITERATIONS,

        "RSA-2048-OAEP":
            rsa_oaep_summary,

        "ML-KEM-1024":
            mlkem_summary,

        "RSA-2048-PSS":
            rsa_pss_summary,

        "ML-DSA-87":
            mldsa_summary

    }


    with open(

        SUMMARY_JSON,

        "w",

        encoding="utf-8"

    ) as file:


        json.dump(

            final_json,

            file,

            indent=4

        )


    # ========================================================
    # PRINT KEY ESTABLISHMENT TABLE
    # ========================================================

    print("\n")

    print("=" * 100)

    print(
        "KEY ESTABLISHMENT COMPARISON"
    )

    print("=" * 100)


    print(

        f"{'Algorithm':<20}"

        f"{'KeyGen(ms)':>15}"

        f"{'Enc/Encap(ms)':>18}"

        f"{'Dec/Decap(ms)':>18}"

        f"{'Public Key(B)':>16}"

        f"{'Private Key(B)':>17}"

        f"{'Ciphertext(B)':>15}"

    )


    print("-" * 120)


    for row in summary_rows[:2]:


        print(

            f"{row['algorithm']:<20}"

            f"{row['avg_keygen_ms']:>15.4f}"

            f"{row['avg_operation1_ms']:>18.4f}"

            f"{row['avg_operation2_ms']:>18.4f}"

            f"{row['public_key_bytes']:>16}"

            f"{row['private_key_bytes']:>17}"

            f"{row['ciphertext_or_signature_bytes']:>15}"

        )


    # ========================================================
    # PRINT SIGNATURE TABLE
    # ========================================================

    print("\n")

    print("=" * 100)

    print(
        "DIGITAL SIGNATURE COMPARISON"
    )

    print("=" * 100)


    print(

        f"{'Algorithm':<20}"

        f"{'KeyGen(ms)':>15}"

        f"{'Sign(ms)':>15}"

        f"{'Verify(ms)':>15}"

        f"{'Public Key(B)':>16}"

        f"{'Private Key(B)':>17}"

        f"{'Signature(B)':>15}"

    )


    print("-" * 115)


    for row in summary_rows[2:]:


        print(

            f"{row['algorithm']:<20}"

            f"{row['avg_keygen_ms']:>15.4f}"

            f"{row['avg_operation1_ms']:>15.4f}"

            f"{row['avg_operation2_ms']:>15.4f}"

            f"{row['public_key_bytes']:>16}"

            f"{row['private_key_bytes']:>17}"

            f"{row['ciphertext_or_signature_bytes']:>15}"

        )


    print("=" * 100)


    # ========================================================
    # EXPERIMENT TIME
    # ========================================================

    total_time = (

        time.perf_counter()

        -

        experiment_start

    )


    print(

        f"\nTotal Experiment Time : "

        f"{total_time:.2f} seconds"

    )


    print(

        f"\nDetailed Results : "

        f"{DETAILED_CSV}"

    )


    print(

        f"Summary Results  : "

        f"{SUMMARY_CSV}"

    )


    print(

        f"JSON Results     : "

        f"{SUMMARY_JSON}"

    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()