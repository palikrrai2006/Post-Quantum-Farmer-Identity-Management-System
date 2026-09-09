"""
verification/batch_verify_socofing.py

SOCOFing End-to-End Verification Evaluation

Enrollment:
    SOCOFing/Real fingerprints are assumed to already be registered.
    Each real fingerprint uses its full filename stem as registration_id.

Genuine verification:
    An altered fingerprint is verified against its corresponding
    registered REAL fingerprint identity.

Impostor verification:
    The same altered fingerprint is verified against randomly selected
    different registered fingerprint identities.

Metrics:
    FAR
    FRR
    GAR
    HTER
    Accuracy
    EER
    EER Threshold
    Average cryptographic/matching timings
"""

import csv
import json
import random
import time
from pathlib import Path

import numpy as np

import config
from verification.e2e_verify import run_verification


# ============================================================
# CONFIGURATION
# ============================================================

SOCOFING_DIR = Path("dataset/SOCOFing")

REAL_DIR = SOCOFING_DIR / "Real"

ALTERED_DIRS = [
    SOCOFING_DIR / "Altered" / "Altered-Easy",
    SOCOFING_DIR / "Altered" / "Altered-Medium",
    SOCOFING_DIR / "Altered" / "Altered-Hard",
]

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

RESULTS_CSV = RESULTS_DIR / "socofing_verification_results.csv"
SUMMARY_JSON = RESULTS_DIR / "socofing_verification_summary.json"


MAX_IDENTITIES = 10
NUM_IMPOSTORS_PER_PROBE = 10
MAX_GENUINE_PROBES_PER_IDENTITY = 1

#MAX_IDENTITIES = 600


# ------------------------------------------------------------
# Number of randomly selected impostor identities tested
# against each genuine probe.
# ------------------------------------------------------------

#NUM_IMPOSTORS_PER_PROBE = 10


# ------------------------------------------------------------
# Maximum genuine altered images tested per identity.
#
# 1 = faster
# 3 = stronger evaluation but slower
# None = use every available altered image
# ------------------------------------------------------------

#MAX_GENUINE_PROBES_PER_IDENTITY = 1


# ------------------------------------------------------------
# Reproducible random sampling
# ------------------------------------------------------------

RANDOM_SEED = 42


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_images(directory):

    if not directory.exists():
        return []

    images = []

    for extension in [
        "*.BMP",
        "*.bmp",
        "*.PNG",
        "*.png",
        "*.TIF",
        "*.tif"
    ]:

        images.extend(
            directory.rglob(extension)
        )

    return sorted(
        list(dict.fromkeys(images))
    )


def get_real_identities():

    real_images = get_images(REAL_DIR)

    identities = {}

    for image in real_images:

        # Example:
        #
        # 1__M_Left_index_finger.BMP
        #
        # registration_id:
        # 1__M_Left_index_finger

        registration_id = image.stem

        identities[registration_id] = image

    return identities


def find_genuine_probes(registration_id):

    """
    Finds altered fingerprints corresponding to the
    registered REAL fingerprint.

    SOCOFing altered filenames usually contain the original
    identity information plus an alteration suffix.

    Example concept:

    REAL:
        1__M_Left_index_finger.BMP

    ALTERED:
        1__M_Left_index_finger_CR.BMP

    Therefore we search for altered filenames beginning
    with the real registration ID.
    """

    probes = []

    for altered_dir in ALTERED_DIRS:

        if not altered_dir.exists():
            continue

        for image in get_images(altered_dir):

            if image.stem.startswith(registration_id):

                probes.append(image)

    return probes


# ============================================================
# EER CALCULATION
# ============================================================

def calculate_eer(
    genuine_scores,
    impostor_scores
):

    if (
        not genuine_scores
        or not impostor_scores
    ):

        return 0.0, config.SOURCEAFIS_MATCH_THRESHOLD


    all_scores = (
        genuine_scores
        +
        impostor_scores
    )


    thresholds = np.linspace(
        min(all_scores),
        max(all_scores),
        1000
    )


    best_difference = float("inf")

    eer = 0.0

    eer_threshold = (
        config.SOURCEAFIS_MATCH_THRESHOLD
    )


    genuine_array = np.array(
        genuine_scores
    )

    impostor_array = np.array(
        impostor_scores
    )


    for threshold in thresholds:

        far = np.mean(
            impostor_array >= threshold
        )

        frr = np.mean(
            genuine_array < threshold
        )


        difference = abs(
            far - frr
        )


        if difference < best_difference:

            best_difference = difference

            eer = (
                far + frr
            ) / 2

            eer_threshold = threshold


    return (
        eer * 100,
        eer_threshold
    )


# ============================================================
# MAIN VERIFICATION
# ============================================================

def batch_verify():

    random.seed(
        RANDOM_SEED
    )


    batch_start = (
        time.perf_counter()
    )


    # ========================================================
    # LOAD REGISTERED IDENTITIES
    # ========================================================

    identities = (
        get_real_identities()
    )


    registration_ids = sorted(
        identities.keys()
    )


    if MAX_IDENTITIES is not None:

        registration_ids = (
            registration_ids[
                :MAX_IDENTITIES
            ]
        )


    print("\n")

    print("=" * 70)

    print(
        "SOCOFING POST-QUANTUM VERIFICATION EVALUATION"
    )

    print("=" * 70)

    print(
        f"Registered Identities Found : {len(identities)}"
    )

    print(
        f"Identities Evaluated        : {len(registration_ids)}"
    )

    print(
        f"Impostors Per Probe         : {NUM_IMPOSTORS_PER_PROBE}"
    )

    print(
        f"Fixed Threshold             : "
        f"{config.SOURCEAFIS_MATCH_THRESHOLD}"
    )

    print("=" * 70)


    # ========================================================
    # RESULT STORAGE
    # ========================================================

    genuine_scores = []

    impostor_scores = []

    rows = []


    genuine_attempts = 0

    impostor_attempts = 0

    genuine_errors = 0

    impostor_errors = 0

    identities_without_probe = 0


    # ========================================================
    # VERIFY IDENTITIES
    # ========================================================

    for index, registration_id in enumerate(
        registration_ids,
        start=1
    ):


        print(
            f"\n[{index}/{len(registration_ids)}] "
            f"{registration_id}"
        )


        # ====================================================
        # FIND GENUINE ALTERED PROBES
        # ====================================================

        genuine_probes = (
            find_genuine_probes(
                registration_id
            )
        )


        if not genuine_probes:

            print(
                "  No corresponding altered "
                "fingerprint found."
            )

            identities_without_probe += 1

            continue


        # ====================================================
        # LIMIT GENUINE PROBES
        # ====================================================

        if (
            MAX_GENUINE_PROBES_PER_IDENTITY
            is not None
        ):

            genuine_probes = (
                genuine_probes[
                    :MAX_GENUINE_PROBES_PER_IDENTITY
                ]
            )


        # ====================================================
        # PROCESS EACH GENUINE PROBE
        # ====================================================

        for probe in genuine_probes:


            # =================================================
            # GENUINE ATTEMPT
            # =================================================

            try:

                result = run_verification(
                    str(probe),
                    registration_id
                )


                genuine_scores.append(
                    result.match_score
                )


                genuine_attempts += 1


                row = {

                    "type":
                        "genuine",

                    "registration_id":
                        registration_id,

                    "probe_image":
                        probe.name,

                    "target_id":
                        registration_id,

                    **vars(result)

                }


                rows.append(
                    row
                )


                print(
                    f"  Genuine: "
                    f"{probe.name} "
                    f"Score={result.match_score:.2f}"
                )


            except Exception as error:

                genuine_errors += 1

                print(
                    f"  [ERROR] Genuine "
                    f"{probe.name}: {error}"
                )


            # =================================================
            # IMPOSTOR SELECTION
            # =================================================

            available_impostors = [

                identity

                for identity
                in registration_ids

                if identity != registration_id

            ]


            selected_impostors = (
                random.sample(

                    available_impostors,

                    min(
                        NUM_IMPOSTORS_PER_PROBE,
                        len(available_impostors)
                    )

                )
            )


            # =================================================
            # IMPOSTOR ATTEMPTS
            # =================================================

            for impostor_id in selected_impostors:

                try:

                    result = run_verification(
                        str(probe),
                        impostor_id
                    )


                    impostor_scores.append(
                        result.match_score
                    )


                    impostor_attempts += 1


                    row = {

                        "type":
                            "impostor",

                        "registration_id":
                            registration_id,

                        "probe_image":
                            probe.name,

                        "target_id":
                            impostor_id,

                        **vars(result)

                    }


                    rows.append(
                        row
                    )


                except Exception as error:

                    impostor_errors += 1

                    print(
                        f"  [ERROR] Impostor "
                        f"{probe.name} -> "
                        f"{impostor_id}: "
                        f"{error}"
                    )


        # ====================================================
        # PROGRESS
        # ====================================================

        elapsed = (
            time.perf_counter()
            -
            batch_start
        )


        total_attempts = (

            genuine_attempts
            +
            impostor_attempts

        )


        print(
            f"  Progress: "
            f"Genuine={genuine_attempts}, "
            f"Impostor={impostor_attempts}, "
            f"Total={total_attempts}, "
            f"Elapsed={elapsed:.2f}s"
        )


    # ========================================================
    # FIXED THRESHOLD METRICS
    # ========================================================

    threshold = (
        config.SOURCEAFIS_MATCH_THRESHOLD
    )


    true_accept = sum(

        1

        for score
        in genuine_scores

        if score >= threshold

    )


    false_reject = (

        len(genuine_scores)
        -
        true_accept

    )


    false_accept = sum(

        1

        for score
        in impostor_scores

        if score >= threshold

    )


    true_reject = (

        len(impostor_scores)
        -
        false_accept

    )


    n_genuine = len(
        genuine_scores
    )


    n_impostor = len(
        impostor_scores
    )


    # ========================================================
    # METRICS
    # ========================================================

    FAR = (

        false_accept
        /
        n_impostor
        *
        100

        if n_impostor > 0

        else 0.0

    )


    FRR = (

        false_reject
        /
        n_genuine
        *
        100

        if n_genuine > 0

        else 0.0

    )


    GAR = (

        true_accept
        /
        n_genuine
        *
        100

        if n_genuine > 0

        else 0.0

    )


    HTER = (

        (
            (
                false_accept
                /
                n_impostor
            )

            +

            (
                false_reject
                /
                n_genuine
            )
        )

        /
        2

        *
        100

        if (
            n_genuine > 0
            and
            n_impostor > 0
        )

        else 0.0

    )


    Accuracy = (

        (
            true_accept
            +
            true_reject
        )

        /

        (
            n_genuine
            +
            n_impostor
        )

        *

        100

        if (
            n_genuine
            +
            n_impostor
        ) > 0

        else 0.0

    )


    # ========================================================
    # EER
    # ========================================================

    eer, eer_threshold = (
        calculate_eer(

            genuine_scores,

            impostor_scores

        )
    )


    # ========================================================
    # TIMING AVERAGES
    # ========================================================

    def average(
        key,
        verification_type="genuine"
    ):

        values = [

            row[key]

            for row in rows

            if (
                row["type"]
                ==
                verification_type

                and

                key in row

                and

                isinstance(
                    row[key],
                    (int, float)
                )
            )

        ]


        return (

            sum(values)
            /
            len(values)

            if values

            else 0.0

        )


    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    execution_time = (

        time.perf_counter()
        -
        batch_start

    )


    total_successful_attempts = (

        n_genuine
        +
        n_impostor

    )


    summary = {

        "Threshold":
            threshold,

        "Identities_Evaluated":
            len(registration_ids),

        "Identities_Without_Genuine_Probe":
            identities_without_probe,

        "Genuine_Attempts":
            n_genuine,

        "Impostor_Attempts":
            n_impostor,

        "Genuine_Errors":
            genuine_errors,

        "Impostor_Errors":
            impostor_errors,

        "True_Accept":
            true_accept,

        "False_Reject":
            false_reject,

        "True_Reject":
            true_reject,

        "False_Accept":
            false_accept,

        "FAR":
            FAR,

        "FRR":
            FRR,

        "GAR":
            GAR,

        "HTER":
            HTER,

        "Accuracy":
            Accuracy,

        "EER":
            eer,

        "EER_Threshold":
            eer_threshold,

        "Avg_DSA_ms":
            average(
                "time_ms_dsa"
            ),

        "Avg_KEM_ms":
            average(
                "time_ms_kem"
            ),

        "Avg_AES_ms":
            average(
                "time_ms_aes"
            ),

        "Avg_Hash_ms":
            average(
                "time_ms_hash"
            ),

        "Avg_Match_ms":
            average(
                "time_ms_match"
            ),

        "Avg_Total_ms":
            average(
                "time_ms_total"
            ),

        "Execution_Time_sec":
            execution_time,

        "Throughput_verifications_per_sec":

            total_successful_attempts
            /
            execution_time

            if execution_time > 0

            else 0.0

    }


    # ========================================================
    # PRINT SUMMARY
    # ========================================================

    print("\n")

    print("=" * 70)

    print(
        "SOCOFING VERIFICATION SUMMARY"
    )

    print("=" * 70)


    for key, value in summary.items():

        if isinstance(
            value,
            float
        ):

            print(
                f"{key:40}: "
                f"{value:.4f}"
            )

        else:

            print(
                f"{key:40}: "
                f"{value}"
            )


    print("=" * 70)


    # ========================================================
    # SAVE JSON
    # ========================================================

    with open(
        SUMMARY_JSON,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            summary,
            file,
            indent=4
        )


    # ========================================================
    # SAVE CSV
    # ========================================================

    if rows:

        all_fields = set()

        for row in rows:

            all_fields.update(
                row.keys()
            )


        fieldnames = sorted(
            all_fields
        )


        with open(
            RESULTS_CSV,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(

                file,

                fieldnames=fieldnames,

                extrasaction="ignore"

            )


            writer.writeheader()

            writer.writerows(
                rows
            )


    print(
        f"\nCSV Saved  : {RESULTS_CSV}"
    )

    print(
        f"JSON Saved : {SUMMARY_JSON}"
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    batch_verify()