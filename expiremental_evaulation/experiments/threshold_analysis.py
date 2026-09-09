"""
experiments/threshold_analysis.py

Standalone threshold sweep analysis across FVC2002 DB1_B - DB4_B.

This script does NOT reimplement fingerprint matching. It reuses the
existing end-to-end verification pipeline (verification.e2e_verify.
run_verification), which internally performs preprocessing, template
extraction, ML-KEM decapsulation, AES-256-GCM decryption, SHA3-256
integrity check, ML-DSA-87 signature verification, and SourceAFIS
matching, and returns a VerificationResult containing `match_score`.

Design note on efficiency / no duplicated matching logic:
    run_verification() is called exactly ONCE per genuine/impostor image
    pair per dataset (same pairing strategy as verification/batch_verify.py:
    genuine = same user, impostor = cross-user, using each user's non-"_1"
    images as probes). The resulting match_score is then evaluated against
    every threshold in range(8, 21) purely by comparison (score >= threshold),
    with no re-invocation of verification and no re-implementation of the
    SourceAFIS matcher.

Do NOT modify any existing project files. This script is standalone.

Run with:
    python -m experiments.threshold_analysis
"""

import csv
import json
import time
from pathlib import Path

import config
from verification.e2e_verify import run_verification

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATASET_ROOT = Path("dataset")
DATASETS = ["DB1_B", "DB2_B", "DB3_B", "DB4_B"]
THRESHOLDS = list(range(8, 21))  # 8 .. 20 inclusive

TABLES_DIR = config.TABLES_DIR
RESULTS_DIR = config.RESULTS_DIR

CSV_OUT = TABLES_DIR / "threshold_analysis.csv"
JSON_OUT = TABLES_DIR / "threshold_analysis.json"


# ---------------------------------------------------------------------------
# Score collection (reuses run_verification, no matching logic duplicated)
# ---------------------------------------------------------------------------

def collect_scores(dataset_name: str):
    """
    Run the existing verification pipeline once per genuine/impostor pair
    for the given dataset and collect match scores.

    Pairing strategy mirrors verification/batch_verify.py:
        - genuine attempts: each user's probe images (excluding the "_1"
          enrollment reference) verified against that same user's ID.
        - impostor attempts: each user's probe images verified against
          every *other* user's ID.
    """
    dataset_dir = DATASET_ROOT / dataset_name

    if not dataset_dir.exists():
        print(f"[WARN] Dataset directory not found: {dataset_dir}")
        return [], []

    all_files = sorted(dataset_dir.glob("*.tif"))
    users = sorted({p.stem.split("_")[0] for p in all_files})

    genuine_scores = []
    impostor_scores = []

    for user in users:
        enrolled_images = sorted(dataset_dir.glob(f"{user}_*.tif"))
        genuine_imgs = [f for f in enrolled_images if not f.stem.endswith("_1")]

        # IMPORTANT: must match the exact user_id used during registration
        # (see experiments/register_dataset.py), which prefixes with the
        # dataset name to avoid ID collisions across DB1_B..DB4_B (FVC2002
        # reuses plain numeric IDs like "101" in every subset). Using the
        # bare "user" number here would look up whichever dataset's
        # template last overwrote that shared ID, causing near-total
        # genuine mismatches for every dataset except the one registered
        # last.
        user_id = f"{dataset_name.upper()}_{user}"

        # Genuine attempts
        for img in genuine_imgs:
            try:
                res = run_verification(str(img), user_id)
                genuine_scores.append(res.match_score)
            except Exception as e:
                print(f"[ERROR] Genuine {img.name}: {e}")

        # Impostor attempts
        impostors = [u for u in users if u != user]
        for imp_user in impostors:
            imp_user_id = f"{dataset_name.upper()}_{imp_user}"
            for img in genuine_imgs:
                try:
                    res = run_verification(str(img), imp_user_id)
                    impostor_scores.append(res.match_score)
                except Exception as e:
                    print(f"[ERROR] Impostor {img.name} -> {imp_user_id}: {e}")

    return genuine_scores, impostor_scores


# ---------------------------------------------------------------------------
# Threshold evaluation (pure comparison against already-computed scores)
# ---------------------------------------------------------------------------

def evaluate_threshold(genuine_scores, impostor_scores, threshold):
    n_gen = len(genuine_scores)
    n_imp = len(impostor_scores)

    true_accept = sum(1 for s in genuine_scores if s >= threshold)
    false_reject = n_gen - true_accept

    false_accept = sum(1 for s in impostor_scores if s >= threshold)
    true_reject = n_imp - false_accept

    far = (false_accept / n_imp) if n_imp > 0 else 0.0
    frr = (false_reject / n_gen) if n_gen > 0 else 0.0
    accuracy = ((true_accept + true_reject) / (n_gen + n_imp)) if (n_gen + n_imp) > 0 else 0.0

    return {
        "true_accept": true_accept,
        "false_accept": false_accept,
        "true_reject": true_reject,
        "false_reject": false_reject,
        "far": far,
        "frr": frr,
        "accuracy": accuracy,
    }


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def run_threshold_analysis():
    start_time = time.perf_counter()

    print("=" * 60)
    print("THRESHOLD ANALYSIS")
    print("=" * 60)

    all_results = []
    best_per_dataset = {}

    for dataset_name in DATASETS:
        print(f"\n{dataset_name.upper()}\n")

        genuine_scores, impostor_scores = collect_scores(dataset_name)

        best_result = None

        for threshold in THRESHOLDS:
            result = evaluate_threshold(genuine_scores, impostor_scores, threshold)

            result["dataset"] = dataset_name.upper()
            result["threshold"] = threshold

            all_results.append(result)

            print(
                f"Threshold {threshold:2d}  "
                f"Accuracy={result['accuracy']*100:.2f}% "
                f"FAR={result['far']*100:.2f}% "
                f"FRR={result['frr']*100:.2f}%"
            )
            print(f"{dataset_name.upper()} Threshold {threshold} completed")

            if best_result is None or result["accuracy"] > best_result["accuracy"]:
                best_result = result

        best_per_dataset[dataset_name.upper()] = best_result

        print("\nBest Threshold")
        print("-" * 28)
        print(f"Dataset   : {dataset_name.upper()}")
        print(f"Threshold : {best_result['threshold']}")
        print(f"Accuracy  : {best_result['accuracy']*100:.2f}%")
        print(f"FAR       : {best_result['far']*100:.2f}%")
        print(f"FRR       : {best_result['frr']*100:.2f}%")

    # -----------------------------------------------------------------
    # Best common threshold across all datasets (highest average accuracy)
    # -----------------------------------------------------------------
    avg_accuracy_by_threshold = {}
    for threshold in THRESHOLDS:
        accs = [r["accuracy"] for r in all_results if r["threshold"] == threshold]
        avg_accuracy_by_threshold[threshold] = sum(accs) / len(accs) if accs else 0.0

    best_common_threshold = max(avg_accuracy_by_threshold, key=avg_accuracy_by_threshold.get)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for dataset_name in DATASETS:
        best = best_per_dataset[dataset_name.upper()]
        print(
            f"Best threshold for {dataset_name.upper()}: {best['threshold']} "
            f"(Accuracy = {best['accuracy']*100:.2f}%)"
        )

    print(
        f"\nBest common threshold across all datasets: {best_common_threshold} "
        f"(Avg Accuracy = {avg_accuracy_by_threshold[best_common_threshold]*100:.2f}%)"
    )

    # -----------------------------------------------------------------
    # Save CSV
    # -----------------------------------------------------------------
    fieldnames = [
        "dataset",
        "threshold",
        "true_accept",
        "false_accept",
        "true_reject",
        "false_reject",
        "far",
        "frr",
        "accuracy",
    ]

    CSV_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(CSV_OUT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_results:
            writer.writerow({k: row[k] for k in fieldnames})

    print(f"\nCSV saved to  : {CSV_OUT}")

    # -----------------------------------------------------------------
    # Save JSON
    # -----------------------------------------------------------------
    with open(JSON_OUT, "w") as f:
        json.dump(
            {
                "results": all_results,
                "best_per_dataset": best_per_dataset,
                "best_common_threshold": best_common_threshold,
                "avg_accuracy_by_threshold": avg_accuracy_by_threshold,
            },
            f,
            indent=4,
        )

    print(f"JSON saved to : {JSON_OUT}")

    total_time = time.perf_counter() - start_time
    print(f"\nTotal analysis time: {total_time:.2f} sec")
    print("=" * 60)

    return all_results


if __name__ == "__main__":
    run_threshold_analysis()