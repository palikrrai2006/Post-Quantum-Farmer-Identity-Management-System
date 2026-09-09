import csv
import json
import random
import statistics
from collections import defaultdict
from itertools import combinations
from pathlib import Path

from biometric.sourceafis_utils import match_fingerprints
from config import (
    FVC_DB1_DIR,
    FVC_DB2_DIR,
    FVC_DB3_DIR,
    FVC_DB4_DIR,
    BIOMETRIC_LOGS_DIR,
    TABLES_DIR,
    MAX_GENUINE_PAIRS,
    MAX_IMPOSTOR_PAIRS,
)


# ============================================================
# SMALL HELPERS
# ============================================================

def mean_safe(values):
    return round(statistics.mean(values), 4) if values else 0.0


def std_safe(values):
    return round(statistics.pstdev(values), 4) if len(values) > 1 else 0.0


# ============================================================
# FVC DATASET GROUPING
# ============================================================

def build_fvc_groups(dataset_dir: Path):
    """
    Build groups for FVC files like:
        101_1.tif, 101_2.tif, ..., 110_8.tif

    Returns:
        {
            "101": [Path(...101_1.tif), ..., Path(...101_8.tif)],
            ...
        }
    """
    groups = defaultdict(list)

    for img_path in sorted(dataset_dir.glob("*.tif")):
        stem = img_path.stem  # e.g. 101_1
        parts = stem.split("_")
        if len(parts) != 2:
            continue

        finger_id = parts[0].strip()
        impression = parts[1].strip()

        if not finger_id.isdigit():
            continue
        if not impression.isdigit():
            continue

        groups[finger_id].append(img_path)

    # keep only IDs with at least 2 images
    clean_groups = {}
    for finger_id, imgs in groups.items():
        imgs = sorted(imgs)
        if len(imgs) >= 2:
            clean_groups[finger_id] = imgs

    return clean_groups


# ============================================================
# PAIR GENERATION
# ============================================================

def generate_all_genuine_pairs(groups):
    """
    Genuine pairs = all combinations of images within the same identity.

    For FVC:
        8 impressions per identity -> C(8,2) = 28 genuine pairs
        10 identities -> 280 genuine pairs total
    """
    genuine_pairs = []

    for finger_id, images in groups.items():
        for img1, img2 in combinations(images, 2):
            genuine_pairs.append(("genuine", finger_id, img1, img2))

    return genuine_pairs


def generate_impostor_pairs(groups, max_impostor_pairs=200, seed=42):
    """
    Generate impostor pairs from different identities.

    Strategy:
    - build a large pool by pairing images from different identities
    - randomly sample max_impostor_pairs from that pool
    """
    random.seed(seed)
    impostor_pool = []

    finger_ids = sorted(groups.keys())

    for id1, id2 in combinations(finger_ids, 2):
        imgs1 = groups[id1]
        imgs2 = groups[id2]

        for img1 in imgs1:
            for img2 in imgs2:
                impostor_pool.append(("impostor", f"{id1}_vs_{id2}", img1, img2))

    random.shuffle(impostor_pool)

    if max_impostor_pairs is None or max_impostor_pairs >= len(impostor_pool):
        return impostor_pool

    return impostor_pool[:max_impostor_pairs]


# ============================================================
# DATASET CHOICE
# ============================================================

def choose_dataset():
    print("Choose FVC dataset:")
    print("1. DB1_B")
    print("2. DB2_B")
    print("3. DB3_B")
    print("4. DB4_B")

    choice = input("Enter dataset (db1b/db2b/db3b/db4b): ").strip().lower()

    if choice == "db1b":
        return "db1b", FVC_DB1_DIR
    elif choice == "db2b":
        return "db2b", FVC_DB2_DIR
    elif choice == "db3b":
        return "db3b", FVC_DB3_DIR
    elif choice == "db4b":
        return "db4b", FVC_DB4_DIR
    else:
        raise ValueError("Invalid dataset choice. Use db1b / db2b / db3b / db4b.")


# ============================================================
# MAIN BIOMETRIC EVALUATION
# ============================================================

def run_biometric_evaluation():
    dataset_name, dataset_dir = choose_dataset()

    if not dataset_dir.exists():
        raise FileNotFoundError(f"Dataset directory not found: {dataset_dir}")

    print(f"[INFO] Dataset directory: {dataset_dir}")

    groups = build_fvc_groups(dataset_dir)

    if not groups:
        raise RuntimeError(f"No usable fingerprint groups found in dataset: {dataset_dir}")

    print(f"[INFO] Found {len(groups)} fingerprint IDs")

    # --------------------------------------------------------
    # 1) Genuine pairs
    # --------------------------------------------------------
    genuine_pairs = generate_all_genuine_pairs(groups)
    if MAX_GENUINE_PAIRS is not None:
        genuine_pairs = genuine_pairs[:MAX_GENUINE_PAIRS]

    # --------------------------------------------------------
    # 2) Impostor pairs
    # --------------------------------------------------------
    impostor_pairs = generate_impostor_pairs(
        groups,
        max_impostor_pairs=MAX_IMPOSTOR_PAIRS,
        seed=42
    )

    print(f"[INFO] Genuine pairs selected: {len(genuine_pairs)}")
    print(f"[INFO] Impostor pairs selected: {len(impostor_pairs)}")

    all_pairs = genuine_pairs + impostor_pairs

    results = []
    genuine_scores = []
    impostor_scores = []
    preprocessing_times = []
    matching_times = []

    total_pairs = len(all_pairs)

    # --------------------------------------------------------
    # 3) Run matching
    # --------------------------------------------------------
    for idx, (pair_type, pair_id, img1, img2) in enumerate(all_pairs, start=1):
        print(f"\n[{idx}/{total_pairs}] {pair_type.upper()} :: {img1.name} vs {img2.name}")

        try:
            result = match_fingerprints(str(img1), str(img2))
            score = float(result["score"])

            metrics = result.get("metrics", {})
            pre_ms = float(metrics.get("preprocessing_time_ms", 0.0))
            match_ms = float(metrics.get("matching_time_ms", 0.0))

            row = {
                "dataset": dataset_name,
                "pair_type": pair_type,
                "pair_id": pair_id,
                "image1": img1.name,
                "image2": img2.name,
                "score": round(score, 4),
                "preprocessing_time_ms": round(pre_ms, 4),
                "matching_time_ms": round(match_ms, 4),
            }
            results.append(row)

            preprocessing_times.append(pre_ms)
            matching_times.append(match_ms)

            if pair_type == "genuine":
                genuine_scores.append(score)
            else:
                impostor_scores.append(score)

            print(
                f"    score={score:.4f}, "
                f"pre_ms={pre_ms:.4f}, "
                f"match_ms={match_ms:.4f}"
            )

        except Exception as e:
            print(f"    [ERROR] Failed on {img1.name} vs {img2.name}: {e}")

    if not results:
        raise RuntimeError("No biometric results were produced.")

    # ========================================================
    # 4) SUMMARY
    # ========================================================
    summary = {
        "dataset_name": dataset_name,
        "dataset_dir": str(dataset_dir),
        "num_groups": len(groups),
        "num_genuine_pairs": len(genuine_scores),
        "num_impostor_pairs": len(impostor_scores),
        "genuine_score_stats": {
            "count": len(genuine_scores),
            "mean": mean_safe(genuine_scores),
            "min": round(min(genuine_scores), 4) if genuine_scores else 0.0,
            "max": round(max(genuine_scores), 4) if genuine_scores else 0.0,
            "std": std_safe(genuine_scores),
        },
        "impostor_score_stats": {
            "count": len(impostor_scores),
            "mean": mean_safe(impostor_scores),
            "min": round(min(impostor_scores), 4) if impostor_scores else 0.0,
            "max": round(max(impostor_scores), 4) if impostor_scores else 0.0,
            "std": std_safe(impostor_scores),
        },
        "matching_time_stats_ms": {
            "count": len(matching_times),
            "mean": mean_safe(matching_times),
            "min": round(min(matching_times), 4) if matching_times else 0.0,
            "max": round(max(matching_times), 4) if matching_times else 0.0,
            "std": std_safe(matching_times),
        },
        "preprocessing_time_stats_ms": {
            "count": len(preprocessing_times),
            "mean": mean_safe(preprocessing_times),
            "min": round(min(preprocessing_times), 4) if preprocessing_times else 0.0,
            "max": round(max(preprocessing_times), 4) if preprocessing_times else 0.0,
            "std": std_safe(preprocessing_times),
        },
    }

    # ========================================================
    # 5) SAVE FILES
    # ========================================================
    csv_path = BIOMETRIC_LOGS_DIR / f"biometric_results_{dataset_name}.csv"
    json_path = BIOMETRIC_LOGS_DIR / f"biometric_results_{dataset_name}.json"
    summary_path = TABLES_DIR / f"biometric_summary_{dataset_name}.json"

    fieldnames = [
        "dataset",
        "pair_type",
        "pair_id",
        "image1",
        "image2",
        "score",
        "preprocessing_time_ms",
        "matching_time_ms",
    ]

    # Save CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    # Save full JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "summary": summary,
                "results": results
            },
            f,
            indent=4
        )

    # Save summary JSON
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=4)

    # ========================================================
    # 6) PRINT SUMMARY
    # ========================================================
    print("\n================ BIOMETRIC SUMMARY ================")
    print(json.dumps(summary, indent=4))

    print("\nSaved:")
    print(f"  CSV   : {csv_path}")
    print(f"  JSON  : {json_path}")
    print(f"  TABLE : {summary_path}")


if __name__ == "__main__":
    run_biometric_evaluation()