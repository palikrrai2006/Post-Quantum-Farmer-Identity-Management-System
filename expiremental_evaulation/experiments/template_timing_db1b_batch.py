import csv
import json
from pathlib import Path
from statistics import mean

from biometric.sourceafis_utils import extract_fingerprint_template
from config import TABLES_DIR

# ============================================================
# CONFIG
# ============================================================

DATASET_NAME = "DB1B"
DATASET_DIR = Path(r"C:\Users\palikrrai\Desktop\MAJOR PROJECT\dataset\DB1_B")
VALID_EXTS = {".tif", ".tiff", ".bmp", ".png", ".jpg", ".jpeg"}

BATCH_SIZES = [10, 20, 30, 40, 50]


# ============================================================
# COLLECT IMAGE FILES
# ============================================================

def collect_images(dataset_dir: Path):
    if not dataset_dir.exists():
        raise FileNotFoundError(f"Dataset folder not found: {dataset_dir}")

    files = []
    for p in sorted(dataset_dir.iterdir()):
        if p.is_file() and p.suffix.lower() in VALID_EXTS:
            files.append(p)

    if not files:
        raise RuntimeError(f"No fingerprint images found in: {dataset_dir}")

    return files


# ============================================================
# MAIN
# ============================================================

def run_template_timing_db1b_batch():
    TABLES_DIR.mkdir(parents=True, exist_ok=True)

    all_images = collect_images(DATASET_DIR)

    max_required = max(BATCH_SIZES)
    if len(all_images) < max_required:
        raise RuntimeError(
            f"Dataset has only {len(all_images)} images, but batch size {max_required} requested."
        )

    summary_rows = []
    detail_rows = []

    print(f"[INFO] Running DB1_B batch timing evaluation")
    print(f"[INFO] Dataset folder: {DATASET_DIR}")
    print(f"[INFO] Batch sizes: {BATCH_SIZES}")

    for batch_size in BATCH_SIZES:
        print("\n" + "=" * 60)
        print(f"[INFO] Processing batch size = {batch_size}")
        print("=" * 60)

        selected_images = all_images[:batch_size]

        preprocessing_times = []
        extraction_times = []
        template_sizes = []

        for idx, img_path in enumerate(selected_images, start=1):
            print(f"[INFO] [{idx}/{batch_size}] Processing: {img_path.name}")

            result = extract_fingerprint_template(str(img_path))

            pre_ms = result["metrics"]["preprocessing_time_ms"]
            ext_ms = result["metrics"]["template_extraction_time_ms"]
            size_b = result["template_size_bytes"]

            preprocessing_times.append(pre_ms)
            extraction_times.append(ext_ms)
            template_sizes.append(size_b)

            detail_rows.append({
                "batch_size": batch_size,
                "image_name": img_path.name,
                "preprocessing_time_ms": round(pre_ms, 4),
                "template_extraction_time_ms": round(ext_ms, 4),
                "template_size_bytes": size_b,
                "template_path": result["template_path"],
            })

        summary = {
            "dataset": DATASET_NAME,
            "batch_size": batch_size,
            "avg_preprocessing_time_ms": round(mean(preprocessing_times), 4),
            "avg_template_extraction_time_ms": round(mean(extraction_times), 4),
            "avg_template_size_bytes": round(mean(template_sizes), 2),
            "min_preprocessing_time_ms": round(min(preprocessing_times), 4),
            "max_preprocessing_time_ms": round(max(preprocessing_times), 4),
            "min_template_extraction_time_ms": round(min(extraction_times), 4),
            "max_template_extraction_time_ms": round(max(extraction_times), 4),
            "min_template_size_bytes": min(template_sizes),
            "max_template_size_bytes": max(template_sizes),
        }

        summary_rows.append(summary)

    # --------------------------------------------------------
    # SAVE FILES
    # --------------------------------------------------------
    summary_csv = TABLES_DIR / "template_timing_db1b_batch_summary.csv"
    summary_json = TABLES_DIR / "template_timing_db1b_batch_summary.json"
    details_csv = TABLES_DIR / "template_timing_db1b_batch_details.csv"

    summary_fields = [
        "dataset",
        "batch_size",
        "avg_preprocessing_time_ms",
        "avg_template_extraction_time_ms",
        "avg_template_size_bytes",
        "min_preprocessing_time_ms",
        "max_preprocessing_time_ms",
        "min_template_extraction_time_ms",
        "max_template_extraction_time_ms",
        "min_template_size_bytes",
        "max_template_size_bytes",
    ]

    with open(summary_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=summary_fields)
        writer.writeheader()
        writer.writerows(summary_rows)

    with open(summary_json, "w", encoding="utf-8") as f:
        json.dump(summary_rows, f, indent=4)

    detail_fields = [
        "batch_size",
        "image_name",
        "preprocessing_time_ms",
        "template_extraction_time_ms",
        "template_size_bytes",
        "template_path",
    ]

    with open(details_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=detail_fields)
        writer.writeheader()
        writer.writerows(detail_rows)

    # --------------------------------------------------------
    # PRINT SUMMARY
    # --------------------------------------------------------
    print("\n====================================================")
    print("DB1_B BATCH TEMPLATE TIMING SUMMARY")
    print("====================================================")
    for row in summary_rows:
        print(json.dumps(row, indent=4))

    print("\nSaved:")
    print(f"  Summary CSV  : {summary_csv}")
    print(f"  Summary JSON : {summary_json}")
    print(f"  Details CSV  : {details_csv}")


if __name__ == "__main__":
    run_template_timing_db1b_batch()