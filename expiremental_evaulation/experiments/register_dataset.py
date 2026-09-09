"""
experiments/register_dataset.py

Standalone bulk registration script for FVC2002 DB1_B - DB4_B.

This script does NOT reimplement preprocessing, template extraction,
AES-256-GCM encryption, ML-KEM-1024 encapsulation, ML-DSA-87 signing,
SHA3-256 hashing, IPFS upload, or blockchain anchoring. It reuses your
existing single-user registration function.

>>> ACTION REQUIRED <<<
Replace the import below with the actual location/name of your existing
registration function (the enrollment counterpart to
verification.e2e_verify.run_verification). It is expected to accept
(image_path: str, user_id: str) and perform the full enrollment pipeline.

Example of what it likely looks like, based on your e2e_verify.py pattern:

    from registration.e2e_register import run_registration

or possibly:

    from registration.processor import register_user as run_registration

Update the import line marked below accordingly. No other part of this
script needs to change.

Do NOT modify any existing project files. This script is standalone.

Run with:
    python -m experiments.register_dataset
"""

from pathlib import Path

import config

# ---------------------------------------------------------------------------
# >>> ACTION REQUIRED: point this at your real registration function <<<
# It must accept (image_path: str, user_id: str) and perform the full
# enrollment pipeline (preprocess -> extract -> encrypt -> KEM -> sign ->
# store package / IPFS / blockchain), exactly like run_verification() does
# for the verification side.
# ---------------------------------------------------------------------------
from registration.e2e_reg import run_registration  # <-- CHANGE THIS LINE IF NEEDED


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATASET_ROOT = Path("dataset")
DATASETS = [""]

# Which image per user is the enrollment reference.
# batch_verify.py treats "_1" as the reference/enrollment image and uses
# every other image as a probe, so registration uses that same "_1" image.
ENROLLMENT_SUFFIX = "_1"


def get_enrollment_image(dataset_dir: Path, user: str) -> Path | None:
    """Return the "_1" reference image for a user, if present."""
    candidates = sorted(dataset_dir.glob(f"{user}{ENROLLMENT_SUFFIX}.tif"))
    return candidates[0] if candidates else None


def register_dataset(dataset_name: str):
    dataset_dir = DATASET_ROOT / dataset_name

    if not dataset_dir.exists():
        print(f"[WARN] Dataset directory not found: {dataset_dir}")
        return {"dataset": dataset_name.upper(), "registered": 0, "failed": 0, "skipped": 0}

    all_files = sorted(dataset_dir.glob("*.tif"))
    users = sorted({p.stem.split("_")[0] for p in all_files})

    registered = 0
    failed = 0
    skipped = 0

    print(f"\n{dataset_name.upper()} — {len(users)} users found\n")

    for user in users:
        # Give each user a dataset-qualified ID so the same numeric IDs
        # across DB1_B..DB4_B don't collide during enrollment.
        user_id = f"{dataset_name.upper()}_{user}"

        enrollment_img = get_enrollment_image(dataset_dir, user)
        if enrollment_img is None:
            print(f"[SKIP] {dataset_name.upper()} user {user}: no {ENROLLMENT_SUFFIX} image found")
            skipped += 1
            continue

        try:
            run_registration(str(enrollment_img), user_id)
            print(f"{dataset_name.upper()} user {user_id} registered")
            registered += 1
        except Exception as e:
            print(f"[ERROR] {dataset_name.upper()} user {user_id}: {e}")
            failed += 1

    return {
        "dataset": dataset_name.upper(),
        "registered": registered,
        "failed": failed,
        "skipped": skipped,
    }


def register_all_datasets():
    print("=" * 60)
    print("BULK REGISTRATION — FVC2002 DB1_B..DB4_B")
    print("=" * 60)

    summary = []
    for dataset_name in DATASETS:
        summary.append(register_dataset(dataset_name))

    print("\n" + "=" * 60)
    print("REGISTRATION SUMMARY")
    print("=" * 60)
    for s in summary:
        print(
            f"{s['dataset']}: registered={s['registered']} "
            f"failed={s['failed']} skipped={s['skipped']}"
        )
    print("=" * 60)

    return summary


if __name__ == "__main__":
    register_all_datasets()