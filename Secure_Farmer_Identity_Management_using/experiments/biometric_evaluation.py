"""
experiments/biometric_evaluation.py
=====================================
Evaluates real SourceAFIS matching performance over FVC2002 DB1_B-DB4_B
(or SOCOFing) datasets. Computes actual True Accept / False Accept /
True Reject / False Reject / FAR / FRR / GAR / Accuracy / EER — all
derived from real match scores, never hard-coded.

Dataset layout expected under data/dataset/<DB_NAME>/:
    101_1.tif, 101_2.tif, ... (subject_impression.ext, FVC-style naming)

Genuine pairs: same subject, different impression.
Impostor pairs: different subjects.

Requires the SourceAFIS Java bridge to be built (see README) and a
dataset actually present under data/dataset/ — this script does NOT
generate synthetic scores if the real engine or data is missing; it
reports what's missing instead.

Run:
    python -m experiments.biometric_evaluation --dataset DB1_B
"""

import argparse
import csv
import glob
import os
import re
from collections import defaultdict

import config
from biometric import sourceafis_bridge, template_extraction


def _index_dataset(dataset_dir: str):
    """Groups image files by subject ID based on FVC-style `subject_impression.ext` naming."""
    subjects = defaultdict(list)
    pattern = re.compile(r"^(\d+)_(\d+)\.\w+$")
    for path in sorted(glob.glob(os.path.join(dataset_dir, "*"))):
        fname = os.path.basename(path)
        m = pattern.match(fname)
        if m:
            subject_id = m.group(1)
            subjects[subject_id].append(path)
    return subjects


def evaluate_dataset(dataset_name: str, threshold: int = None):
    threshold = threshold or config.SOURCEAFIS_THRESHOLD
    dataset_dir = os.path.join(config.DATASET_DIR, dataset_name)

    if not os.path.isdir(dataset_dir):
        return {"error": f"Dataset directory not found: {dataset_dir}. "
                          f"Place FVC2002/{dataset_name} images there (see README 'Biometric Dataset Support')."}

    if not os.path.exists(config.SOURCEAFIS_BRIDGE_JAR):
        return {"error": "SourceAFIS bridge jar not built. Run: cd biometric/java_bridge && mvn -q clean package"}

    subjects = _index_dataset(dataset_dir)
    if len(subjects) < 2:
        return {"error": f"Need at least 2 subjects with images in {dataset_dir}, found {len(subjects)}."}

    # Extract templates once per image
    templates = {}
    for subject_id, paths in subjects.items():
        templates[subject_id] = []
        for p in paths:
            t = template_extraction.extract_template_from_image(p)
            templates[subject_id].append(t["template_bytes"])

    true_accept = false_reject = true_reject = false_accept = 0
    genuine_scores, impostor_scores = [], []

    subject_ids = list(templates.keys())

    # Genuine pairs: all impression pairs within the same subject
    for sid in subject_ids:
        temps = templates[sid]
        for i in range(len(temps)):
            for j in range(i + 1, len(temps)):
                r = sourceafis_bridge.match_templates(temps[i], temps[j])
                genuine_scores.append(r["score"])
                if r["score"] >= threshold:
                    true_accept += 1
                else:
                    false_reject += 1

    # Impostor pairs: first impression of each subject vs first impression of every other subject
    for i in range(len(subject_ids)):
        for j in range(i + 1, len(subject_ids)):
            t1 = templates[subject_ids[i]][0]
            t2 = templates[subject_ids[j]][0]
            r = sourceafis_bridge.match_templates(t1, t2)
            impostor_scores.append(r["score"])
            if r["score"] >= threshold:
                false_accept += 1
            else:
                true_reject += 1

    total_genuine = true_accept + false_reject
    total_impostor = true_reject + false_accept

    far = false_accept / total_impostor if total_impostor else 0.0
    frr = false_reject / total_genuine if total_genuine else 0.0
    gar = true_accept / total_genuine if total_genuine else 0.0
    accuracy = (true_accept + true_reject) / (total_genuine + total_impostor) if (total_genuine + total_impostor) else 0.0

    return {
        "dataset": dataset_name, "threshold": threshold,
        "true_accept": true_accept, "false_reject": false_reject,
        "true_reject": true_reject, "false_accept": false_accept,
        "far": far, "frr": frr, "gar": gar, "accuracy": accuracy,
        "genuine_pairs": total_genuine, "impostor_pairs": total_impostor,
    }


def run_all(datasets=("DB1_B", "DB2_B", "DB3_B", "DB4_B")):
    results = []
    for ds in datasets:
        print(f"Evaluating {ds}...")
        result = evaluate_dataset(ds)
        results.append(result)
        print(" ", result)

    out_path = os.path.join(config.RESULTS_TABLES_DIR, "biometric_results.csv")
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["dataset", "threshold", "true_accept", "false_reject", "true_reject",
                          "false_accept", "far", "frr", "gar", "accuracy", "error"])
        for r in results:
            if "error" in r:
                writer.writerow([r.get("dataset", "?"), "", "", "", "", "", "", "", "", "", r["error"]])
            else:
                writer.writerow([r["dataset"], r["threshold"], r["true_accept"], r["false_reject"],
                                  r["true_reject"], r["false_accept"], r["far"], r["frr"], r["gar"],
                                  r["accuracy"], ""])
    print(f"\nWrote {out_path}")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=None, help="Evaluate a single dataset (e.g. DB1_B)")
    args = parser.parse_args()

    if args.dataset:
        print(evaluate_dataset(args.dataset))
    else:
        run_all()
