"""
experiments/threshold_evaluation.py
=====================================
Sweeps config.THRESHOLD_SWEEP (8-20) over a chosen dataset, computing
real FAR/FRR/GAR/Accuracy at each threshold using the same SourceAFIS
scores as biometric_evaluation.py (re-extracted once, matched at every
threshold — not re-running matching per threshold since the underlying
scores don't change, only the accept/reject cutoff does).

Run:
    python -m experiments.threshold_evaluation --dataset DB1_B
"""

import argparse
import csv
import os

import config
from experiments.biometric_evaluation import _index_dataset
from biometric import sourceafis_bridge, template_extraction


def sweep_dataset(dataset_name: str):
    dataset_dir = os.path.join(config.DATASET_DIR, dataset_name)
    if not os.path.isdir(dataset_dir):
        return {"error": f"Dataset directory not found: {dataset_dir}"}
    if not os.path.exists(config.SOURCEAFIS_BRIDGE_JAR):
        return {"error": "SourceAFIS bridge jar not built. See README."}

    subjects = _index_dataset(dataset_dir)
    if len(subjects) < 2:
        return {"error": f"Need at least 2 subjects, found {len(subjects)}."}

    templates = {}
    for subject_id, paths in subjects.items():
        templates[subject_id] = [template_extraction.extract_template_from_image(p)["template_bytes"] for p in paths]

    subject_ids = list(templates.keys())
    genuine_scores, impostor_scores = [], []

    for sid in subject_ids:
        temps = templates[sid]
        for i in range(len(temps)):
            for j in range(i + 1, len(temps)):
                genuine_scores.append(sourceafis_bridge.match_templates(temps[i], temps[j])["score"])

    for i in range(len(subject_ids)):
        for j in range(i + 1, len(subject_ids)):
            impostor_scores.append(sourceafis_bridge.match_templates(
                templates[subject_ids[i]][0], templates[subject_ids[j]][0])["score"])

    rows = []
    for threshold in config.THRESHOLD_SWEEP:
        ta = sum(1 for s in genuine_scores if s >= threshold)
        fr = len(genuine_scores) - ta
        fa = sum(1 for s in impostor_scores if s >= threshold)
        tr = len(impostor_scores) - fa

        far = fa / len(impostor_scores) if impostor_scores else 0.0
        frr = fr / len(genuine_scores) if genuine_scores else 0.0
        gar = ta / len(genuine_scores) if genuine_scores else 0.0
        accuracy = (ta + tr) / (len(genuine_scores) + len(impostor_scores)) if (genuine_scores or impostor_scores) else 0.0

        rows.append({"threshold": threshold, "far": far, "frr": frr, "gar": gar, "accuracy": accuracy})

    return {"dataset": dataset_name, "rows": rows,
            "genuine_pairs": len(genuine_scores), "impostor_pairs": len(impostor_scores)}


def run(dataset_name: str = "DB1_B"):
    result = sweep_dataset(dataset_name)
    out_path = os.path.join(config.RESULTS_TABLES_DIR, "threshold_results.csv")

    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["dataset", "threshold", "far", "frr", "gar", "accuracy", "error"])
        if "error" in result:
            writer.writerow([dataset_name, "", "", "", "", "", result["error"]])
        else:
            for r in result["rows"]:
                writer.writerow([dataset_name, r["threshold"], r["far"], r["frr"], r["gar"], r["accuracy"], ""])

    print(f"Wrote {out_path}")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="DB1_B")
    args = parser.parse_args()
    print(run(args.dataset))
