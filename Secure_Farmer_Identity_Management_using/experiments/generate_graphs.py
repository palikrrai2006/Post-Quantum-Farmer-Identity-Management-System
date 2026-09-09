"""
experiments/generate_graphs.py
================================
Reads the CSVs produced by the other experiment scripts and renders the
required graphs (spec section 37) into results/graphs/. Skips a graph
gracefully (prints why) if its source CSV has no usable rows yet — e.g.
before you've run a dataset-backed experiment.

Run (after running the other experiments at least once):
    python -m experiments.generate_graphs
"""

import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import config


def _read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def plot_threshold_curves():
    rows = [r for r in _read_csv(os.path.join(config.RESULTS_TABLES_DIR, "threshold_results.csv")) if r.get("far")]
    if not rows:
        print("Skipping threshold graphs — no usable rows in threshold_results.csv yet.")
        return

    thresholds = [float(r["threshold"]) for r in rows]
    far = [float(r["far"]) for r in rows]
    frr = [float(r["frr"]) for r in rows]
    accuracy = [float(r["accuracy"]) for r in rows]

    plt.figure()
    plt.plot(thresholds, far, marker="o", label="FAR")
    plt.plot(thresholds, frr, marker="o", label="FRR")
    plt.xlabel("SourceAFIS Threshold")
    plt.ylabel("Rate")
    plt.title("FAR / FRR vs Threshold")
    plt.legend()
    plt.grid(True)
    plt.savefig(os.path.join(config.RESULTS_GRAPHS_DIR, "far_frr_vs_threshold.png"))
    plt.close()

    plt.figure()
    plt.plot(thresholds, accuracy, marker="o", color="green")
    plt.xlabel("SourceAFIS Threshold")
    plt.ylabel("Accuracy")
    plt.title("Accuracy vs Threshold")
    plt.grid(True)
    plt.savefig(os.path.join(config.RESULTS_GRAPHS_DIR, "accuracy_vs_threshold.png"))
    plt.close()
    print("Wrote far_frr_vs_threshold.png and accuracy_vs_threshold.png")


def plot_dataset_accuracy():
    rows = [r for r in _read_csv(os.path.join(config.RESULTS_TABLES_DIR, "biometric_results.csv")) if r.get("accuracy")]
    if not rows:
        print("Skipping dataset-wise accuracy graph — no usable rows in biometric_results.csv yet.")
        return

    datasets = [r["dataset"] for r in rows]
    accuracy = [float(r["accuracy"]) for r in rows]

    plt.figure()
    plt.bar(datasets, accuracy, color="steelblue")
    plt.ylabel("Accuracy")
    plt.title("Dataset-wise Accuracy")
    plt.savefig(os.path.join(config.RESULTS_GRAPHS_DIR, "dataset_accuracy.png"))
    plt.close()
    print("Wrote dataset_accuracy.png")


def plot_crypto_timing():
    rows = [r for r in _read_csv(os.path.join(config.RESULTS_TABLES_DIR, "crypto_results.csv")) if r.get("mean_ns")]
    if not rows:
        print("Skipping crypto timing graph — no usable rows in crypto_results.csv yet.")
        return

    labels = [f"{r['algorithm']}\n({r['operation']})" for r in rows]
    means = [float(r["mean_ns"]) / 1000 for r in rows]  # convert to microseconds

    plt.figure(figsize=(10, 5))
    plt.bar(labels, means, color="darkorange")
    plt.ylabel("Mean time (microseconds)")
    plt.title("Cryptographic Execution Time")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(config.RESULTS_GRAPHS_DIR, "crypto_execution_time.png"))
    plt.close()
    print("Wrote crypto_execution_time.png")


def plot_rsa_vs_pqc():
    rows = [r for r in _read_csv(os.path.join(config.RESULTS_TABLES_DIR, "rsa_pqc_results.csv")) if r.get("mean_ns")]
    if not rows:
        print("Skipping RSA vs PQC graph — no usable rows in rsa_pqc_results.csv yet.")
        return

    labels = [f"{r['algorithm']}\n({r['operation']})" for r in rows]
    means = [float(r["mean_ns"]) / 1e6 for r in rows]  # milliseconds

    plt.figure(figsize=(10, 5))
    plt.bar(labels, means, color="purple")
    plt.ylabel("Mean time (milliseconds)")
    plt.title("RSA vs PQC Execution Time")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(config.RESULTS_GRAPHS_DIR, "rsa_vs_pqc_time.png"))
    plt.close()
    print("Wrote rsa_vs_pqc_time.png")


if __name__ == "__main__":
    plot_threshold_curves()
    plot_dataset_accuracy()
    plot_crypto_timing()
    plot_rsa_vs_pqc()
