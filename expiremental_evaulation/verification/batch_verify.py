import csv
from random import random
import time
import json
import numpy as np
from pathlib import Path
import config
from verification.e2e_verify import run_verification

DATASET_DIR = Path("dataset\DB4_B")
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

def batch_verify():
    batch_start = time.perf_counter()
    all_files = sorted(DATASET_DIR.glob("*.tif"))
    users = sorted({p.stem.split("_")[0] for p in all_files})
    
    genuine_scores = []
    impostor_scores = []
    rows = []

    print(f"Executing evaluation on {len(users)} users...")

    for user in users:
        enrolled_images = sorted(DATASET_DIR.glob(f"{user}_*.tif"))
        genuine_imgs = [f for f in enrolled_images if not f.stem.endswith("_1")]

        # Genuine Attempts
        for img in genuine_imgs:
            try:
                res = run_verification(str(img), user)
                genuine_scores.append(res.match_score)
                rows.append({"type": "genuine", **vars(res)})
            except Exception as e:
                print(f"[ERROR] Genuine {img.name}: {e}")

        # Impostor Attempts
       # Impostor Attempts
        impostors = [u for u in users if u != user]
        for imp_user in impostors:
            for img in genuine_imgs:
                try:
                    res = run_verification(str(img), imp_user)
                    impostor_scores.append(res.match_score)
                    rows.append({"type": "impostor", **vars(res)})
                except Exception as e:
                    print(f"[ERROR] Impostor {img.name} -> {imp_user}: {e}")
    # Robust EER Computation
    all_scores = genuine_scores + impostor_scores
    if all_scores:
        thresholds = np.linspace(min(all_scores), max(all_scores), 1000)
    else:
        thresholds = np.array([config.SOURCEAFIS_MATCH_THRESHOLD])
        
    best_diff = float("inf")
    eer = 0.0
    eer_threshold = config.SOURCEAFIS_MATCH_THRESHOLD
    
    for t in thresholds:
        far = np.mean(np.array(impostor_scores) >= t) if impostor_scores else 0.0
        frr = np.mean(np.array(genuine_scores) < t) if genuine_scores else 0.0
        diff = abs(far - frr)
        if diff < best_diff:
            best_diff = diff
            eer = (far + frr) / 2
            eer_threshold = t

    # Metrics at fixed config threshold
    t_fixed = config.SOURCEAFIS_MATCH_THRESHOLD
    ta = sum(1 for s in genuine_scores if s >= t_fixed)
    fr = len(genuine_scores) - ta
    fa = sum(1 for s in impostor_scores if s >= t_fixed)
    tr = len(impostor_scores) - fa

    n_gen = len(genuine_scores)
    n_imp = len(impostor_scores)
    
    # Timing Averages (Genuine Focus for Authentication Latency)
    def avg(key, v_type="genuine"): 
        vals = [r[key] for r in rows if key in r and r["type"] == v_type]
        return sum(vals) / len(vals) if vals else 0.0
    
    batch_time = time.perf_counter() - batch_start
    summary = {
        "Threshold": t_fixed,
        "Genuine_Attempts": n_gen, "Impostor_Attempts": n_imp,
        "True_Accept": ta, "False_Reject": fr, "True_Reject": tr, "False_Accept": fa,
        "FAR": (fa / n_imp * 100) if n_imp > 0 else 0.0,
        "FRR": (fr / n_gen * 100) if n_gen > 0 else 0.0,
        "GAR": (ta / n_gen * 100) if n_gen > 0 else 0.0,
        "HTER": (((fa / n_imp) + (fr / n_gen)) / 2 * 100) if (n_imp > 0 and n_gen > 0) else 0.0,
        "Accuracy": ((ta + tr) / (n_gen + n_imp) * 100) if (n_gen + n_imp) > 0 else 0.0,
        "EER": eer * 100, "EER_Threshold": eer_threshold,
        "Avg_DSA_ms": avg("time_ms_dsa"), "Avg_KEM_ms": avg("time_ms_kem"),
        "Avg_AES_ms": avg("time_ms_aes"), "Avg_Hash_ms": avg("time_ms_hash"),
        "Avg_Match_ms": avg("time_ms_match"), "Avg_Total_ms": avg("time_ms_total"),
        "Execution_Time_sec": batch_time,
        "Throughput_verifications_per_sec": len(rows) / batch_time if batch_time > 0 else 0.0
    }

    print("\n" + "="*60 + "\nVERIFICATION SUMMARY\n" + "="*60)
    for k, v in summary.items():
        if isinstance(v, float): print(f"{k:35}: {v:.4f}")
        else: print(f"{k:35}: {v}")
    print("="*60)

    with open(RESULTS_DIR / "summary_metrics.json", "w") as f:
        json.dump(summary, f, indent=4)
    if rows:
        with open(RESULTS_DIR / "detailed_results.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=sorted(rows[0].keys()))
            writer.writeheader(); writer.writerows(rows)

if __name__ == "__main__":
    batch_verify()