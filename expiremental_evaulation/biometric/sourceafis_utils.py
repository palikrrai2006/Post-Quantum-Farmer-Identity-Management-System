import shutil
import subprocess
import time
from pathlib import Path

from config import (
    SOURCEAFIS_JAVA_DIR,
    MAVEN_CMD,
    PREPROCESSED_REG_DIR,
    RAW_TEMPLATES_DIR,
    USE_GABOR,
)
from preprocessing.preprocessing import preprocess_fingerprint


def _safe_stem(path_str: str) -> str:
    return Path(path_str).stem


# ============================================================
# TEMPLATE EXTRACTION
# ============================================================

def extract_fingerprint_template(image_path: str):
    """
    Preprocess fingerprint image and extract SourceAFIS template.

    Returns:
        {
            "template_path": str,
            "template_size_bytes": int,
            "preprocessed_image": str,
            "metrics": {
                "preprocessing_time_ms": float,
                "template_extraction_time_ms": float
            },
            "raw_output": str
        }
    """

    # -------------------------------------------------
    # 1) Preprocess image
    # -------------------------------------------------
    pre_path = PREPROCESSED_REG_DIR / f"{_safe_stem(image_path)}_pre.png"
    pre_result = preprocess_fingerprint(image_path, str(pre_path), use_gabor=USE_GABOR)
    preprocessing_time_ms = pre_result["metrics"]["preprocessing_time_ms"]

    # -------------------------------------------------
    # 2) Copy preprocessed image into Java folder
    # -------------------------------------------------
    java_input = SOURCEAFIS_JAVA_DIR / "extract_input.png"
    shutil.copy2(pre_path, java_input)

    # -------------------------------------------------
    # 3) Define template output path
    # -------------------------------------------------
    template_out = RAW_TEMPLATES_DIR / f"{_safe_stem(image_path)}_template.txt"

    # We also pass a simple output filename to Java to avoid Windows path issues
    java_template_out = SOURCEAFIS_JAVA_DIR / "template_output.txt"

    # -------------------------------------------------
    # 4) Run Java extract mode
    # -------------------------------------------------
    start = time.perf_counter()

    cmd = [
        MAVEN_CMD,
        "exec:java",
        '-Dexec.args=extract extract_input.png template_output.txt'
    ]

    completed = subprocess.run(
        cmd,
        cwd=str(SOURCEAFIS_JAVA_DIR),
        capture_output=True,
        text=True,
        shell=False
    )

    end = time.perf_counter()
    template_extraction_time_ms = round((end - start) * 1000, 4)

    raw_output = (completed.stdout or "").strip()
    raw_error = (completed.stderr or "").strip()
    combined_output = "\n".join([raw_output, raw_error]).strip()

    if completed.returncode != 0:
        raise RuntimeError(
            f"Java SourceAFIS template extraction failed.\n\nSTDOUT:\n{raw_output}\n\nSTDERR:\n{raw_error}"
        )

    # -------------------------------------------------
    # 5) Move generated template into project template folder
    # -------------------------------------------------
    if not java_template_out.exists():
        raise FileNotFoundError(
            f"Expected template output not found: {java_template_out}\nJava output:\n{combined_output}"
        )

    shutil.copy2(java_template_out, template_out)

    template_size_bytes = template_out.stat().st_size

    return {
        "template_path": str(template_out),
        "template_size_bytes": template_size_bytes,
        "preprocessed_image": str(pre_path),
        "metrics": {
            "preprocessing_time_ms": round(preprocessing_time_ms, 4),
            "template_extraction_time_ms": template_extraction_time_ms,
        },
        "raw_output": combined_output
    }


# ============================================================
# MATCHING
# ============================================================

def match_fingerprints(image1_path: str, image2_path: str):
    """
    Preprocess two fingerprint images and call Java SourceAFIS matcher.

    Returns:
        {
            "score": float,
            "preprocessed_image1": str,
            "preprocessed_image2": str,
            "metrics": {
                "preprocessing_time_ms": float,
                "matching_time_ms": float
            },
            "raw_output": str
        }
    """

    # -------------------------------------------------
    # 1) Preprocess image 1
    # -------------------------------------------------
    pre1 = PREPROCESSED_REG_DIR / f"{_safe_stem(image1_path)}_pre.png"
    r1 = preprocess_fingerprint(image1_path, str(pre1), use_gabor=USE_GABOR)

    # -------------------------------------------------
    # 2) Preprocess image 2
    # -------------------------------------------------
    pre2 = PREPROCESSED_REG_DIR / f"{_safe_stem(image2_path)}_pre.png"
    r2 = preprocess_fingerprint(image2_path, str(pre2), use_gabor=USE_GABOR)

    preprocessing_time_ms = (
        r1["metrics"]["preprocessing_time_ms"] +
        r2["metrics"]["preprocessing_time_ms"]
    )

    # -------------------------------------------------
    # 3) Copy files into Java folder with simple names
    # -------------------------------------------------
    java_probe = SOURCEAFIS_JAVA_DIR / "probe.png"
    java_candidate = SOURCEAFIS_JAVA_DIR / "candidate.png"

    shutil.copy2(pre1, java_probe)
    shutil.copy2(pre2, java_candidate)

    # -------------------------------------------------
    # 4) Run Java SourceAFIS matcher
    # -------------------------------------------------
    start = time.perf_counter()

    cmd = [
        MAVEN_CMD,
        "exec:java",
        '-Dexec.args=match probe.png candidate.png'
    ]

    completed = subprocess.run(
        cmd,
        cwd=str(SOURCEAFIS_JAVA_DIR),
        capture_output=True,
        text=True,
        shell=False
    )

    end = time.perf_counter()
    matching_time_ms = round((end - start) * 1000, 4)

    raw_output = (completed.stdout or "").strip()
    raw_error = (completed.stderr or "").strip()
    combined_output = "\n".join([raw_output, raw_error]).strip()

    if completed.returncode != 0:
        raise RuntimeError(
            f"Java SourceAFIS match failed.\n\nSTDOUT:\n{raw_output}\n\nSTDERR:\n{raw_error}"
        )

    # -------------------------------------------------
    # 5) Parse score from output
    # -------------------------------------------------
    lines = [line.strip() for line in combined_output.splitlines() if line.strip()]

    score = None
    for line in reversed(lines):
        try:
            score = float(line)
            break
        except ValueError:
            continue

    if score is None:
        raise ValueError(
            f"Could not parse SourceAFIS score from output:\n{combined_output}"
        )

    return {
        "score": score,
        "preprocessed_image1": str(pre1),
        "preprocessed_image2": str(pre2),
        "metrics": {
            "preprocessing_time_ms": round(preprocessing_time_ms, 4),
            "matching_time_ms": matching_time_ms
        },
        "raw_output": combined_output
    }


# ============================================================
# TEST DRIVER
# ============================================================

if __name__ == "__main__":
    print("Choose mode:")
    print("1. extract")
    print("2. match")
    choice = input("Enter choice (1/2): ").strip()

    if choice == "1":
        img = input("Enter fingerprint image path: ").strip()
        result = extract_fingerprint_template(img)
        print("\n=== TEMPLATE EXTRACTION RESULT ===")
        print(result)

    elif choice == "2":
        img1 = input("Enter first fingerprint image path: ").strip()
        img2 = input("Enter second fingerprint image path: ").strip()
        result = match_fingerprints(img1, img2)
        print("\n=== SOURCEAFIS MATCH RESULT ===")
        print(result)

    else:
        print("Invalid choice.")