"""
biometric/preprocessing.py
===========================
OpenCV preprocessing for fingerprint images BEFORE they go to SourceAFIS.

IMPORTANT: This does NOT do fingerprint matching (that is SourceAFIS's job,
never OpenCV's — see project spec section 4/12). This only prepares the
image: grayscale, normalization, CLAHE contrast enhancement, mild denoising.
Preprocessing that would destroy minutiae (heavy blurring, binarization
that erases ridge detail) is deliberately avoided.

Requires: pip install opencv-python numpy
"""

import time
import cv2
import numpy as np


def preprocess_fingerprint(image_path: str) -> dict:
    """
    Load and preprocess a fingerprint image.

    Returns:
        {
          "processed_image": np.ndarray (grayscale, CLAHE-enhanced),
          "preprocessing_time_ns": int,
          "original_shape": tuple,
        }
    """
    start = time.perf_counter_ns()

    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise FileNotFoundError(f"Could not read image at {image_path}")
    original_shape = img.shape

    # Normalize to 0-255 full range
    normalized = cv2.normalize(img, None, alpha=0, beta=255, norm_type=cv2.NORM_MINMAX)

    # CLAHE: local contrast enhancement without destroying ridge minutiae
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(normalized)

    # Mild denoise — deliberately light (h is small) to avoid smearing ridges
    denoised = cv2.fastNlMeansDenoising(enhanced, h=7, templateWindowSize=7, searchWindowSize=21)

    elapsed = time.perf_counter_ns() - start

    return {
        "processed_image": denoised,
        "preprocessing_time_ns": elapsed,
        "original_shape": original_shape,
    }


def save_processed_image(processed_image: np.ndarray, output_path: str):
    cv2.imwrite(output_path, processed_image)


if __name__ == "__main__":
    # Self-test with a synthetic fingerprint-like image (real OpenCV ops, real timing) —
    # a real dataset image would be used in actual operation.
    import os
    synthetic = np.zeros((300, 300), dtype=np.uint8)
    for i in range(0, 300, 6):
        cv2.line(synthetic, (0, i), (300, i), 200, 1)
    noise = np.random.randint(0, 40, synthetic.shape, dtype=np.uint8)
    synthetic = cv2.add(synthetic, noise)

    tmp_path = "/tmp/_synthetic_fingerprint.png"
    cv2.imwrite(tmp_path, synthetic)

    result = preprocess_fingerprint(tmp_path)
    print("Original shape:", result["original_shape"])
    print("Preprocessing time (ns):", result["preprocessing_time_ns"])
    print("Processed image shape:", result["processed_image"].shape)
    assert result["processed_image"].shape == result["original_shape"]
    os.remove(tmp_path)
    print("SELF-TEST PASSED")
