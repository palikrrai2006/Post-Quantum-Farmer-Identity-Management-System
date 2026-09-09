import time
from pathlib import Path

import cv2

from config import (
    CLAHE_CLIP_LIMIT,
    CLAHE_TILE_GRID,
    MEDIAN_BLUR_KSIZE,
)

def preprocess_fingerprint(input_path: str, output_path: str, use_gabor: bool = False):
    """
    Preprocess fingerprint image using:
    - grayscale load
    - CLAHE
    - median blur

    Returns:
        {
            "output_path": str,
            "metrics": {
                "preprocessing_time_ms": float
            }
        }
    """
    start = time.perf_counter()

    input_path = Path(input_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    img = cv2.imread(str(input_path), cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise FileNotFoundError(f"Could not read fingerprint image: {input_path}")

    # CLAHE
    clahe = cv2.createCLAHE(
        clipLimit=CLAHE_CLIP_LIMIT,
        tileGridSize=CLAHE_TILE_GRID
    )
    enhanced = clahe.apply(img)

    # Light denoising
    if MEDIAN_BLUR_KSIZE and MEDIAN_BLUR_KSIZE > 1:
        enhanced = cv2.medianBlur(enhanced, MEDIAN_BLUR_KSIZE)

    # Optional Gabor placeholder (disabled for now)
    if use_gabor:
        pass

    cv2.imwrite(str(output_path), enhanced)

    end = time.perf_counter()
    return {
        "output_path": str(output_path),
        "metrics": {
            "preprocessing_time_ms": round((end - start) * 1000, 4)
        }
    }