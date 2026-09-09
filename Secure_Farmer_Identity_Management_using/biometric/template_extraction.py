"""
biometric/template_extraction.py
==================================
Combines OpenCV preprocessing + real SourceAFIS extraction into one call,
as required by the registration/verification pipelines.
"""

import os
import tempfile

from biometric import preprocessing, sourceafis_bridge


def extract_template_from_image(image_path: str) -> dict:
    """
    Full pipeline: raw image -> OpenCV preprocessing -> SourceAFIS template.

    Returns:
        {
          "template_bytes": bytes,
          "template_size_bytes": int,
          "preprocessing_time_ns": int,
          "extraction_time_ns": int,
        }
    """
    pre = preprocessing.preprocess_fingerprint(image_path)

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        preprocessing.save_processed_image(pre["processed_image"], tmp_path)
        extraction = sourceafis_bridge.extract_template(tmp_path)
    finally:
        os.remove(tmp_path)

    return {
        "template_bytes": extraction["template_bytes"],
        "template_size_bytes": extraction["template_size_bytes"],
        "preprocessing_time_ns": pre["preprocessing_time_ns"],
        "extraction_time_ns": extraction["extraction_time_ns"],
    }
