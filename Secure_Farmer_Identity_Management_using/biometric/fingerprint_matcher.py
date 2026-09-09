"""
biometric/fingerprint_matcher.py
==================================
Applies config.SOURCEAFIS_THRESHOLD to a raw SourceAFIS match score.
Threshold lives ONLY in config.py — never hard-coded elsewhere (spec section 26).
"""

import config
from biometric import sourceafis_bridge


def match_fingerprints(template1_bytes: bytes, template2_bytes: bytes, threshold: int = None) -> dict:
    """
    Returns:
        {
          "score": float,
          "threshold": int,
          "match_time_ns": int,
          "authenticated": bool,
        }
    """
    threshold = config.SOURCEAFIS_THRESHOLD if threshold is None else threshold
    result = sourceafis_bridge.match_templates(template1_bytes, template2_bytes)
    authenticated = result["score"] >= threshold
    return {
        "score": result["score"],
        "threshold": threshold,
        "match_time_ns": result["match_time_ns"],
        "authenticated": authenticated,
    }
