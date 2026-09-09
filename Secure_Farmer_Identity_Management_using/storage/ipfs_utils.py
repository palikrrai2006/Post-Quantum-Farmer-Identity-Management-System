"""
storage/ipfs_utils.py
======================
Client for a LOCAL Kubo IPFS node's HTTP API (default http://127.0.0.1:5001).

This talks to a real IPFS daemon over HTTP — there is no simulation here.
If the daemon is not running, every call below will raise a connection
error (see health_check()), which is the correct behavior: we must never
fabricate a CID.

Requires: `ipfs daemon` running (see README "IPFS Setup"), and:
    pip install requests
"""

import json
import time
from typing import Dict, Any

import requests

import config


class IPFSUnavailableError(RuntimeError):
    pass


def health_check() -> Dict[str, Any]:
    """
    Calls /api/v0/id. Raises IPFSUnavailableError if the daemon isn't reachable —
    callers must surface this as "IPFS unavailable", never silently continue.
    """
    try:
        resp = requests.post(f"{config.IPFS_API_BASE_URL}/id", timeout=config.IPFS_TIMEOUT_SECONDS)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        raise IPFSUnavailableError(
            f"Could not reach IPFS daemon at {config.IPFS_API_BASE_URL}. "
            f"Is `ipfs daemon` running? Original error: {e}"
        )


def get_node_information() -> Dict[str, Any]:
    """Alias — same underlying call, kept for spec-required function name."""
    return health_check()


def upload_package(package: Dict[str, Any]) -> Dict[str, Any]:
    """
    Upload a JSON-serializable secure package to IPFS via /api/v0/add.

    Returns: {"cid": str, "size_bytes": int, "upload_time_ns": int}
    """
    payload_bytes = json.dumps(package, sort_keys=True).encode("utf-8")
    files = {"file": ("package.json", payload_bytes)}

    start = time.perf_counter_ns()
    try:
        resp = requests.post(
            f"{config.IPFS_API_BASE_URL}/add",
            files=files,
            params={"pin": "true", "cid-version": "1"},
            timeout=config.IPFS_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise IPFSUnavailableError(f"IPFS upload failed: {e}")
    elapsed = time.perf_counter_ns() - start

    result = resp.json()
    return {
        "cid": result["Hash"],
        "size_bytes": len(payload_bytes),
        "upload_time_ns": elapsed,
    }


def download_package(cid: str) -> Dict[str, Any]:
    """
    Download and JSON-parse a package from IPFS via /api/v0/cat.

    Returns: {"package": dict, "size_bytes": int, "download_time_ns": int}
    """
    start = time.perf_counter_ns()
    try:
        resp = requests.post(
            f"{config.IPFS_API_BASE_URL}/cat",
            params={"arg": cid},
            timeout=config.IPFS_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise IPFSUnavailableError(f"IPFS download failed for CID {cid}: {e}")
    elapsed = time.perf_counter_ns() - start

    raw = resp.content
    package = json.loads(raw.decode("utf-8"))
    return {"package": package, "size_bytes": len(raw), "download_time_ns": elapsed}


def verify_download(cid: str, expected_integrity_hash: str) -> bool:
    """Downloads the package and checks its SHA3-256 integrity hash matches on-chain value."""
    from crypto import hashing  # local import to avoid a hard circular dependency at module load
    result = download_package(cid)
    recomputed = hashing.compute_package_integrity_hash(result["package"])
    return recomputed == expected_integrity_hash


if __name__ == "__main__":
    try:
        info = health_check()
        print("IPFS node reachable:", info)
    except IPFSUnavailableError as e:
        print(e)
        print("Start it with: ipfs init  (first time only)  then  ipfs daemon")
