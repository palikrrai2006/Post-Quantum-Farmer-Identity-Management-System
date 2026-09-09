"""
storage/ipfs_utils.py

Production-ready Kubo (IPFS) Integration Utility for Post-Quantum Secure Fingerprint Authentication.
Provides full recursive directory handling, dynamic extraction detection, and IEEE-ready metrics.
"""

import hashlib
import json
import logging
import shutil
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Callable, Any
from functools import wraps

import requests
import config

try:
    from logging_utils import get_logger
    logger = get_logger(__name__)
except ImportError:
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers & Retries
# ---------------------------------------------------------------------------

def with_retries(retries: int = 3, delay: float = 1.0):
    """Decorator to retry IPFS API calls on transient network failures."""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_err = None
            for attempt in range(retries):
                try:
                    return func(*args, **kwargs)
                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                    last_err = e
                    time.sleep(delay * (attempt + 1))
            raise last_err
        return wrapper
    return decorator

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class IPFSUploadResult:
    cid: str
    upload_time_seconds: float
    upload_time_milliseconds: float
    package_size_bytes: int
    uploaded_files: List[str]
    success: bool

@dataclass
class IPFSDownloadResult:
    output_directory: Path
    download_time_seconds: float
    download_time_milliseconds: float
    downloaded_files: List[str]
    success: bool

# ---------------------------------------------------------------------------
# Core Utilities
# ---------------------------------------------------------------------------

def health_check() -> bool:
    """Verify daemon status and node identity."""
    try:
        response = requests.post(f"{config.IPFS_API_BASE_URL}/id", timeout=config.IPFS_TIMEOUT_SECONDS)
        response.raise_for_status()
        return "ID" in response.json()
    except requests.exceptions.RequestException:
        return False

def get_node_information() -> Dict[str, str]:
    """Retrieve node configuration, identity, and version info."""
    try:
        id_resp = requests.post(f"{config.IPFS_API_BASE_URL}/id", timeout=config.IPFS_TIMEOUT_SECONDS).json()
        ver_resp = requests.post(f"{config.IPFS_API_BASE_URL}/version", timeout=config.IPFS_TIMEOUT_SECONDS).json()
        return {
            "Peer ID": id_resp.get("ID"),
            "Version": ver_resp.get("Version"),
            "Gateway": config.IPFS_GATEWAY_BASE_URL,
            "API": config.IPFS_API_BASE_URL,
            "Repository Version": ver_resp.get("Repo")
        }
    except Exception as e:
        logger.error(f"Failed to get node info: {e}")
        raise

def calculate_package_size(folder_path: Path) -> int:
    """Calculate total size of all files recursively."""
    return sum(f.stat().st_size for f in Path(folder_path).rglob("*") if f.is_file())

def list_package_files(folder_path: Path) -> List[str]:
    """List all file names in the package recursively."""
    return [f.name for f in Path(folder_path).rglob("*") if f.is_file()]

# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------

@with_retries()
def upload_package(folder_path: Path) -> IPFSUploadResult:
    """Upload package recursively to Kubo via HTTP API."""
    folder_path = Path(folder_path)
    logger.info(f"Upload Started: {folder_path.resolve()}")
    
    t0 = time.perf_counter()
    files_payload = [('file', (f.name, f.read_bytes())) for f in folder_path.rglob("*") if f.is_file()]
    
    response = requests.post(
        f"{config.IPFS_API_BASE_URL}/add",
        params={'wrap-with-directory': 'true'},
        files=files_payload,
        timeout=config.IPFS_TIMEOUT_SECONDS
    )
    response.raise_for_status()
    
    root_cid = [json.loads(line) for line in response.text.strip().split('\n')][-1].get("Hash")
    
    t1 = time.perf_counter()
    duration = t1 - t0
    
    logger.info(f"CID Generated: {root_cid}")
    logger.info(f"Upload Finished ({duration*1000:.2f} ms)")
    
    return IPFSUploadResult(root_cid, duration, duration*1000, calculate_package_size(folder_path), list_package_files(folder_path), True)

@with_retries()
def download_package(cid: str, output_directory: Path) -> IPFSDownloadResult:
    """Download and extract package, detecting the extracted directory dynamically."""
    logger.info(f"Download Started: CID {cid}")
    output_directory = Path(output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)
    
    t0 = time.perf_counter()
    response = requests.post(f"{config.IPFS_API_BASE_URL}/get", params={'arg': cid}, stream=True, timeout=config.IPFS_TIMEOUT_SECONDS)
    response.raise_for_status()

    with tarfile.open(fileobj=response.raw, mode='r|*') as tar:
        tar.extractall(path=output_directory, filter='data')

    # Detect extracted directory dynamically
    extracted_dirs = [d for d in output_directory.iterdir() if d.is_dir()]
    if extracted_dirs:
        root_dir = extracted_dirs[0]
        for item in root_dir.iterdir():
            shutil.move(str(item), str(output_directory / item.name))
        root_dir.rmdir()
        
    t1 = time.perf_counter()
    duration = t1 - t0
    
    logger.info(f"Download Finished ({duration*1000:.2f} ms)")
    return IPFSDownloadResult(output_directory, duration, duration*1000, list_package_files(output_directory), True)

def verify_download(original_folder: Path, downloaded_folder: Path) -> bool:
    """Verify cryptographic integrity of the downloaded package."""
    orig_files = {f.name: f for f in Path(original_folder).rglob("*") if f.is_file()}
    dl_files = {f.name: f for f in Path(downloaded_folder).rglob("*") if f.is_file()}
    
    if set(orig_files.keys()) != set(dl_files.keys()):
        return False

    for name, orig_path in orig_files.items():
        dl_path = dl_files[name]
        if orig_path.stat().st_size != dl_path.stat().st_size:
            return False
        if hashlib.sha256(orig_path.read_bytes()).hexdigest() != hashlib.sha256(dl_path.read_bytes()).hexdigest():
            return False
            
    logger.info("Verification Passed")
    return True

def delete_download(output_directory: Path) -> None:
    """Safely delete a downloaded package directory."""
    if output_directory.exists() and output_directory.is_dir():
        shutil.rmtree(output_directory)
        logger.info(f"Deleted local download directory: {output_directory}")