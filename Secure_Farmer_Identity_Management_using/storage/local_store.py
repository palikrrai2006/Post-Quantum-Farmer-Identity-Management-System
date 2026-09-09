"""
storage/local_store.py
========================
Manages per-farmer PQC keypairs on local disk under keys/<farmer_id>/.

Private keys (ML-KEM secret key, ML-DSA secret key) NEVER go into the
database, IPFS, or the blockchain (spec section 20). Public keys are not
sensitive but are kept alongside for convenience.

Production note (also stated in README): a real deployment should use an
HSM/KMS/hardware-backed vault instead of plain files. This is a prototype
key store only.
"""

import os
import stat

import config


def _farmer_key_dir(farmer_id: str) -> str:
    path = os.path.join(config.KEYSTORE_PATH, farmer_id)
    os.makedirs(path, exist_ok=True)
    return path


def _restrict_permissions(path: str):
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600 — owner read/write only
    except (OSError, NotImplementedError):
        pass  # best-effort; not all platforms (e.g. some Windows setups) support POSIX modes


def save_keypairs(farmer_id: str, kem_public_key: bytes, kem_secret_key: bytes,
                   dsa_public_key: bytes, dsa_secret_key: bytes):
    d = _farmer_key_dir(farmer_id)
    files = {
        "kem_public.key": kem_public_key,
        "kem_secret.key": kem_secret_key,
        "dsa_public.key": dsa_public_key,
        "dsa_secret.key": dsa_secret_key,
    }
    for filename, data in files.items():
        path = os.path.join(d, filename)
        with open(path, "wb") as f:
            f.write(data)
        _restrict_permissions(path)


def load_keypairs(farmer_id: str) -> dict:
    d = _farmer_key_dir(farmer_id)
    result = {}
    for key_name, filename in [
        ("kem_public_key", "kem_public.key"), ("kem_secret_key", "kem_secret.key"),
        ("dsa_public_key", "dsa_public.key"), ("dsa_secret_key", "dsa_secret.key"),
    ]:
        path = os.path.join(d, filename)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Missing key file for {farmer_id}: {path}")
        with open(path, "rb") as f:
            result[key_name] = f.read()
    return result


def farmer_has_keypairs(farmer_id: str) -> bool:
    d = os.path.join(config.KEYSTORE_PATH, farmer_id)
    return os.path.exists(os.path.join(d, "kem_secret.key"))
