"""Key lifecycle manager for AES, ML-KEM-1024, and ML-DSA-87 system keys.

Automatically generates missing post-quantum key pairs on first run and
loads existing ones on subsequent runs. AES keys are per-registration and
are not persisted by this module (they are protected via ML-KEM and stored
inside each registration package instead).
"""

from __future__ import annotations

from dataclasses import dataclass

from config import (
    MLDSA_PUBLIC_KEY_FILE,
    MLDSA_SECRET_KEY_FILE,
    MLKEM_PUBLIC_KEY_FILE,
    MLKEM_SECRET_KEY_FILE,
)
from crypto import mldsa_utils, mlkem_utils
from logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class SystemKeys:
    """Bundle of the system-wide post-quantum key material."""

    mlkem_public_key: bytes
    mlkem_secret_key: bytes
    mldsa_public_key: bytes
    mldsa_secret_key: bytes


def get_or_create_mlkem_keys() -> tuple[bytes, bytes]:
    """Load existing ML-KEM-1024 system keys, generating them if absent.

    Returns:
        A tuple of ``(public_key, secret_key)``.
    """
    if MLKEM_PUBLIC_KEY_FILE.exists() and MLKEM_SECRET_KEY_FILE.exists():
        logger.info("Loading existing ML-KEM-1024 system keys.")
        return mlkem_utils.load_keypair(MLKEM_PUBLIC_KEY_FILE, MLKEM_SECRET_KEY_FILE)

    logger.info("No ML-KEM-1024 system keys found; generating new key pair.")
    keypair = mlkem_utils.generate_keypair()
    mlkem_utils.save_keypair(keypair, MLKEM_PUBLIC_KEY_FILE, MLKEM_SECRET_KEY_FILE)
    return keypair.public_key, keypair.secret_key


def get_or_create_mldsa_keys() -> tuple[bytes, bytes]:
    """Load existing ML-DSA-87 system keys, generating them if absent.

    Returns:
        A tuple of ``(public_key, secret_key)``.
    """
    if MLDSA_PUBLIC_KEY_FILE.exists() and MLDSA_SECRET_KEY_FILE.exists():
        logger.info("Loading existing ML-DSA-87 system keys.")
        return mldsa_utils.load_keypair(MLDSA_PUBLIC_KEY_FILE, MLDSA_SECRET_KEY_FILE)

    logger.info("No ML-DSA-87 system keys found; generating new key pair.")
    keypair = mldsa_utils.generate_keypair()
    mldsa_utils.save_keypair(keypair, MLDSA_PUBLIC_KEY_FILE, MLDSA_SECRET_KEY_FILE)
    return keypair.public_key, keypair.secret_key


def load_system_keys() -> SystemKeys:
    """Load (or create, on first run) all system-wide post-quantum keys.

    Returns:
        A :class:`SystemKeys` bundle with ML-KEM-1024 and ML-DSA-87 key pairs.
    """
    mlkem_public, mlkem_secret = get_or_create_mlkem_keys()
    mldsa_public, mldsa_secret = get_or_create_mldsa_keys()
    return SystemKeys(
        mlkem_public_key=mlkem_public,
        mlkem_secret_key=mlkem_secret,
        mldsa_public_key=mldsa_public,
        mldsa_secret_key=mldsa_secret,
    )
