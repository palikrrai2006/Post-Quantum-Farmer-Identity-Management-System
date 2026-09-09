"""Global configuration for the Post-Quantum Secure Fingerprint Authentication system.

Defines filesystem paths, algorithm identifiers, and tunable parameters shared
across the crypto, registration, verification, and storage modules.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Base directories
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent

KEYS_DIR: Path = PROJECT_ROOT / "keys"
PACKAGES_DIR: Path = PROJECT_ROOT / "packages"
RESULTS_DIR: Path = PROJECT_ROOT / "results"
LOGS_DIR: Path = PROJECT_ROOT / "logs"

# ---------------------------------------------------------------------------
# Data directories
# ---------------------------------------------------------------------------

DATA_DIR: Path = PROJECT_ROOT / "data"

TEMPLATES_DIR: Path = DATA_DIR / "templates"

RAW_TEMPLATES_DIR: Path = TEMPLATES_DIR / "raw_templates"

DECRYPTED_TEMPLATES_DIR: Path = TEMPLATES_DIR / "decrypted_templates"

ENCRYPTED_TEMPLATES_DIR: Path = DATA_DIR / "encrypted_templates"

METADATA_DIR: Path = DATA_DIR / "metadata"

TABLES_DIR: Path = RESULTS_DIR / "tables"

GRAPHS_DIR: Path = RESULTS_DIR / "graphs"

for _directory in (
    KEYS_DIR,
    PACKAGES_DIR,
    RESULTS_DIR,
    LOGS_DIR,
    DATA_DIR,
    TEMPLATES_DIR,
    RAW_TEMPLATES_DIR,
    DECRYPTED_TEMPLATES_DIR,
    ENCRYPTED_TEMPLATES_DIR,
    METADATA_DIR,
    TABLES_DIR,
    GRAPHS_DIR,
):
    _directory.mkdir(parents=True, exist_ok=True)

# config.py

# Preprocessing Constants
CLAHE_CLIP_LIMIT = 2.0
CLAHE_TILE_GRID = (8, 8)
MEDIAN_BLUR_KSIZE = 3

#KEYS_DIR = PROJECT_ROOT / "keys"

MLKEM_PUBLIC_KEY_FILE = KEYS_DIR / "mlkem_public.key"
MLKEM_SECRET_KEY_FILE = KEYS_DIR / "mlkem_secret.key"

MLDSA_PUBLIC_KEY_FILE = KEYS_DIR / "mldsa_public.key"
MLDSA_SECRET_KEY_FILE = KEYS_DIR / "mldsa_secret.key"

# ---------------------------------------------------------------------------
# Algorithm identifiers (NIST FIPS designations, used in metadata.json)
# ---------------------------------------------------------------------------
ALGO_SYMMETRIC: str = "AES-256-GCM"
ALGO_HASH: str = "SHA3-256"
ALGO_KEM: str = "ML-KEM-1024"  # FIPS 203
ALGO_SIGNATURE: str = "ML-DSA-87"  # FIPS 204

# ---------------------------------------------------------------------------
# AES-GCM parameters
# ---------------------------------------------------------------------------
AES_KEY_SIZE_BYTES: int = 32  # 256-bit key
AES_NONCE_SIZE_BYTES: int = 12  # 96-bit nonce, recommended for GCM
AES_TAG_SIZE_BYTES: int = 16  # 128-bit authentication tag

# ---------------------------------------------------------------------------
# Hash parameters
# ---------------------------------------------------------------------------
HASH_DIGEST_SIZE_BYTES: int = 32  # SHA3-256 output size

# ---------------------------------------------------------------------------
# IPFS configuration
# ---------------------------------------------------------------------------
IPFS_API_BASE_URL: str = "http://127.0.0.1:5001/api/v0"
IPFS_GATEWAY_BASE_URL: str = "http://127.0.0.1:8080/ipfs"
IPFS_TIMEOUT_SECONDS: int = 30

# ---------------------------------------------------------------------------
# Blockchain configuration
# ---------------------------------------------------------------------------
# config.py
# Make sure this is the raw hex string from Ganache (without the '0x' prefix)

BLOCKCHAIN_RPC_URL: str = "http://127.0.0.1:7545"  # Ganache default
BLOCKCHAIN_ACCOUNT = "0x979f82828Aaa624412c7E5bbdebd022344154f8c"

BLOCKCHAIN_PRIVATE_KEY = "0x779505fba4cab1d6bd8417b1ba537c7d7e743ad337f269ed182c899dca397ee2" # populated after Hardhat/Ganache deployment
BLOCKCHAIN_CONTRACT_ABI_PATH: Path = PROJECT_ROOT / "storage" / "BiometricRegistry_abi.json"
  # set via environment variable in production

# ===========================================================================
# BLOCKCHAIN CONFIGURATION (Consolidated)
# ===========================================================================
BLOCKCHAIN_RPC_URL: str = "http://127.0.0.1:7545"
BLOCKCHAIN_CHAIN_ID: int = 5777
BLOCKCHAIN_GAS_LIMIT: int = 3_000_000

# Primary deployed instance address
BLOCKCHAIN_CONTRACT_ADDRESS = "0x5815287260695C96795D0860186FDe7635a00785"

# Paths to blockchain artifacts
BLOCKCHAIN_CONTRACT_ABI_PATH: Path = PROJECT_ROOT / "blockchain" / "contract_abi.json"
BLOCKCHAIN_CONTRACT_BIN_PATH: Path = PROJECT_ROOT / "blockchain" / "contract.bin"

# Private key for the deployer account (64-character raw hex string)
# Ensure this matches the account that deployed the contract above


# ---------------------------------------------------------------------------
# Fingerprint matching
# ---------------------------------------------------------------------------
SOURCEAFIS_MATCH_THRESHOLD = 14.0 # SourceAFIS similarity score threshold

# ---------------------------------------------------------------------------
# Registration package layout (relative file names inside a package folder)
# ---------------------------------------------------------------------------
PKG_TEMPLATE_FILE: str = "template.enc"
PKG_KEY_FILE: str = "key.kem"
PKG_SIGNATURE_FILE: str = "signature.sig"
PKG_METADATA_FILE: str = "metadata.json"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_FILE: Path = LOGS_DIR / "pqc_system.log"
LOG_LEVEL: str = "INFO"
