"""
config.py
=========
Centralized configuration for the Secure Farmer Identity Management System.

Nothing else in this project should hard-code a path, threshold, or URL.
Every module imports from here.
"""

import os

# ----------------------------------------------------------------------
# PROJECT ROOT / DIRECTORIES
# ----------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = os.path.join(PROJECT_ROOT, "data")
DATASET_DIR = os.path.join(DATA_DIR, "dataset")
ENCRYPTED_DIR = os.path.join(DATA_DIR, "encrypted")
DOWNLOADED_DIR = os.path.join(DATA_DIR, "downloaded")
DATABASE_DIR = os.path.join(DATA_DIR, "database")

KEYSTORE_PATH = os.path.join(PROJECT_ROOT, "keys")
LOG_DIRECTORY = os.path.join(PROJECT_ROOT, "logs")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
RESULTS_TABLES_DIR = os.path.join(RESULTS_DIR, "tables")
RESULTS_GRAPHS_DIR = os.path.join(RESULTS_DIR, "graphs")
RESULTS_LOGS_DIR = os.path.join(RESULTS_DIR, "logs")

UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")

for _d in (DATA_DIR, DATASET_DIR, ENCRYPTED_DIR, DOWNLOADED_DIR, DATABASE_DIR,
           KEYSTORE_PATH, LOG_DIRECTORY, RESULTS_DIR, RESULTS_TABLES_DIR,
           RESULTS_GRAPHS_DIR, RESULTS_LOGS_DIR, UPLOAD_FOLDER):
    os.makedirs(_d, exist_ok=True)

# ----------------------------------------------------------------------
# DATABASE
# ----------------------------------------------------------------------
DATABASE_PATH = os.path.join(DATABASE_DIR, "farmer_identity.db")

# ----------------------------------------------------------------------
# IPFS (Kubo) — must be running locally: `ipfs daemon`
# ----------------------------------------------------------------------
IPFS_API_BASE_URL = os.environ.get("IPFS_API_BASE_URL", "http://127.0.0.1:5001/api/v0")
IPFS_GATEWAY_BASE_URL = os.environ.get("IPFS_GATEWAY_BASE_URL", "http://127.0.0.1:8080/ipfs")
IPFS_TIMEOUT_SECONDS = 30

# ----------------------------------------------------------------------
# BLOCKCHAIN (Ganache / any Ethereum-compatible dev chain)
# ----------------------------------------------------------------------
BLOCKCHAIN_RPC_URL = os.environ.get("BLOCKCHAIN_RPC_URL", "http://127.0.0.1:7545")
CONTRACT_CONFIG_PATH = os.path.join(PROJECT_ROOT, "blockchain", "contract_config.json")
# CONTRACT_ADDRESS is populated into contract_config.json by blockchain/deploy.py
CONTRACT_ADDRESS = os.environ.get("CONTRACT_ADDRESS", "0x9311122757F56f49D9C6c3300ae22bD580Bf09A1")
DEPLOYER_PRIVATE_KEY = os.environ.get("DEPLOYER_PRIVATE_KEY", "0xed2517e6a869c22ac232381de05579c4397363983e4409142249694312d03a57")
# =========================
# BLOCKCHAIN CONFIGURATION
# =========================


CHAIN_ID = 5777

# Ganache network ID (displayed in Ganache GUI)
#NETWORK_ID = 5777

CONTRACT_CONFIG_PATH = os.path.join(
    PROJECT_ROOT,
    "blockchain",
    "contract_config.json"
)

# ----------------------------------------------------------------------
# BIOMETRIC MATCHING
# ----------------------------------------------------------------------
SOURCEAFIS_THRESHOLD = 14          # Minimum SourceAFIS match score to accept
MIN_FINGERPRINTS = 5               # Minimum enrolled fingers to complete registration
MAX_FINGERPRINTS = 10              # Maximum enrolled fingers per farmer

NORMAL_AUTH_FINGER_COUNT = 1       # 1-of-N standard verification
HIGH_SECURITY_FINGER_COUNT = 2     # 2-of-N high-security verification (govt sensitive ops)

VALID_FINGER_POSITIONS = [
    "LEFT_THUMB", "LEFT_INDEX", "LEFT_MIDDLE", "LEFT_RING", "LEFT_LITTLE",
    "RIGHT_THUMB", "RIGHT_INDEX", "RIGHT_MIDDLE", "RIGHT_RING", "RIGHT_LITTLE",
]

SOURCEAFIS_JAR_DIR = os.path.join(
    PROJECT_ROOT,
    "biometric",
    "java_bridge",
    "target"
)

SOURCEAFIS_BRIDGE_JAR = os.path.join(
    SOURCEAFIS_JAR_DIR,
    "sourceafis-bridge.jar"
)

JAVA_EXECUTABLE = os.environ.get("JAVA_EXECUTABLE", "java")

# ----------------------------------------------------------------------
# CRYPTO ALGORITHM NAMES (liboqs identifiers)
# ----------------------------------------------------------------------
KEM_ALGORITHM = "ML-KEM-1024"
SIG_ALGORITHM = "ML-DSA-87"
HASH_ALGORITHM = "SHA3-256"
AES_KEY_BYTES = 32          # AES-256
AES_NONCE_BYTES = 12        # 96-bit GCM nonce (standard, recommended)
KDF_CONTEXT_INFO = b"FARMER-IDENTITY-SYSTEM|ML-KEM-1024|AES-256-GCM|v1"

# Expected (approximate, verify programmatically) object sizes for sanity checks
EXPECTED_SIZES = {
    "ML-KEM-1024": {"public_key": 1568, "secret_key": 3168, "ciphertext": 1568, "shared_secret": 32},
    "ML-DSA-87":   {"public_key": 2592, "secret_key": 4896, "signature": 4627},
    "RSA-2048":    {"public_key_der_approx": 294, "private_key_der_approx": 1190, "ciphertext": 256, "signature": 256},
}

# ----------------------------------------------------------------------
# FLASK / SESSION
# ----------------------------------------------------------------------
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me-in-production")
SESSION_COOKIE_NAME = "farmer_identity_session"
DEBUG = os.environ.get("FLASK_DEBUG", "1") == "1"
HOST = "127.0.0.1"
PORT = 5000

# ----------------------------------------------------------------------
# ROLES
# ----------------------------------------------------------------------
ROLE_ADMIN = "ADMIN"
ROLE_GOVERNMENT_OFFICER = "GOVERNMENT_OFFICER"
ROLE_REGISTRATION_CENTER_OPERATOR = "REGISTRATION_CENTER_OPERATOR"
ROLE_FARMER = "FARMER"
ALL_ROLES = [ROLE_ADMIN, ROLE_GOVERNMENT_OFFICER, ROLE_REGISTRATION_CENTER_OPERATOR, ROLE_FARMER]

# ----------------------------------------------------------------------
# EXPERIMENT SAMPLE SIZES
# ----------------------------------------------------------------------
IPFS_EXPERIMENT_SIZES = [10, 50, 100, 500, 603]
BLOCKCHAIN_EXPERIMENT_SIZES = [10, 50, 100, 500, 603]
THRESHOLD_SWEEP = list(range(8, 21))
CRYPTO_BENCHMARK_ITERATIONS = 200
CRYPTO_BENCHMARK_WARMUP = 20
