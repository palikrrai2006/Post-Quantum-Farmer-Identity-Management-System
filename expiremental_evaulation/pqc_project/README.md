# Post-Quantum Cryptographic Module — Fingerprint Authentication System

Complete, runnable cryptographic subsystem that picks up immediately after
your existing SourceAFIS template extraction step. No biometric algorithms
are implemented or duplicated here.

## What this is built on

- **AES-256-GCM** — `pycryptodome`
- **SHA3-256** — Python's built-in `hashlib`
- **ML-KEM-1024 (FIPS 203)** — `pqcrypto.kem.ml_kem_1024`
- **ML-DSA-87 (FIPS 204)** — `pqcrypto.sign.ml_dsa_87`
- **IPFS** — direct HTTP calls to the Kubo RPC API via `requests` (avoids the
  known `ipfshttpclient` version mismatch with Kubo v0.40.1)
- **Blockchain** — `web3.py` against your Ganache/Hardhat node, calling the
  included `BiometricRegistry.sol` contract

All four crypto primitives were executed and verified in this environment
(key generation, encryption/decryption, encapsulation/decapsulation, signing/
verification all round-tripped correctly — see `experiments/run_crypto_benchmarks.py`,
which you can run immediately with no external services).

## One integration point you must wire up

`verification/verify_user.py` calls:

```python
from biometric_module import match_templates
```

This intentionally points at **your existing** SourceAFIS matcher rather than
reimplementing fingerprint comparison. Update that import line to match
whatever module/function name your existing biometric pipeline already
exposes (e.g. if your function lives in `biometric_module.py` as
`compare_templates(path_a, path_b) -> float`, just rename the import).

## Two things you must configure before running the IPFS/blockchain steps

1. **`config.py` → `BLOCKCHAIN_CONTRACT_ADDRESS`** — set this after deploying
   `storage/BiometricRegistry.sol` via Hardhat/Ganache.
2. **`config.py` → `BLOCKCHAIN_PRIVATE_KEY`** — set this (ideally via an
   environment variable rather than hardcoding) for the Admin account that
   will call `registerRecord`.

Everything else (IPFS API/gateway URLs, AES/nonce/tag sizes, file paths) is
already configured with sensible local-development defaults in `config.py`.

## Running it

```bash
pip install -r requirements.txt

# Crypto-only benchmark (no IPFS/blockchain needed) — produces
# results/crypto_benchmark_trials.csv and results/crypto_benchmark_summary.json
python -m experiments.run_crypto_benchmarks

# Full registration (requires a running IPFS daemon + deployed contract)
python -c "
from pathlib import Path
from registration.register_user import register_user
result = register_user('FRM001', '101_1', Path('path/to/101_1_template.txt'))
print(result)
"

# Full verification (requires the same services)
python -c "
from pathlib import Path
from verification.verify_user import verify_user
result = verify_user('FRM001', Path('path/to/live_101_1_template.txt'))
print(result)
"
```

## Registration package layout

```
packages/FRM001/
    template.enc      # AES-256-GCM ciphertext (nonce|tag|ciphertext)
    key.kem            # ML-KEM-1024 ciphertext + XOR-protected AES key
    signature.sig       # ML-DSA-87 signature over metadata+template.enc+key.kem
    metadata.json        # IDs, timestamps, algorithm names, hashes, all timings, CID, tx hash
```

## Notes on design choices

- The AES key is never stored in plaintext anywhere: it's protected by
  XOR-ing it with the ML-KEM-1024 shared secret (both are 32 bytes), and the
  KEM ciphertext + protected key live together in `key.kem`. Decapsulation
  recovers the same shared secret, which un-XORs the AES key.
- The ML-DSA-87 signature covers the canonical metadata JSON plus the raw
  bytes of `template.enc` and `key.kem`, so any tampering with any package
  file invalidates the signature.
- All nine requested timing measurements (SHA3, AES enc/dec, ML-KEM
  keygen/encap/decap, ML-DSA keygen/sign/verify, IPFS upload/download,
  blockchain write/read, registration/verification totals) are captured and
  written into both per-package `metadata.json` and the `results/` CSV/JSON
  outputs.
