# Post-Quantum Secure Fingerprint Authentication using ML-KEM, ML-DSA, Blockchain, and IPFS

> A secure fingerprint authentication framework integrating **post-quantum cryptography**, **blockchain**, **IPFS**, and **biometric authentication** for protecting fingerprint templates against classical and future quantum threats.

---

## Overview

This project presents a secure fingerprint authentication system that combines modern biometric authentication with NIST-standardized post-quantum cryptography and decentralized storage technologies.

Unlike conventional biometric systems that store fingerprint templates in centralized databases, this framework encrypts fingerprint templates using **AES-256-GCM**, protects the encryption key using **ML-KEM-1024**, signs the encrypted package using **ML-DSA-87**, stores the encrypted package on **IPFS**, and stores only the IPFS Content Identifier (CID) on an **Ethereum blockchain**.

The system was developed as part of an IEEE research project to investigate secure biometric authentication in the post-quantum era.

---

# Key Features

- Fingerprint image preprocessing
- SourceAFIS fingerprint template extraction
- SourceAFIS fingerprint matching
- SHA3-256 fingerprint integrity verification
- AES-256-GCM template encryption
- ML-KEM-1024 (FIPS 203) key encapsulation
- ML-DSA-87 (FIPS 204) digital signatures
- IPFS decentralized biometric storage
- Ethereum blockchain CID management
- End-to-end registration workflow
- End-to-end verification workflow
- Batch registration evaluation
- Batch verification evaluation
- FAR, FRR, GAR, HTER, Accuracy and EER evaluation
- Cryptographic performance benchmarking
- IPFS performance evaluation
- Blockchain performance evaluation

---

# System Architecture

```
Fingerprint Image
        │
        ▼
Preprocessing
        │
        ▼
SourceAFIS Template Extraction
        │
        ▼
SHA3-256 Hash
        │
        ▼
ML-KEM-1024
(Generate Shared Secret)
        │
        ▼
AES-256-GCM Encryption
        │
        ▼
ML-DSA-87 Signature
        │
        ▼
Encrypted Registration Package
        │
        ▼
IPFS Storage
        │
        ▼
CID
        │
        ▼
Ethereum Blockchain
```

---

# Registration Workflow

1. Capture fingerprint image.
2. Apply fingerprint preprocessing.
3. Extract SourceAFIS fingerprint template.
4. Generate SHA3-256 hash of the template.
5. Generate an ML-KEM-1024 shared secret.
6. Encrypt the fingerprint template using AES-256-GCM.
7. Sign the encrypted registration package using ML-DSA-87.
8. Upload the encrypted package to IPFS.
9. Store the IPFS CID on the Ethereum blockchain.

---

# Verification Workflow

1. Capture live fingerprint.
2. Retrieve CID from blockchain.
3. Download encrypted package from IPFS.
4. Verify ML-DSA signature.
5. Recover the shared secret using ML-KEM decapsulation.
6. Decrypt fingerprint template using AES-256-GCM.
7. Verify SHA3-256 integrity hash.
8. Match live template with stored template using SourceAFIS.
9. Authenticate user based on the matching threshold.

---

# Project Structure

```
MAJOR PROJECT/

backend/
│
├── sourceafis_bridge.py
│
blockchain/
│
├── contracts/
├── web3_utils.py
├── blockchain_evaluation.py
│
crypto/
│
├── aes_utils.py
├── hash_utils.py
├── mlkem_utils.py
├── mldsa_utils.py
├── key_manager.py
│
registration/
│
├── processor.py
├── e2e_reg.py
├── batch_register.py
│
verification/
│
├── processor.py
├── e2e_verify.py
├── batch_verify.py
│
storage/
│
├── ipfs_utils.py
├── ipfs_evaluation.py
│
dataset/
│
keys/
│
packages/
│
results/
│
config.py
requirements.txt
README.md
```

---

# Technologies Used

| Component | Technology |
|------------|------------|
| Programming Language | Python 3.12 |
| Fingerprint Matching | SourceAFIS |
| Hash Function | SHA3-256 |
| Symmetric Encryption | AES-256-GCM |
| Post-Quantum KEM | ML-KEM-1024 |
| Post-Quantum Signature | ML-DSA-87 |
| Blockchain | Ethereum |
| Smart Contract | Solidity |
| Storage | IPFS |
| Web3 Library | web3.py |
| Dataset | FVC2002 |

---

# Cryptographic Algorithms

## SHA3-256

Used for fingerprint template integrity verification.

Output:

- 256-bit digest

---

## AES-256-GCM

Used to encrypt fingerprint templates.

Provides:

- Confidentiality
- Integrity
- Authentication

Key Size

- 256 bits

---

## ML-KEM-1024

NIST FIPS 203 standardized Key Encapsulation Mechanism.

Purpose

- Secure generation and protection of AES session keys.

---

## ML-DSA-87

NIST FIPS 204 standardized Digital Signature Algorithm.

Purpose

- Authenticate registration packages.
- Detect tampering.

---

# Smart Contract

The Ethereum smart contract stores only

- User ID
- IPFS CID
- Registration Timestamp

No fingerprint templates are stored on-chain.

---

# Installation

Clone the repository

```bash
git clone https://github.com/<username>/PostQuantumFingerprintAuthentication.git
```

Navigate to project

```bash
cd "MAJOR PROJECT"
```

Create virtual environment

```bash
python -m venv venv
```

Activate

Windows

```bash
venv\Scripts\activate
```

Linux

```bash
source venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# Dataset

Download

FVC2002 fingerprint database.

Place dataset as

```
dataset/

DB1_B/

DB2_B/

DB3_B/

DB4_B/

SOCOFING /
```

---

# Configuration

Update `config.py`

Configure

- Dataset directory
- Blockchain RPC URL
- Contract Address
- Private Key
- ABI path
- IPFS API endpoint
- SourceAFIS threshold

---

# Running Registration

Single Registration

```bash
python registration/e2e_reg.py dataset/DB3_B/101_1.tif 101
```

Batch Registration

```bash
python registration/batch_register.py
```

---

# Running Verification

Single Verification

```bash
python verification/e2e_verify.py dataset/DB3_B/101_8.tif 101
```

Batch Verification

```bash
python verification/batch_verify.py
```

---

# IPFS Evaluation

```bash
python -m storage.ipfs_evaluation
```

Outputs

- Upload Time
- Download Time
- Package Size
- Throughput

---

# Blockchain Evaluation

```bash
python blockchain/blockchain_evaluation.py
```

Outputs

- Retrieval Time
- Success Rate
- Throughput

---

# Evaluation Metrics

The framework evaluates

### Authentication Metrics

- Accuracy
- FAR
- FRR
- GAR
- HTER
- EER

### Cryptographic Metrics

- AES Encryption Time
- AES Decryption Time
- SHA3 Hash Time
- SHA3 Verification Time
- ML-KEM Encapsulation Time
- ML-KEM Decapsulation Time
- ML-DSA Signing Time
- ML-DSA Verification Time

### Storage Metrics

- IPFS Upload Time
- IPFS Download Time
- Package Size

### Blockchain Metrics

- CID Retrieval Time
- Throughput
- Success Rate

---

# Experimental Results

The framework was evaluated on the **FVC2002 benchmark dataset**.

Example results obtained during evaluation include:

| Metric | Example Result |
|---------|---------------:|
| Accuracy | 97.32% |
| FAR | 1.27% |
| GAR | 92.86% |
| FRR | 7.14% |
| HTER | 4.21% |
| EER | 5.48% |

(Results may vary depending on the selected dataset and matching threshold.)

---

# Security Properties

The proposed framework provides:

- Post-quantum confidentiality
- Template integrity verification
- Digital signature authentication
- Tamper detection
- Decentralized storage
- Immutable blockchain records
- Protection against centralized database compromise

---

# Future Improvements

- Fingerprint liveness detection
- Multi-factor authentication
- Mobile deployment
- Distributed blockchain network
- Hardware Security Module integration
- Larger biometric datasets
- Performance optimization
- Threshold optimization

---

# References

- NIST FIPS 203 – Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM)
- NIST FIPS 204 – Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
- SourceAFIS Documentation
- FVC2002 Fingerprint Verification Competition Database
- Ethereum Documentation
- IPFS Documentation

---

# License

This repository is intended for academic and research purposes.



---

-

# Acknowledgements



- National Institute of Standards and Technology (NIST)
- SourceAFIS
- FVC2002 Benchmark Dataset
- Ethereum Foundation
- IPFS Project
- Open-source Python community
