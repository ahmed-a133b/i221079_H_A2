
## CS-3002 Information Security Assignment 02 - SecureChat - PKI-Based Secure Messaging System

A secure chat application implementing PKI authentication, end-to-end encryption, and digital signatures for secure communications.

## Overview

This implementation includes:
- RSA X.509 PKI with self-signed CA and mutual certificate validation
- Diffie-Hellman key exchange for session key establishment
- AES-128 ECB encryption with PKCS#7 padding for message confidentiality
- RSA-SHA256 digital signatures for message authenticity and integrity
- MySQL user storage with salted password hashing
- Append-only transcripts and signed session receipts for non-repudiation
- Replay protection using sequence numbers and timestamps

## Implementation Status

All core components have been implemented:
- PKI certificate generation and validation
- User registration and authentication with salted password hashing
- Diffie-Hellman key exchange
- AES-128 message encryption/decryption
- RSA digital signatures for message integrity
- Transcript logging and session receipts for non-repudiation
- Replay protection and tampering detection
- Complete client-server protocol implementation

## Project Structure
```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (use cryptography lib)
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt)
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/manual/NOTES.md     # Manual testing + Wireshark evidence checklist
├─ certs/.keep               # Local certs/keys (gitignored)
├─ transcripts/.keep         # Session logs (gitignored)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
├─ requirements.txt          # Minimal dependencies
└─ .github/workflows/ci.yml  # Compile-only sanity check (no execution)
```

## Setup Instructions

### 1. Environment Setup
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Database Setup
```bash
# Start MySQL (using Docker)
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8

# Initialize database tables
python -m app.storage.db --init
```

### 3. Certificate Generation
```bash
python setup.py
```

### 4. Running the Application
```bash
# Terminal 1: Start server
python -m app.server

# Terminal 2: Start client
python -m app.client
```

## Usage Guide

### First Time Setup
1. Run the server
2. Run the client and choose "Register" (option 2)
3. Enter email, username, and password
4. After registration, login with the same credentials
5. Start chatting securely!

### Security Features Demonstrated
- **Certificate Validation**: Invalid/expired certificates are rejected
- **Encrypted Communication**: All messages encrypted with AES-128
- **Message Signatures**: Each message digitally signed with RSA
- **Replay Protection**: Sequence numbers prevent message replay
- **Non-Repudiation**: Session transcripts and receipts provide cryptographic proof

