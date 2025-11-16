
# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository implements a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

## 🧩 Overview

This implementation includes:
- **RSA X.509 PKI** with self-signed CA and mutual certificate validation
- **Diffie-Hellman** key exchange for session key establishment
- **AES-128 ECB** encryption with PKCS#7 padding for message confidentiality
- **RSA-SHA256** digital signatures for message authenticity and integrity
- **MySQL** user storage with salted password hashing
- **Append-only transcripts** and signed session receipts for non-repudiation
- **Replay protection** using sequence numbers and timestamps

## ✅ Implementation Status

All core components have been implemented:
- ✅ PKI certificate generation and validation
- ✅ User registration and authentication with salted password hashing
- ✅ Diffie-Hellman key exchange
- ✅ AES-128 message encryption/decryption
- ✅ RSA digital signatures for message integrity
- ✅ Transcript logging and session receipts for non-repudiation
- ✅ Replay protection and tampering detection
- ✅ Complete client-server protocol implementation

## 🏗️ Folder Structure
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

## ⚙️ Setup Instructions

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
# Start MySQL (using Docker - recommended)
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
# Generate Root CA
python scripts/gen_ca.py --name "FAST-NU Root CA"

# Generate server certificate
python scripts/gen_cert.py --cn server.local --out certs/server

# Generate client certificate  
python scripts/gen_cert.py --cn client.local --out certs/client
```

### 4. Running the Application
```bash
# Terminal 1: Start server
python -m app.server

# Terminal 2: Start client
python -m app.client
```

## 📋 Usage Guide

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

## 🚫 Important Rules

- **Do not use TLS/SSL or any secure-channel abstraction**  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations must occur **explicitly** at the application layer.

- You are **not required** to implement AES, RSA, or DH math, Use any of the available libraries.
- Do **not commit secrets** (certs, private keys, salts, `.env` values).
- Your commits must reflect progressive development — at least **10 meaningful commits**.

## 🧾 Deliverables

When submitting on Google Classroom (GCR):

1. A ZIP of your **GitHub fork** (repository).
2. MySQL schema dump and a few sample records.
3. Updated **README.md** explaining setup, usage, and test outputs.
4. `RollNumber-FullName-Report-A02.docx`
5. `RollNumber-FullName-TestReport-A02.docx`

## 🧪 Testing & Validation

### Quick Setup
```bash
# Run the setup script to generate certificates and test basic functionality
python setup.py

# Or run individual tests
python test_implementation.py
```

### Security Testing Checklist

#### ✅ Certificate Validation
- Invalid certificates are rejected with `BAD_CERT` status
- Expired certificates are rejected
- Self-signed certificates (not from trusted CA) are rejected
- Common Name (CN) validation works correctly

#### ✅ Encryption & Integrity
- All messages are encrypted with AES-128 ECB + PKCS#7 padding
- Message tampering is detected and rejected with `SIG_FAIL`
- Digital signatures use RSA-SHA256 with PKCS#1 v1.5 padding

#### ✅ Replay Protection
- Messages with duplicate or out-of-order sequence numbers are rejected
- Server responds with `REPLAY` status for replay attempts

#### ✅ Non-Repudiation
- All messages are logged in append-only transcripts
- Session receipts are generated with cryptographic signatures
- Offline verification of transcripts and receipts is supported

### Wireshark Analysis
To capture network traffic for analysis:
1. Start Wireshark and capture on the loopback interface
2. Apply filter: `tcp.port == 8443`
3. Run the client-server communication
4. Verify that all message payloads are encrypted (no plaintext visible)

### Manual Testing Scenarios

#### Test 1: Normal Operation
1. Start server: `python -m app.server`
2. Start client: `python -m app.client`
3. Register a new user
4. Login with the registered credentials
5. Send encrypted messages
6. Verify transcripts and receipts are generated

#### Test 2: Certificate Validation
1. Replace client certificate with a self-signed one
2. Attempt to connect
3. Verify server rejects with `BAD_CERT`

#### Test 3: Message Tampering
1. Modify the signature verification code temporarily to print raw message data
2. Manually alter a message in transit
3. Verify signature verification fails with `SIG_FAIL`

#### Test 4: Replay Attack
1. Capture a valid message
2. Resend the same message
3. Verify server rejects with `REPLAY` status
