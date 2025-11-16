# Security Testing Guide for SecureChat

This guide explains how to perform the security tests outlined in your requirements using the current implementation.

## Prerequisites

1. Ensure your SecureChat system is fully set up:
   - MySQL database running (Docker container on port 3305)
   - Certificates generated in `certs/` directory
   - All dependencies installed

2. Make sure you have the test files:
   - `test_security.py` - Main security test suite
   - `verify_offline.py` - Offline verification script

## Running the Tests

### 1. Invalid Certificate Tests

Run the security test suite:
```bash
python test_security.py
```

This will test:
- **Valid certificates**: Should pass validation
- **Self-signed certificates**: Should be rejected with "Certificate signature validation failed"
- **Forged certificates**: Should be rejected during signature validation
- **Expired certificates**: Should be rejected with "Certificate expired" error

**Expected Results**: All invalid certificates should be rejected with appropriate error messages.

### 2. Message Tampering Tests

The test suite includes tampering detection tests:

**Message Signature Tampering**:
- Creates a signed message
- Modifies the message content
- Attempts verification with original signature
- **Expected**: Signature verification should FAIL

**Ciphertext Tampering**:
- Encrypts a message with AES
- Flips a bit in the ciphertext
- Attempts decryption
- **Expected**: Decryption should fail or produce garbage

### 3. Replay Attack Tests

The test demonstrates sequence number tracking:
- Processes messages with sequence numbers 1, 2, 3
- Attempts to replay message with seqno 2
- **Expected**: Replay should be detected and rejected with "REPLAY_FAIL"

### 4. Non-Repudiation Tests

The test creates and verifies a complete transcript:

**Steps performed**:
1. Creates signed messages from multiple users
2. Builds a transcript with message history
3. Generates a signed session receipt
4. Exports evidence to `non_repudiation_evidence.json`
5. Verifies all signatures offline

**Verification process**:
1. **Message verification**: Recomputes SHA-256 hash of each message and verifies RSA signature
2. **Receipt verification**: Verifies RSA signature over transcript hash
3. **Tampering test**: Shows that modifying any message breaks verification

## Manual Testing Steps

### Test 1: Certificate Validation
```bash
# Run the security test suite
python test_security.py

# Look for output like:
# ✓ Valid certificate: PASSED
# ✓ Self-signed certificate rejected: Certificate signature validation failed
# ✓ Forged certificate rejected: Certificate signature validation failed
# ✓ Expired certificate rejected: Certificate expired
```

### Test 2: Live Tampering Test
1. Start the server: `python -m app.server`
2. Start the client: `python -m app.client`
3. Send some messages normally
4. Examine the transcript file to see signed messages
5. Manually edit a message in the transcript
6. Try to verify the transcript - should fail

### Test 3: Replay Attack Test
1. Capture network traffic during a session
2. Try to resend a previous message
3. The server should reject it due to duplicate sequence numbers

### Test 4: Offline Verification
```bash
# First, generate evidence
python test_security.py

# Then verify offline
python verify_offline.py non_repudiation_evidence.json

# Expected output:
# ✓ Message 1 (alice): AUTHENTIC
# ✓ Message 2 (bob): AUTHENTIC  
# ✓ Session receipt: AUTHENTIC
# 🔒 VERIFICATION PASSED: All messages and receipt are authentic
```

## Understanding the Results

### Certificate Tests (BAD CERT)
- **Self-signed**: Rejected because signature verification fails against CA
- **Forged**: Rejected because private key doesn't match CA
- **Expired**: Rejected because current time is outside validity window

### Tampering Tests (SIG FAIL)
- **Message tampering**: Changing any field breaks the SHA-256 hash
- **Signature tampering**: Invalid signature detected by RSA verification
- **Ciphertext tampering**: AES decryption fails or produces corrupted data

### Replay Tests (REPLAY FAIL)
- **Sequence tracking**: Each message has unique sequence number
- **Duplicate detection**: Server maintains set of seen sequence numbers
- **Rejection**: Duplicate sequence numbers are automatically rejected

### Non-Repudiation
- **Message authenticity**: Each message cryptographically signed by sender
- **Transcript integrity**: Hash chain prevents message insertion/deletion
- **Session receipt**: Proves transcript state at session end
- **Offline verification**: Evidence can be verified without original system

## Key Security Properties Demonstrated

1. **Confidentiality**: AES encryption protects message content
2. **Integrity**: SHA-256 hashes detect tampering
3. **Authenticity**: RSA signatures prove sender identity
4. **Non-repudiation**: Signed transcripts provide undeniable proof
5. **Replay protection**: Sequence numbers prevent message replay

## Files Generated

- `non_repudiation_evidence.json`: Complete evidence package for offline verification
- `test_transcript.txt`: Sample transcript with signed messages
- Test output showing all security validations

Run these tests to demonstrate that your SecureChat implementation successfully provides all required security properties (CIANR - Confidentiality, Integrity, Authenticity, Non-Repudiation, Replay protection).