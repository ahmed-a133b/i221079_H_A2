#!/usr/bin/env python3
"""
Security tests for SecureChat implementation.
Tests: Invalid certificates, tampering detection, replay attacks, non-repudiation.
"""

import os
import sys
import json
import hashlib
import base64
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from app.crypto.pki import validate_certificate_chain, CertificateValidationError, load_certificate
from app.crypto.sign import rsa_sign, rsa_verify, rsa_verify_with_cert
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.common.utils import sha256_hex, b64e, b64d
from app.common.protocol import ChatMessage, SessionReceipt
from app.storage.transcript import TranscriptManager


class SecurityTester:
    def __init__(self):
        self.ca_cert_path = "certs/ca-cert.pem"
        self.server_cert_path = "certs/server-cert.pem"
        self.client_cert_path = "certs/client-cert.pem"
        self.server_key_path = "certs/server-key.pem"
        self.client_key_path = "certs/client-key.pem"
        
    def load_file(self, path):
        """Load file content as string."""
        with open(path, 'r') as f:
            return f.read()
    
    def load_key(self, path):
        """Load private key from PEM file."""
        with open(path, 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

    def test_invalid_certificates(self):
        """Test 1: Invalid certificate detection."""
        print("=== TEST 1: Invalid Certificate Detection ===")
        
        ca_cert_pem = self.load_file(self.ca_cert_path)
        server_cert_pem = self.load_file(self.server_cert_path)
        
        # Test 1a: Valid certificate (should pass)
        try:
            validate_certificate_chain(server_cert_pem, ca_cert_pem, "server.local")
            print("✓ Valid certificate: PASSED")
        except CertificateValidationError as e:
            print(f"✗ Valid certificate test failed: {e}")
        
        # Test 1b: Self-signed certificate (should fail)
        print("\n--- Testing self-signed certificate ---")
        try:
            validate_certificate_chain(server_cert_pem, server_cert_pem, "server.local")
            print("✗ Self-signed certificate: Should have failed but passed!")
        except CertificateValidationError as e:
            print(f"✓ Self-signed certificate rejected: {e}")
        
        # Test 1c: Forged certificate (create fake cert)
        print("\n--- Testing forged certificate ---")
        forged_cert = self.create_forged_certificate()
        try:
            validate_certificate_chain(forged_cert, ca_cert_pem, "server.local")
            print("✗ Forged certificate: Should have failed but passed!")
        except CertificateValidationError as e:
            print(f"✓ Forged certificate rejected: {e}")
        
        # Test 1d: Expired certificate
        print("\n--- Testing expired certificate ---")
        expired_cert = self.create_expired_certificate()
        try:
            validate_certificate_chain(expired_cert, ca_cert_pem, "expired_server")
            print("✗ Expired certificate: Should have failed but passed!")
        except CertificateValidationError as e:
            print(f"✓ Expired certificate rejected: {e}")

    def create_forged_certificate(self):
        """Create a forged certificate for testing."""
        # Generate a new key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create a self-signed certificate pretending to be signed by CA
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "server"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def create_expired_certificate(self):
        """Create an expired certificate for testing."""
        # Generate a new key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create an expired certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "expired_server"),
        ])
        
        # Make it expired (valid from 2 days ago to 1 day ago)
        now = datetime.now(timezone.utc)
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now - timedelta(days=2)
        ).not_valid_after(
            now - timedelta(days=1)
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def test_tampering_detection(self):
        """Test 2: Message tampering detection."""
        print("\n=== TEST 2: Message Tampering Detection ===")
        
        # Create a test message
        message_data = {
            "sender": "alice",
            "recipient": "bob", 
            "message": "Hello Bob!",
            "seqno": 1,
            "timestamp": int(datetime.now().timestamp() * 1000)
        }
        
        # Create signature
        private_key_pem = self.load_file(self.client_key_path)
        message_json = json.dumps(message_data, sort_keys=True)
        message_hash = sha256_hex(message_json)
        signature = rsa_sign(message_hash, private_key_pem)
        
        chat_message = ChatMessage(
            seqno=message_data["seqno"],
            ts=message_data["timestamp"],
            ct=b64e(b"fake_ciphertext"),  # Fake ciphertext for testing
            sig=b64e(signature)
        )
        
        print(f"Original message: {message_data['message']}")
        print(f"Original hash: {message_hash}")
        
        # Test 2a: Valid message (should pass)
        client_cert_pem = self.load_file(self.client_cert_path)
        try:
            # Verify signature (using original message data since ChatMessage doesn't store it)
            verify_data = {
                "sender": message_data["sender"],
                "recipient": message_data["recipient"],
                "message": message_data["message"],
                "seqno": message_data["seqno"],
                "timestamp": message_data["timestamp"]
            }
            verify_json = json.dumps(verify_data, sort_keys=True)
            verify_hash = sha256_hex(verify_json)
            
            if rsa_verify_with_cert(verify_hash, b64d(chat_message.sig), client_cert_pem):
                print("✓ Valid message signature: VERIFIED")
            else:
                print("✗ Valid message signature: FAILED")
        except Exception as e:
            print(f"✗ Valid message verification failed: {e}")
        
        # Test 2b: Tampered message (should fail)
        print("\n--- Testing tampered message ---")
        
        try:
            # Try to verify tampered data with original signature (should fail)
            tampered_data = message_data.copy()
            tampered_data["message"] = "Hacked message!"  # Change the message content
            
            verify_json = json.dumps(tampered_data, sort_keys=True)
            verify_hash = sha256_hex(verify_json)
            
            if rsa_verify_with_cert(verify_hash, b64d(chat_message.sig), client_cert_pem):
                print("✗ Tampered message: Should have failed but passed!")
            else:
                print("✓ Tampered message signature: REJECTED (as expected)")
        except Exception as e:
            print(f"✓ Tampered message verification failed: {e} (as expected)")

        # Test 2c: Tampered ciphertext
        print("\n--- Testing tampered ciphertext ---")
        session_key = b"0123456789abcdef"  # 16-byte AES key
        plaintext = "Secret message"
        
        # Encrypt message
        ciphertext = aes_encrypt(plaintext, session_key)
        print(f"Original ciphertext: {b64e(ciphertext)}")
        
        # Tamper with ciphertext (flip one bit)
        tampered_ct = bytearray(ciphertext)
        tampered_ct[5] ^= 1  # Flip one bit
        tampered_ct = bytes(tampered_ct)
        print(f"Tampered ciphertext: {b64e(tampered_ct)}")
        
        try:
            decrypted = aes_decrypt(tampered_ct, session_key)
            print(f"✗ Tampered ciphertext decrypted to: '{decrypted}' (should be garbage or fail)")
        except Exception as e:
            print(f"✓ Tampered ciphertext decryption failed: {e} (as expected)")

    def test_replay_attacks(self):
        """Test 3: Replay attack detection."""
        print("\n=== TEST 3: Replay Attack Detection ===")
        
        # Simulate sequence number tracking
        received_seqnos = set()
        
        def process_message(seqno):
            """Simulate message processing with replay detection."""
            if seqno in received_seqnos:
                return False, "REPLAY_FAIL: Duplicate sequence number"
            received_seqnos.add(seqno)
            return True, "Message accepted"
        
        # Test legitimate sequence
        test_cases = [
            (1, "First message"),
            (2, "Second message"),
            (3, "Third message"),
            (2, "Replayed message (should fail)"),  # Replay attack
            (4, "Fourth message"),
            (1, "Another replay (should fail)")     # Another replay
        ]
        
        for seqno, description in test_cases:
            success, result = process_message(seqno)
            status = "✓" if (success and "replay" not in description.lower()) or (not success and "replay" in description.lower()) else "✗"
            print(f"{status} Seqno {seqno} ({description}): {result}")

    def test_non_repudiation(self):
        """Test 4: Non-repudiation and transcript verification."""
        print("\n=== TEST 4: Non-Repudiation Testing ===")
        
        # Create a transcript manager
        transcript_file = os.path.join(".", "test_transcript.txt")
        if os.path.exists(transcript_file):
            os.remove(transcript_file)
        
        transcript = TranscriptManager(transcript_file)
        
        # Load keys and certificates
        client_key_pem = self.load_file(self.client_key_path)
        server_key_pem = self.load_file(self.server_key_path)
        client_cert = self.load_file(self.client_cert_path)
        server_cert = self.load_file(self.server_cert_path)
        
        print("--- Creating signed messages for transcript ---")
        
        # Create some signed messages
        messages = [
            {"sender": "alice", "recipient": "bob", "message": "Hello Bob!", "seqno": 1},
            {"sender": "bob", "recipient": "alice", "message": "Hi Alice!", "seqno": 2},
            {"sender": "alice", "recipient": "bob", "message": "How are you?", "seqno": 3}
        ]
        
        signed_messages = []
        for msg_data in messages:
            msg_data["timestamp"] = int(datetime.now().timestamp() * 1000)
            
            # Choose key based on sender
            signing_key_pem = client_key_pem if msg_data["sender"] == "alice" else server_key_pem
            sender_cert = client_cert if msg_data["sender"] == "alice" else server_cert
            
            # Create signature
            message_json = json.dumps(msg_data, sort_keys=True)
            message_hash = sha256_hex(message_json)
            signature = rsa_sign(message_hash, signing_key_pem)
            
            # Store message data with signature for verification
            msg_with_sig = {
                "sender": msg_data["sender"],
                "recipient": msg_data["recipient"],
                "message": msg_data["message"],
                "seqno": msg_data["seqno"],
                "timestamp": msg_data["timestamp"],
                "signature": signature
            }
            
            signed_messages.append((msg_with_sig, sender_cert))
            
            # Add to transcript (simplified for testing)
            transcript.add_message(
                seqno=msg_data["seqno"],
                timestamp=msg_data["timestamp"],
                ciphertext=b64e(f"encrypted_{msg_data['message']}".encode()),
                signature=b64e(signature),
                peer_cert_fingerprint=sha256_hex(sender_cert.encode()),
                direction="sent" if msg_data["sender"] == "alice" else "received"
            )
        
        # Create session receipt
        transcript_hash = transcript.compute_transcript_hash()
        client_key_pem = self.load_file(self.client_key_path)  # Load as PEM string for session receipt
        
        # Import the standalone function
        from app.storage.transcript import create_session_receipt
        receipt_data = create_session_receipt(transcript, "client", client_key_pem)
        
        print(f"✓ Created transcript with {len(signed_messages)} messages")
        print(f"✓ Transcript hash: {transcript_hash}")
        print(f"✓ Session receipt created and signed")
        
        # Test 4a: Verify each message signature
        print("\n--- Verifying individual message signatures ---")
        for i, (message, cert) in enumerate(signed_messages):
            try:
                verify_data = {
                    "sender": message["sender"],
                    "recipient": message["recipient"],
                    "message": message["message"],
                    "seqno": message["seqno"],
                    "timestamp": message["timestamp"]
                }
                verify_json = json.dumps(verify_data, sort_keys=True)
                verify_hash = sha256_hex(verify_json)
                
                if rsa_verify_with_cert(verify_hash, message["signature"], cert):
                    print(f"✓ Message {i+1} signature: VALID")
                else:
                    print(f"✗ Message {i+1} signature: INVALID")
            except Exception as e:
                print(f"✗ Message {i+1} verification failed: {e}")
        
        # Test 4b: Verify session receipt
        print("\n--- Verifying session receipt ---")
        try:
            # The session receipt signature is over the transcript hash directly
            if rsa_verify_with_cert(receipt_data["transcript_sha256"], b64d(receipt_data["sig"]), client_cert):
                print("✓ Session receipt signature: VALID")
            else:
                print("✗ Session receipt signature: INVALID")
        except Exception as e:
            print(f"✗ Session receipt verification failed: {e}")
        
        # Test 4c: Show that tampering breaks verification
        print("\n--- Testing tampering detection in transcript ---")
        
        # Create a tampered version of first message
        tampered_message = signed_messages[0][0].copy()
        tampered_message["message"] = "HACKED MESSAGE!"
        
        try:
            verify_data = {
                "sender": tampered_message["sender"],
                "recipient": tampered_message["recipient"],
                "message": tampered_message["message"],  # This is tampered!
                "seqno": tampered_message["seqno"],
                "timestamp": tampered_message["timestamp"]
            }
            verify_json = json.dumps(verify_data, sort_keys=True)
            verify_hash = sha256_hex(verify_json)
            
            if rsa_verify_with_cert(verify_hash, tampered_message["signature"], signed_messages[0][1]):
                print("✗ Tampered message: Should have failed but verified!")
            else:
                print("✓ Tampered message signature: REJECTED (tampering detected)")
        except Exception as e:
            print(f"✓ Tampered message verification failed: {e} (tampering detected)")
        
        # Export transcript and receipt for offline verification
        print("\n--- Exporting for offline verification ---")
        
        export_data = {
            "messages": [],
            "transcript_hash": transcript_hash,
            "session_receipt": receipt_data,
            "certificates": {
                "alice": client_cert,
                "bob": server_cert
            }
        }
        
        for message, cert_pem in signed_messages:
            export_data["messages"].append({
                "sender": message["sender"],
                "recipient": message["recipient"],
                "message": message["message"],
                "seqno": message["seqno"],
                "timestamp": message["timestamp"],
                "signature": b64e(message["signature"])
            })
        
        with open("non_repudiation_evidence.json", "w") as f:
            json.dump(export_data, f, indent=2)
        
        print("✓ Evidence exported to 'non_repudiation_evidence.json'")
        print("✓ This file can be used for offline verification of message authenticity")
        
        # Clean up
        if os.path.exists(transcript_file):
            os.remove(transcript_file)

    def run_all_tests(self):
        """Run all security tests."""
        print("SecureChat Security Test Suite")
        print("=" * 50)
        
        try:
            self.test_invalid_certificates()
            self.test_tampering_detection()
            self.test_replay_attacks()
            self.test_non_repudiation()
            
            print("\n" + "=" * 50)
            print("All security tests completed!")
            print("Check the results above to verify security properties.")
            
        except Exception as e:
            print(f"Test suite failed: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    tester = SecurityTester()
    tester.run_all_tests()