#!/usr/bin/env python3
"""
Simple test script to validate basic functionality of the SecureChat implementation.
"""
import os
import sys
import tempfile
import shutil

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

def test_utils():
    """Test utility functions."""
    print("Testing utility functions...")
    
    from app.common.utils import b64e, b64d, sha256_hex, now_ms
    
    # Test base64 encoding/decoding
    test_data = b"Hello, World!"
    encoded = b64e(test_data)
    decoded = b64d(encoded)
    assert decoded == test_data, "Base64 encoding/decoding failed"
    
    # Test SHA-256 hashing
    test_string = "test string"
    hash1 = sha256_hex(test_string)
    hash2 = sha256_hex(test_string)
    assert hash1 == hash2, "SHA-256 hashing inconsistent"
    assert len(hash1) == 64, "SHA-256 hash length incorrect"
    
    # Test timestamp
    ts = now_ms()
    assert isinstance(ts, int), "Timestamp should be integer"
    assert ts > 0, "Timestamp should be positive"
    
    print("✓ Utility functions tests passed")

def test_aes():
    """Test AES encryption/decryption."""
    print("Testing AES encryption...")
    
    from app.crypto.aes import aes_encrypt, aes_decrypt, aes_decrypt_to_string
    import secrets
    
    # Generate random key
    key = secrets.token_bytes(16)
    
    # Test string encryption/decryption
    plaintext = "This is a secret message!"
    ciphertext = aes_encrypt(plaintext, key)
    decrypted = aes_decrypt_to_string(ciphertext, key)
    
    assert decrypted == plaintext, "AES string encryption/decryption failed"
    
    # Test bytes encryption/decryption
    plaintext_bytes = b"Binary secret data"
    ciphertext = aes_encrypt(plaintext_bytes, key)
    decrypted_bytes = aes_decrypt(ciphertext, key)
    
    assert decrypted_bytes == plaintext_bytes, "AES bytes encryption/decryption failed"
    
    print("✓ AES encryption tests passed")

def test_dh():
    """Test Diffie-Hellman key exchange."""
    print("Testing Diffie-Hellman key exchange...")
    
    from app.crypto.dh import DHKeyExchange, derive_aes_key
    
    # Create two DH instances (client and server)
    dh_client = DHKeyExchange()
    dh_server = DHKeyExchange(dh_client.p, dh_client.g)  # Use same parameters
    
    # Generate keypairs
    client_private, client_public = dh_client.generate_keypair()
    server_private, server_public = dh_server.generate_keypair()
    
    # Compute shared secrets
    client_shared = dh_client.compute_shared_secret(server_public)
    server_shared = dh_server.compute_shared_secret(client_public)
    
    assert client_shared == server_shared, "DH shared secrets don't match"
    
    # Test key derivation
    client_key = dh_client.derive_session_key(client_shared)
    server_key = dh_server.derive_session_key(server_shared)
    
    assert client_key == server_key, "Derived session keys don't match"
    assert len(client_key) == 16, "Session key should be 16 bytes"
    
    print("✓ Diffie-Hellman tests passed")

def test_rsa_signing():
    """Test RSA signing and verification."""
    print("Testing RSA signing...")
    
    from app.crypto.sign import generate_rsa_keypair, rsa_sign, rsa_verify
    
    # Generate keypair
    private_key_pem, public_key_pem = generate_rsa_keypair(1024)  # Small key for testing
    
    # Test signing and verification
    test_data = "This message should be signed"
    signature = rsa_sign(test_data, private_key_pem)
    
    # Verify with correct key
    assert rsa_verify(test_data, signature, public_key_pem), "Valid signature not verified"
    
    # Verify with wrong data
    assert not rsa_verify("Wrong data", signature, public_key_pem), "Invalid signature verified"
    
    print("✓ RSA signing tests passed")

def test_certificates():
    """Test certificate generation and validation."""
    print("Testing certificate operations...")
    
    # This test requires generating actual certificates
    # For now, just test that the functions can be imported
    from app.crypto.pki import load_certificate, validate_certificate_validity
    from scripts.gen_ca import generate_ca_keypair, create_ca_certificate
    from scripts.gen_cert import generate_entity_keypair, create_entity_certificate
    
    # Generate a test CA
    ca_private_key = generate_ca_keypair(1024)  # Small key for testing
    ca_cert = create_ca_certificate(ca_private_key, "Test CA", 1)  # 1 day validity
    
    # Generate an entity certificate
    entity_private_key = generate_entity_keypair(1024)
    entity_cert = create_entity_certificate(
        entity_private_key, ca_private_key, ca_cert, "test.local", 1
    )
    
    # Test certificate validation
    assert validate_certificate_validity(ca_cert), "CA certificate validity check failed"
    assert validate_certificate_validity(entity_cert), "Entity certificate validity check failed"
    
    print("✓ Certificate tests passed")

def test_transcript():
    """Test transcript management."""
    print("Testing transcript management...")
    
    from app.storage.transcript import TranscriptManager
    
    # Create temporary transcript file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        transcript_path = f.name
    
    try:
        # Create transcript manager
        transcript = TranscriptManager(transcript_path)
        
        # Add some test messages
        transcript.add_message(1, 1000, "ct1", "sig1", "fingerprint1", "sent")
        transcript.add_message(2, 2000, "ct2", "sig2", "fingerprint2", "received")
        
        # Test transcript hash computation
        hash1 = transcript.compute_transcript_hash()
        hash2 = transcript.compute_transcript_hash()
        assert hash1 == hash2, "Transcript hash should be consistent"
        
        # Test sequence range
        first_seq, last_seq = transcript.get_sequence_range()
        assert first_seq == 1, "First sequence number incorrect"
        assert last_seq == 2, "Last sequence number incorrect"
        
        print("✓ Transcript tests passed")
        
    finally:
        # Clean up
        if os.path.exists(transcript_path):
            os.unlink(transcript_path)

def main():
    """Run all tests."""
    print("SecureChat Implementation Test Suite")
    print("=" * 40)
    
    try:
        test_utils()
        test_aes()
        test_dh()
        test_rsa_signing()
        test_certificates()
        test_transcript()
        
        print("\n" + "=" * 40)
        print("🎉 All tests passed!")
        print("\nThe SecureChat implementation appears to be working correctly.")
        print("You can now proceed with:")
        print("1. Setting up the database")
        print("2. Generating certificates")
        print("3. Running the server and client")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()