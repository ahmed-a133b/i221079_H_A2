#!/usr/bin/env python3
"""
Verification Test Client
Tests non-repudiation through transcript and receipt verification
"""

import json
import socket
import secrets
import hashlib
import time
import os
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.common.protocol import *
from app.common.utils import *
from app.crypto.aes import aes_encrypt, aes_decrypt_to_string
from app.crypto.dh import DHKeyExchange, derive_aes_key
from app.crypto.sign import rsa_sign, rsa_verify_with_cert
from app.crypto.pki import load_certificate, load_private_key
from app.storage.transcript import TranscriptManager


class VerificationTestClient:
    """Client that generates and verifies transcripts for non-repudiation"""
    
    def __init__(self, host: str, port: int, client_config: dict, output_dir: str):
        self.host = host
        self.port = port
        self.client_config = client_config
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.session_key = None
        self.client_cert_pem = None
        self.client_key_pem = None
        self.server_cert_pem = None
        self.transcript = None
        self.session_receipt = None
        
    def _load_credentials(self):
        """Load client certificate and private key"""
        try:
            with open(self.client_config['cert_path'], 'r') as f:
                self.client_cert_pem = f.read()
            with open(self.client_config['key_path'], 'r') as f:
                self.client_key_pem = f.read()
        except Exception as e:
            raise RuntimeError(f"Failed to load client credentials: {e}")
    
    def _connect_and_authenticate(self) -> socket.socket:
        """Establish connection and complete authentication"""
        self._load_credentials()
        
        # Initialize transcript
        transcript_path = self.output_dir / f"client_transcript_{int(time.time())}.log"
        self.transcript = TranscriptManager(str(transcript_path))
        
        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)  # 30 second timeout
        sock.connect((self.host, self.port))
        
        # Send hello
        hello = HelloMessage(client_cert=self.client_cert_pem, nonce=b64e(secrets.token_bytes(16)))
        self._send_message(sock, hello.model_dump())
        
        # Receive server hello
        server_hello_data = self._receive_message(sock)
        server_hello = ServerHelloMessage(**server_hello_data)
        self.server_cert_pem = server_hello.server_cert
        
        # DH key exchange for temporary key
        dh = DHKeyExchange()
        client_private, client_public = dh.generate_keypair()
        
        dh_client = DHClientMessage(p=dh.p, g=dh.g, A=client_public)
        self._send_message(sock, dh_client.model_dump())
        
        dh_server_data = self._receive_message(sock)
        dh_server = DHServerMessage(**dh_server_data)
        
        # Compute shared secret and temp key
        shared_secret = dh.compute_shared_secret(dh_server.B)
        temp_key = dh.derive_session_key(shared_secret)
        
        # Try to register user first (in case they don't exist)
        register_data = {
            "type": "register",
            "email": self.client_config['email'],
            "username": self.client_config['username'],
            "pwd": self.client_config['password']
        }
        
        encrypted_register = aes_encrypt(json.dumps(register_data), temp_key)
        self._send_message(sock, {"type": "encrypted", "ct": b64e(encrypted_register)})
        
        # Receive registration response (ignore if user already exists)
        register_response = self._receive_message(sock)
        
        # Try to register user first (in case they don't exist)
        try:
            register_data = {
                "type": "register",
                "email": self.client_config['email'],
                "username": self.client_config['username'],
                "pwd": self.client_config['password']
            }
            
            encrypted_register = aes_encrypt(json.dumps(register_data), temp_key)
            self._send_message(sock, {"type": "encrypted", "ct": b64e(encrypted_register)})
            
            # Receive register response (might fail if user exists, that's ok)
            register_response = self._receive_message(sock)
        except Exception:
            pass  # Registration might fail if user exists, continue to login
        
        # Login
        login_data = {
            "type": "login",
            "email": self.client_config['email'],
            "pwd": self.client_config['password']
        }
        
        encrypted_login = aes_encrypt(json.dumps(login_data), temp_key)
        self._send_message(sock, {"type": "encrypted", "ct": b64e(encrypted_login)})
        
        # Receive login response
        login_response = self._receive_message(sock)
        if login_response.get('status') != 'ok':
            raise RuntimeError(f"Login failed: {login_response}")
        
        # DH key exchange for session key
        session_dh = DHKeyExchange()
        session_private, session_public = session_dh.generate_keypair()
        
        session_dh_client = DHClientMessage(p=session_dh.p, g=session_dh.g, A=session_public)
        self._send_message(sock, session_dh_client.model_dump())
        
        session_dh_server_data = self._receive_message(sock)
        session_dh_server = DHServerMessage(**session_dh_server_data)
        
        # Compute session key
        session_shared = session_dh.compute_shared_secret(session_dh_server.B)
        self.session_key = session_dh.derive_session_key(session_shared)
        
        return sock
    
    def _send_message(self, sock: socket.socket, message: dict):
        """Send JSON message to server"""
        json_data = json.dumps(message)
        message_bytes = json_data.encode('utf-8')
        
        length = len(message_bytes)
        sock.send(length.to_bytes(4, 'big'))
        sock.send(message_bytes)
    
    def _receive_message(self, sock: socket.socket) -> dict:
        """Receive JSON message from server"""
        # Receive length
        length_bytes = sock.recv(4)
        length = int.from_bytes(length_bytes, 'big')
        
        # Receive message
        message_bytes = sock.recv(length)
        return json.loads(message_bytes.decode('utf-8'))
    
    def _send_chat_message(self, sock: socket.socket, seqno: int, plaintext: str):
        """Send a chat message and record in transcript"""
        # Encrypt message
        ct_bytes = aes_encrypt(plaintext, self.session_key)
        ct_b64 = b64e(ct_bytes)
        
        # Create signature
        timestamp = now_ms()
        data_to_sign = f"{seqno}|{timestamp}|{ct_b64}"
        signature = rsa_sign(data_to_sign, self.client_key_pem)
        sig_b64 = b64e(signature)
        
        message = {
            "type": "msg",
            "seqno": seqno,
            "ts": timestamp,
            "ct": ct_b64,
            "sig": sig_b64
        }
        
        # Add to transcript
        from app.crypto.pki import get_certificate_fingerprint
        client_fingerprint = get_certificate_fingerprint(self.client_cert_pem)
        
        self.transcript.add_message(
            seqno, timestamp, ct_b64, sig_b64, client_fingerprint, "sent"
        )
        
        # Send message
        self._send_message(sock, message)
        
        return message
    
    def generate_test_session(self, message_count: int) -> dict:
        """Generate a complete test session with specified number of messages"""
        result = {
            'timestamp': time.time(),
            'message_count': message_count,
            'messages_sent': [],
            'server_responses': []
        }
        
        try:
            sock = self._connect_and_authenticate()
            
            try:
                for i in range(1, message_count + 1):
                    plaintext = f"Verification test message {i} - timestamp {now_ms()}"
                    
                    # Send message
                    message = self._send_chat_message(sock, i, plaintext)
                    result['messages_sent'].append({
                        'seqno': i,
                        'plaintext': plaintext,
                        'message': message
                    })
                    
                    # Receive server response
                    response = self._receive_message(sock)
                    result['server_responses'].append(response)
                    
                    # Add server response to transcript if it's a message
                    if response.get('type') == 'msg':
                        from app.crypto.pki import get_certificate_fingerprint
                        server_fingerprint = get_certificate_fingerprint(self.server_cert_pem)
                        
                        self.transcript.add_message(
                            response['seqno'], response['ts'], response['ct'], 
                            response['sig'], server_fingerprint, "received"
                        )
                    
                    print(f"Message {i} sent and acknowledged")
                    time.sleep(0.2)
                
                # Send quit to get session receipt
                self._send_message(sock, {"type": "quit"})
                
                # Receive session receipt
                try:
                    receipt = self._receive_message(sock)
                    if receipt.get('type') == 'session_receipt':
                        self.session_receipt = receipt
                        result['session_receipt'] = receipt
                        print("Session receipt received")
                    
                except Exception:
                    print("No session receipt received")
                
            finally:
                sock.close()
                
        except Exception as e:
            result['error'] = str(e)
            print(f"Error in test session: {e}")
        
        return result
    
    def export_transcript(self) -> str:
        """Export transcript to file"""
        if not self.transcript:
            raise RuntimeError("No transcript available")
        
        transcript_path = self.output_dir / "exported_transcript.json"
        
        # Export transcript data
        transcript_data = {
            'messages': self.transcript.entries,
            'session_info': {
                'client_cert': self.client_cert_pem,
                'server_cert': self.server_cert_pem,
                'export_timestamp': time.time()
            }
        }
        
        with open(transcript_path, 'w') as f:
            json.dump(transcript_data, f, indent=2)
        
        print(f"Transcript exported to: {transcript_path}")
        return str(transcript_path)
    
    def export_receipt(self) -> str:
        """Export session receipt to file"""
        if not self.session_receipt:
            raise RuntimeError("No session receipt available")
        
        receipt_path = self.output_dir / "session_receipt.json"
        
        with open(receipt_path, 'w') as f:
            json.dump(self.session_receipt, f, indent=2)
        
        print(f"Session receipt exported to: {receipt_path}")
        return str(receipt_path)
    
    def run_offline_verification(self) -> dict:
        """Run comprehensive offline verification"""
        result = {
            'timestamp': time.time(),
            'verification_results': {}
        }
        
        if not self.transcript:
            result['error'] = "No transcript available for verification"
            return result
        
        print("Running offline verification...")
        
        # 1. Verify each message signature
        message_verifications = []
        for msg in self.transcript.entries:
            verification = self._verify_message_signature(msg)
            message_verifications.append(verification)
        
        result['verification_results']['messages'] = message_verifications
        
        # 2. Verify session receipt
        if self.session_receipt:
            receipt_verification = self._verify_session_receipt()
            result['verification_results']['receipt'] = receipt_verification
        
        # 3. Compute transcript integrity hash
        transcript_hash = self._compute_transcript_hash()
        result['verification_results']['transcript_hash'] = transcript_hash
        
        # Summary
        total_messages = len(message_verifications)
        valid_messages = sum(1 for v in message_verifications if v['signature_valid'])
        
        result['summary'] = {
            'total_messages': total_messages,
            'valid_signatures': valid_messages,
            'signature_verification_rate': valid_messages / total_messages if total_messages > 0 else 0,
            'receipt_valid': result['verification_results'].get('receipt', {}).get('signature_valid', False)
        }
        
        print(f"Verification complete: {valid_messages}/{total_messages} messages valid")
        return result
    
    def _verify_message_signature(self, message: dict) -> dict:
        """Verify a single message signature"""
        try:
            # Reconstruct signature data
            data_to_verify = f"{message['seqno']}|{message['timestamp']}|{message['ciphertext']}"
            signature_bytes = b64d(message['signature'])
            
            # Determine which certificate to use
            if message['direction'] == 'sent':
                cert_pem = self.client_cert_pem
                signer = "client"
            else:
                cert_pem = self.server_cert_pem
                signer = "server"
            
            # Verify signature
            is_valid = rsa_verify_with_cert(data_to_verify, signature_bytes, cert_pem)
            
            # Compute message hash for integrity
            message_hash = hashlib.sha256(data_to_verify.encode()).hexdigest()
            
            return {
                'seqno': message['seqno'],
                'direction': message['direction'],
                'signer': signer,
                'signature_valid': is_valid,
                'message_hash': message_hash,
                'timestamp': message['timestamp']
            }
            
        except Exception as e:
            return {
                'seqno': message.get('seqno', 'unknown'),
                'direction': message.get('direction', 'unknown'),
                'signature_valid': False,
                'error': str(e)
            }
    
    def _verify_session_receipt(self) -> dict:
        """Verify session receipt signature"""
        try:
            receipt = self.session_receipt
            
            # Reconstruct receipt data for verification
            transcript_hash = receipt['transcript_hash']
            session_info = f"{receipt['session_id']}|{receipt['timestamp']}|{transcript_hash}"
            
            # Verify server signature on receipt
            signature_bytes = b64d(receipt['signature'])
            is_valid = rsa_verify_with_cert(session_info, signature_bytes, self.server_cert_pem)
            
            return {
                'receipt_type': receipt['type'],
                'session_id': receipt['session_id'],
                'signature_valid': is_valid,
                'transcript_hash': transcript_hash,
                'timestamp': receipt['timestamp']
            }
            
        except Exception as e:
            return {
                'signature_valid': False,
                'error': str(e)
            }
    
    def _compute_transcript_hash(self) -> str:
        """Compute integrity hash of entire transcript"""
        # Create canonical representation of transcript
        messages_data = []
        for msg in self.transcript.entries:
            msg_str = f"{msg['seqno']}|{msg['timestamp']}|{msg['ciphertext']}|{msg['signature']}|{msg['direction']}"
            messages_data.append(msg_str)
        
        # Compute hash of concatenated messages
        transcript_content = '\n'.join(sorted(messages_data))  # Sort for deterministic hash
        return hashlib.sha256(transcript_content.encode()).hexdigest()
    
    def test_tamper_detection(self, tamper_tests: dict) -> dict:
        """Test detection of various tampering attempts"""
        result = {
            'timestamp': time.time(),
            'tamper_tests': {}
        }
        
        if not self.transcript or not self.transcript.entries:
            result['error'] = "No messages available for tampering tests"
            return result
        
        # Test modifying message content
        if tamper_tests.get('modify_message_content'):
            result['tamper_tests']['modified_content'] = self._test_content_tampering()
        
        # Test modifying signature
        if tamper_tests.get('modify_signature'):
            result['tamper_tests']['modified_signature'] = self._test_signature_tampering()
        
        # Test modifying sequence number
        if tamper_tests.get('modify_sequence'):
            result['tamper_tests']['modified_sequence'] = self._test_sequence_tampering()
        
        # Test modifying timestamp
        if tamper_tests.get('modify_timestamp'):
            result['tamper_tests']['modified_timestamp'] = self._test_timestamp_tampering()
        
        return result
    
    def _test_content_tampering(self) -> dict:
        """Test tampering with message content"""
        if not self.transcript.entries:
            return {'error': 'No messages to tamper'}
        
        # Take first message and tamper with ciphertext
        original_msg = self.transcript.entries[0].copy()
        tampered_msg = original_msg.copy()
        
        # Flip some bits in ciphertext
        ct_bytes = bytearray(b64d(original_msg['ciphertext']))
        ct_bytes[0] ^= 0xFF  # Flip all bits in first byte
        tampered_msg['ciphertext'] = b64e(bytes(ct_bytes))
        
        # Verify original vs tampered
        original_verification = self._verify_message_signature(original_msg)
        tampered_verification = self._verify_message_signature(tampered_msg)
        
        return {
            'original_valid': original_verification['signature_valid'],
            'tampered_valid': tampered_verification['signature_valid'],
            'tampering_detected': original_verification['signature_valid'] and not tampered_verification['signature_valid']
        }
    
    def _test_signature_tampering(self) -> dict:
        """Test tampering with signature"""
        if not self.transcript.entries:
            return {'error': 'No messages to tamper'}
        
        original_msg = self.transcript.entries[0].copy()
        tampered_msg = original_msg.copy()
        
        # Flip bits in signature
        sig_bytes = bytearray(b64d(original_msg['signature']))
        sig_bytes[0] ^= 0xFF
        tampered_msg['signature'] = b64e(bytes(sig_bytes))
        
        # Verify original vs tampered
        original_verification = self._verify_message_signature(original_msg)
        tampered_verification = self._verify_message_signature(tampered_msg)
        
        return {
            'original_valid': original_verification['signature_valid'],
            'tampered_valid': tampered_verification['signature_valid'],
            'tampering_detected': original_verification['signature_valid'] and not tampered_verification['signature_valid']
        }
    
    def _test_sequence_tampering(self) -> dict:
        """Test tampering with sequence number"""
        if not self.transcript.entries:
            return {'error': 'No messages to tamper'}
        
        original_msg = self.transcript.entries[0].copy()
        tampered_msg = original_msg.copy()
        
        # Change sequence number
        tampered_msg['seqno'] = original_msg['seqno'] + 100
        
        # Verify (signature should be invalid because seqno is part of signed data)
        original_verification = self._verify_message_signature(original_msg)
        tampered_verification = self._verify_message_signature(tampered_msg)
        
        return {
            'original_valid': original_verification['signature_valid'],
            'tampered_valid': tampered_verification['signature_valid'],
            'tampering_detected': original_verification['signature_valid'] and not tampered_verification['signature_valid']
        }
    
    def _test_timestamp_tampering(self) -> dict:
        """Test tampering with timestamp"""
        if not self.transcript.entries:
            return {'error': 'No messages to tamper'}
        
        original_msg = self.transcript.entries[0].copy()
        tampered_msg = original_msg.copy()
        
        # Change timestamp
        tampered_msg['timestamp'] = original_msg['timestamp'] + 100000
        
        # Verify (signature should be invalid because timestamp is part of signed data)
        original_verification = self._verify_message_signature(original_msg)
        tampered_verification = self._verify_message_signature(tampered_msg)
        
        return {
            'original_valid': original_verification['signature_valid'],
            'tampered_valid': tampered_verification['signature_valid'],
            'tampering_detected': original_verification['signature_valid'] and not tampered_verification['signature_valid']
        }


def main():
    """Test verification client directly"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test non-repudiation verification')
    parser.add_argument('--host', default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=8446, help='Server port')
    parser.add_argument('--messages', type=int, default=10, help='Number of test messages')
    parser.add_argument('--output', default='tests/verification_output', help='Output directory')
    
    args = parser.parse_args()
    
    # Basic client config
    client_config = {
        'cert_path': 'certs/client-cert.pem',
        'key_path': 'certs/client-key.pem',
        'username': 'verifyuser',
        'email': 'verify@example.com',
        'password': 'verifypass123'
    }
    
    client = VerificationTestClient(args.host, args.port, client_config, args.output)
    
    # Generate test session
    print(f"Generating test session with {args.messages} messages...")
    session_result = client.generate_test_session(args.messages)
    
    if 'error' in session_result:
        print(f"Error: {session_result['error']}")
        return
    
    # Export transcript and receipt
    print("Exporting transcript and receipt...")
    transcript_path = client.export_transcript()
    
    if client.session_receipt:
        receipt_path = client.export_receipt()
    
    # Run verification
    print("Running offline verification...")
    verification_result = client.run_offline_verification()
    
    print("\nVerification Summary:")
    print(f"Messages verified: {verification_result['summary']['valid_signatures']}/{verification_result['summary']['total_messages']}")
    print(f"Receipt valid: {verification_result['summary']['receipt_valid']}")
    
    # Test tampering detection
    print("\nTesting tamper detection...")
    tamper_tests = {
        'modify_message_content': True,
        'modify_signature': True,
        'modify_sequence': True,
        'modify_timestamp': True
    }
    
    tamper_result = client.test_tamper_detection(tamper_tests)
    
    for test_name, test_result in tamper_result['tamper_tests'].items():
        if 'tampering_detected' in test_result:
            status = "DETECTED" if test_result['tampering_detected'] else "NOT DETECTED"
            print(f"{test_name}: {status}")
    
    # Save all results
    results_path = Path(args.output) / 'verification_results.json'
    with open(results_path, 'w') as f:
        json.dump({
            'session': session_result,
            'verification': verification_result,
            'tamper_detection': tamper_result
        }, f, indent=2, default=str)
    
    print(f"\nAll results saved to: {results_path}")


if __name__ == "__main__":
    main()