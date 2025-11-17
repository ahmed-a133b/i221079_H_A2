#!/usr/bin/env python3
"""
Tampering Test Client
Implements message tampering attacks to test integrity verification
"""

import json
import socket
import secrets
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.common.protocol import *
from app.common.utils import *
from app.crypto.aes import aes_encrypt, aes_decrypt_to_string
from app.crypto.dh import DHKeyExchange, derive_aes_key
from app.crypto.sign import rsa_sign
from app.crypto.pki import load_certificate, load_private_key


class TamperingTestClient:
    """Client that performs message tampering attacks"""
    
    def __init__(self, host: str, port: int, client_config: dict):
        self.host = host
        self.port = port
        self.client_config = client_config
        self.session_key = None
        self.client_cert_pem = None
        self.client_key_pem = None
        self.sequence_number = 0
        
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
        try:
            # Receive length
            length_bytes = sock.recv(4)
            if len(length_bytes) != 4:
                raise ConnectionError("Failed to receive message length")
            
            length = int.from_bytes(length_bytes, 'big')
            if length <= 0 or length > 1024 * 1024:  # Sanity check: max 1MB
                raise ValueError(f"Invalid message length: {length}")
            
            # Receive message in chunks if needed
            message_bytes = b''
            while len(message_bytes) < length:
                chunk = sock.recv(length - len(message_bytes))
                if not chunk:
                    raise ConnectionError("Connection closed during message receive")
                message_bytes += chunk
            
            # Parse JSON
            message_str = message_bytes.decode('utf-8')
            if not message_str.strip():
                raise ValueError("Received empty message")
            
            return json.loads(message_str)
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON response: {e}. Raw data: {message_bytes[:100]}")
        except Exception as e:
            raise ConnectionError(f"Error receiving message: {e}")
    
    def _create_valid_message(self, plaintext: str) -> dict:
        """Create a valid signed message"""
        self.sequence_number += 1
        
        # Encrypt message
        ct_bytes = aes_encrypt(plaintext, self.session_key)
        ct_b64 = b64e(ct_bytes)
        
        # Create signature
        timestamp = now_ms()
        data_to_sign = f"{self.sequence_number}|{timestamp}|{ct_b64}"
        signature = rsa_sign(data_to_sign, self.client_key_pem)
        sig_b64 = b64e(signature)
        
        return {
            "type": "msg",
            "seqno": self.sequence_number,
            "ts": timestamp,
            "ct": ct_b64,
            "sig": sig_b64
        }
    
    def _tamper_message(self, message: dict, tampering_pattern: dict) -> dict:
        """Apply tampering pattern to message"""
        tampered = message.copy()
        
        if 'bit_flip' in tampering_pattern:
            # Flip specific bits in ciphertext
            ct_bytes = bytearray(b64d(message['ct']))
            for bit_pos in tampering_pattern['bit_flip']:
                if bit_pos < len(ct_bytes) * 8:
                    byte_idx = bit_pos // 8
                    bit_idx = bit_pos % 8
                    ct_bytes[byte_idx] ^= (1 << bit_idx)
            
            tampered['ct'] = b64e(bytes(ct_bytes))
        
        if 'byte_corruption' in tampering_pattern:
            # Corrupt specific bytes in ciphertext
            ct_bytes = bytearray(b64d(message['ct']))
            for byte_pos in tampering_pattern['byte_corruption']:
                if byte_pos < len(ct_bytes):
                    ct_bytes[byte_pos] ^= 0xFF  # Flip all bits in byte
            
            tampered['ct'] = b64e(bytes(ct_bytes))
        
        return tampered
    
    def test_message_tampering(self, plaintext: str, tampering_pattern: dict) -> dict:
        """Test message tampering attack"""
        result = {
            'timestamp': now_ms(),
            'plaintext': plaintext,
            'tampering_pattern': tampering_pattern,
            'status': 'UNKNOWN'
        }
        
        try:
            print(f"DEBUG: Starting tampering test for message: '{plaintext}'")
            print(f"DEBUG: Tampering pattern: {tampering_pattern}")
            
            # Connect and authenticate
            print("DEBUG: Connecting and authenticating...")
            sock = self._connect_and_authenticate()
            print("DEBUG: Authentication completed successfully")
            
            try:
                # Create valid message
                print("DEBUG: Creating valid message...")
                valid_message = self._create_valid_message(plaintext)
                result['original_message'] = valid_message.copy()
                print(f"DEBUG: Valid message created with seq {valid_message['seqno']}")
                
                # Apply tampering
                print("DEBUG: Applying tampering...")
                tampered_message = self._tamper_message(valid_message, tampering_pattern)
                result['tampered_message'] = tampered_message.copy()
                print(f"DEBUG: Tampering applied. Original CT length: {len(valid_message['ct'])}, Tampered CT length: {len(tampered_message['ct'])}")
                
                # Send tampered message
                print("DEBUG: Sending tampered message to server...")
                self._send_message(sock, tampered_message)
                
                # Receive response with timeout
                sock.settimeout(10)  # 10 second timeout for response
                print("DEBUG: Waiting for server response...")
                try:
                    response = self._receive_message(sock)
                    result['server_response'] = response
                    print(f"DEBUG: Received response: {response}")
                    
                    # Check if server detected tampering
                    if response.get('status') == 'sig_fail':
                        result['status'] = 'SIG_FAIL'  # Tampering detected (expected)
                        print("DEBUG: Server correctly detected tampering (sig_fail)")
                    elif response.get('status') == 'ok':
                        result['status'] = 'ACCEPTED'  # Tampering not detected (bad!)
                        print("DEBUG: WARNING - Server accepted tampered message!")
                    else:
                        result['status'] = response.get('status', 'UNKNOWN')
                        print(f"DEBUG: Unexpected server response status: {result['status']}")
                        
                except socket.timeout:
                    result['status'] = 'TIMEOUT'
                    result['error'] = 'Server did not respond within timeout period'
                    print("DEBUG: Timeout waiting for server response")
                except Exception as e:
                    result['status'] = 'RESPONSE_ERROR'
                    result['error'] = f'Failed to receive server response: {str(e)}'
                    print(f"DEBUG: Error receiving response: {e}")
                    
            finally:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    sock.close()
                except:
                    pass
                
        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = str(e)
            print(f"DEBUG: Exception in test_message_tampering: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
        
        return result


def main():
    """Test tampering client directly"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test message tampering attacks')
    parser.add_argument('--host', default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=8444, help='Server port')
    parser.add_argument('--message', default='Test message for tampering', 
                       help='Message to tamper')
    
    args = parser.parse_args()
    
    # Basic client config (assumes standard test certificates)
    client_config = {
        'cert_path': 'certs/client-cert.pem',
        'key_path': 'certs/client-key.pem',
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'testpass123'
    }
    
    client = TamperingTestClient(args.host, args.port, client_config)
    
    # Test different tampering patterns
    patterns = [
        {'bit_flip': [0, 1, 2]},
        {'bit_flip': [8, 16, 24]},
        {'byte_corruption': [0, 5, 10]},
        {'byte_corruption': [1, 3, 7]}
    ]
    
    for i, pattern in enumerate(patterns):
        print(f"\nTest {i+1}: {pattern}")
        result = client.test_message_tampering(args.message, pattern)
        print(f"Result: {result['status']}")
        if 'error' in result:
            print(f"Error: {result['error']}")


if __name__ == "__main__":
    main()