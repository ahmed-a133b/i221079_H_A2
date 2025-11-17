#!/usr/bin/env python3
"""
Replay Attack Test Client
Implements replay attacks to test sequence number validation
"""

import json
import socket
import secrets
import time
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


class ReplayTestClient:
    """Client that performs replay attacks"""
    
    def __init__(self, host: str, port: int, client_config: dict):
        self.host = host
        self.port = port
        self.client_config = client_config
        self.session_key = None
        self.client_cert_pem = None
        self.client_key_pem = None
        self.message_history = []  # Store sent messages for replay
        
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
    
    def _create_message(self, seqno: int, plaintext: str) -> dict:
        """Create a signed message with specific sequence number"""
        # Encrypt message
        ct_bytes = aes_encrypt(plaintext, self.session_key)
        ct_b64 = b64e(ct_bytes)
        
        # Create signature
        timestamp = now_ms()
        data_to_sign = f"{seqno}|{timestamp}|{ct_b64}"
        signature = rsa_sign(data_to_sign, self.client_key_pem)
        sig_b64 = b64e(signature)
        
        return {
            "type": "msg",
            "seqno": seqno,
            "ts": timestamp,
            "ct": ct_b64,
            "sig": sig_b64
        }
    
    def send_initial_messages(self, count: int) -> list:
        """Send initial sequence of messages"""
        results = []
        
        try:
            sock = self._connect_and_authenticate()
            
            try:
                for i in range(1, count + 1):
                    message_text = f"Initial message {i}"
                    message = self._create_message(i, message_text)
                    
                    # Store for potential replay
                    self.message_history.append(message.copy())
                    
                    # Send message
                    self._send_message(sock, message)
                    
                    # Receive response
                    response = self._receive_message(sock)
                    
                    result = {
                        'seqno': i,
                        'status': response.get('status', 'unknown'),
                        'message': message_text,
                        'timestamp': message['ts']
                    }
                    results.append(result)
                    
                    print(f"Sent message {i}: {result['status']}")
                    time.sleep(0.5)  # Small delay between messages
                    
            finally:
                sock.close()
                
        except Exception as e:
            print(f"Error sending initial messages: {e}")
        
        return results
    
    def replay_message(self, seqno: int) -> dict:
        """Attempt to replay a specific message by sequence number"""
        result = {
            'timestamp': now_ms(),
            'replayed_seqno': seqno,
            'status': 'UNKNOWN'
        }
        
        # Find the original message
        original_message = None
        for msg in self.message_history:
            if msg['seqno'] == seqno:
                original_message = msg.copy()
                break
        
        if not original_message:
            result['status'] = 'ERROR'
            result['error'] = f'No original message found for seqno {seqno}'
            return result
        
        try:
            # Connect (new session)
            sock = self._connect_and_authenticate()
            
            try:
                # Attempt to send the replayed message
                print(f"Replaying message with seqno {seqno}...")
                self._send_message(sock, original_message)
                
                # Receive response
                response = self._receive_message(sock)
                result['server_response'] = response
                
                # Check if server detected replay
                if response.get('status') == 'replay':
                    result['status'] = 'REPLAY_FAIL'  # Replay detected (expected)
                elif response.get('status') == 'ok':
                    result['status'] = 'ACCEPTED'  # Replay not detected (bad!)
                else:
                    result['status'] = response.get('status', 'UNKNOWN')
                    
            finally:
                sock.close()
                
        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = str(e)
        
        return result
    
    def test_out_of_order_replay(self) -> dict:
        """Test sending messages out of sequence order"""
        result = {
            'timestamp': now_ms(),
            'test_type': 'out_of_order',
            'status': 'UNKNOWN'
        }
        
        try:
            sock = self._connect_and_authenticate()
            
            try:
                # Send messages in wrong order: 1, 3, 2
                messages = [
                    (1, "Message 1"),
                    (3, "Message 3 (out of order)"),
                    (2, "Message 2 (should fail)")
                ]
                
                responses = []
                for seqno, text in messages:
                    message = self._create_message(seqno, text)
                    self._send_message(sock, message)
                    
                    response = self._receive_message(sock)
                    responses.append({
                        'seqno': seqno,
                        'text': text,
                        'status': response.get('status'),
                        'response': response
                    })
                    
                    print(f"Seq {seqno}: {response.get('status')}")
                
                result['responses'] = responses
                
                # Check if any out-of-order was detected
                replay_detected = any(r['status'] == 'replay' for r in responses[1:])
                result['status'] = 'REPLAY_FAIL' if replay_detected else 'ACCEPTED'
                
            finally:
                sock.close()
                
        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = str(e)
        
        return result
    
    def test_duplicate_message_replay(self) -> dict:
        """Test sending exact duplicate message"""
        result = {
            'timestamp': now_ms(),
            'test_type': 'exact_duplicate',
            'status': 'UNKNOWN'
        }
        
        try:
            sock = self._connect_and_authenticate()
            
            try:
                # Create a message
                message = self._create_message(1, "Duplicate test message")
                
                # Send it twice
                print("Sending message first time...")
                self._send_message(sock, message)
                response1 = self._receive_message(sock)
                
                print("Sending exact same message again...")
                self._send_message(sock, message)
                response2 = self._receive_message(sock)
                
                result['first_response'] = response1
                result['second_response'] = response2
                
                # Check if duplicate was detected
                if response2.get('status') == 'replay':
                    result['status'] = 'REPLAY_FAIL'  # Duplicate detected (expected)
                elif response2.get('status') == 'ok':
                    result['status'] = 'ACCEPTED'  # Duplicate not detected (bad!)
                else:
                    result['status'] = response2.get('status', 'UNKNOWN')
                    
            finally:
                sock.close()
                
        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = str(e)
        
        return result


def main():
    """Test replay client directly"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test replay attacks')
    parser.add_argument('--host', default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=8445, help='Server port')
    parser.add_argument('--messages', type=int, default=5, help='Number of initial messages')
    
    args = parser.parse_args()
    
    # Basic client config (assumes standard test certificates)
    client_config = {
        'cert_path': 'certs/client-cert.pem',
        'key_path': 'certs/client-key.pem',
        'username': 'replayuser',
        'email': 'replay@example.com',
        'password': 'replaypass123'
    }
    
    client = ReplayTestClient(args.host, args.port, client_config)
    
    # Send initial messages
    print(f"Sending {args.messages} initial messages...")
    initial_results = client.send_initial_messages(args.messages)
    
    # Test replay attacks
    print("\nTesting replay attacks...")
    
    # Test replaying individual messages
    for seqno in [1, 3, 2]:  # Try replaying in different order
        print(f"\nTesting replay of sequence {seqno}")
        result = client.replay_message(seqno)
        print(f"Result: {result['status']}")
        if 'error' in result:
            print(f"Error: {result['error']}")
    
    # Test out-of-order messages
    print("\nTesting out-of-order messages...")
    ooo_result = client.test_out_of_order_replay()
    print(f"Out-of-order result: {ooo_result['status']}")
    
    # Test exact duplicate
    print("\nTesting exact duplicate message...")
    dup_result = client.test_duplicate_message_replay()
    print(f"Duplicate result: {dup_result['status']}")


if __name__ == "__main__":
    main()