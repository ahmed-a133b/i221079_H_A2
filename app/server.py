"""Server skeleton — plain TCP; no TLS. See assignment spec."""
import os
import json
import socket
import threading
import secrets
from dotenv import load_dotenv
from typing import Dict, Any, Optional

from .common.protocol import *
from .common.utils import *
from .crypto.aes import aes_encrypt, aes_decrypt_to_string
from .crypto.dh import DHKeyExchange, derive_aes_key
from .crypto.pki import validate_certificate_chain, get_certificate_fingerprint, CertificateValidationError
from .crypto.sign import rsa_sign, rsa_verify_with_cert
from .storage.db import get_database, DatabaseError
from .storage.transcript import TranscriptManager, create_session_receipt

# Load environment variables
load_dotenv()


class SecureChatServer:
    """Secure chat server implementation."""
    
    def __init__(self, host: str = None, port: int = None):
        """Initialize server."""
        self.host = host or os.getenv('SERVER_HOST', 'localhost')
        self.port = port or int(os.getenv('SERVER_PORT', 8443))
        
        # Load certificates
        self.ca_cert_path = os.getenv('CA_CERT_PATH', 'certs/ca-cert.pem')
        self.server_cert_path = os.getenv('SERVER_CERT_PATH', 'certs/server-cert.pem')
        self.server_key_path = os.getenv('SERVER_KEY_PATH', 'certs/server-key.pem')
        
        # Load server certificate and private key
        self.server_cert_pem = self._load_file(self.server_cert_path)
        self.server_key_pem = self._load_file(self.server_key_path)
        self.ca_cert_pem = self._load_file(self.ca_cert_path)
        
        # Database
        self.db = get_database()
        
        # Active connections
        self.active_connections: Dict[str, Dict[str, Any]] = {}
        
        # Per-user sequence tracking (prevents replay per user)
        self.user_sequences: Dict[str, int] = {}
        
        # Connection nonces (prevent replay of handshake)
        self.used_nonces: set = set()
        
    def _load_file(self, filepath: str) -> str:
        """Load file content."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            raise RuntimeError(f"Failed to load {filepath}: {e}")
    
    def _send_message(self, conn: socket.socket, message: Dict[str, Any]):
        """Send JSON message to client."""
        try:
            json_data = json.dumps(message)
            message_bytes = json_data.encode('utf-8')
            
            # Send length prefix (4 bytes) + message
            length = len(message_bytes)
            conn.send(length.to_bytes(4, 'big'))
            conn.send(message_bytes)
            
        except Exception as e:
            print(f"Error sending message: {e}")
    
    def _receive_message(self, conn: socket.socket) -> Optional[Dict[str, Any]]:
        """Receive JSON message from client."""
        try:
            # Receive length prefix (4 bytes)
            length_bytes = self._receive_exact(conn, 4)
            if not length_bytes:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            
            # Receive message
            message_bytes = self._receive_exact(conn, length)
            if not message_bytes:
                return None
            
            json_data = message_bytes.decode('utf-8')
            return json.loads(json_data)
            
        except Exception as e:
            print(f"Error receiving message: {e}")
            return None
    
    def _receive_exact(self, conn: socket.socket, length: int) -> Optional[bytes]:
        """Receive exact number of bytes."""
        data = b''
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def _handle_hello(self, conn: socket.socket, message: Dict[str, Any], 
                     conn_state: Dict[str, Any]) -> bool:
        """Handle client hello message."""
        try:
            hello = HelloMessage(**message)
            
            # Check for nonce replay (prevent handshake replay)
            client_nonce = getattr(hello, 'nonce', None)
            if client_nonce and client_nonce in self.used_nonces:
                print(f"[SECURITY] HANDSHAKE REPLAY DETECTED: nonce={client_nonce}")
                self._send_message(conn, {
                    "type": "status", 
                    "status": "replay",
                    "message": "Handshake replay detected - nonce reuse"
                })
                return False
            
            # Add nonce to used set
            if client_nonce:
                self.used_nonces.add(client_nonce)
            
            # Validate client certificate
            try:
                validate_certificate_chain(hello.client_cert, self.ca_cert_pem)
                conn_state['client_cert'] = hello.client_cert
                conn_state['client_cert_fingerprint'] = get_certificate_fingerprint(hello.client_cert)
                
            except CertificateValidationError as e:
                self._send_message(conn, {
                    "type": "status",
                    "status": "bad_cert",
                    "message": str(e)
                })
                return False
            
            # Send server hello
            server_nonce = b64e(secrets.token_bytes(16))
            server_hello = ServerHelloMessage(
                server_cert=self.server_cert_pem,
                nonce=server_nonce
            )
            
            self._send_message(conn, server_hello.model_dump())
            conn_state['phase'] = 'authenticated'
            
            return True
            
        except Exception as e:
            print(f"Error handling hello: {e}")
            self._send_message(conn, {
                "type": "status",
                "status": "error",
                "message": "Invalid hello message"
            })
            return False
    
    def _handle_register(self, conn: socket.socket, encrypted_payload: Dict[str, Any],
                        conn_state: Dict[str, Any]) -> bool:
        """Handle user registration."""
        try:
            # Decrypt registration data
            ct_bytes = b64d(encrypted_payload['ct'])
            temp_key = conn_state['temp_session_key']
            
            decrypted = aes_decrypt_to_string(ct_bytes, temp_key)
            register_data = json.loads(decrypted)
            register_msg = RegisterMessage(**register_data)
            
            # Register user in database
            try:
                # Register user with plain password (database will handle hashing and salting)
                self.db.register_user(register_msg.email, register_msg.username, register_msg.pwd)
                
                # Update the stored hash manually (in real implementation, modify db.py)
                # For now, just confirm registration
                
                self._send_message(conn, {
                    "type": "status",
                    "status": "ok",
                    "message": "Registration successful"
                })
                
                return True
                
            except DatabaseError as e:
                self._send_message(conn, {
                    "type": "status",
                    "status": "error", 
                    "message": str(e)
                })
                return False
                
        except Exception as e:
            print(f"Error handling registration: {e}")
            self._send_message(conn, {
                "type": "status",
                "status": "error",
                "message": "Registration failed"
            })
            return False
    
    def _handle_login(self, conn: socket.socket, encrypted_payload: Dict[str, Any],
                     conn_state: Dict[str, Any]) -> bool:
        """Handle user login."""
        try:
            # Decrypt login data
            ct_bytes = b64d(encrypted_payload['ct'])
            temp_key = conn_state['temp_session_key']
            
            decrypted = aes_decrypt_to_string(ct_bytes, temp_key)
            login_data = json.loads(decrypted)
            login_msg = LoginMessage(**login_data)
            
            # Authenticate user with actual password
            user = self.db.authenticate_user(login_msg.email, login_msg.pwd)
            
            if user:
                conn_state['authenticated_user'] = user
                self._send_message(conn, {
                    "type": "status", 
                    "status": "ok",
                    "message": "Login successful"
                })
                conn_state['phase'] = 'logged_in'
                return True
            else:
                self._send_message(conn, {
                    "type": "status",
                    "status": "error",
                    "message": "Invalid credentials"
                })
                return False
                
        except Exception as e:
            print(f"Error handling login: {e}")
            self._send_message(conn, {
                "type": "status",
                "status": "error", 
                "message": "Login failed"
            })
            return False
    
    def _handle_dh_client(self, conn: socket.socket, message: Dict[str, Any], 
                         conn_state: Dict[str, Any]) -> bool:
        """Handle DH key exchange from client."""
        try:
            dh_msg = DHClientMessage(**message)
            
            # Create DH instance and generate server keypair
            dh = DHKeyExchange(dh_msg.p, dh_msg.g)
            server_private, server_public = dh.generate_keypair()
            
            # Compute shared secret
            shared_secret = dh.compute_shared_secret(dh_msg.A)
            
            # Derive session key
            if conn_state['phase'] == 'authenticated':
                # This is temporary key for login/register
                temp_key = dh.derive_session_key(shared_secret)
                conn_state['temp_session_key'] = temp_key
            else:
                # This is the main session key
                session_key = dh.derive_session_key(shared_secret)
                conn_state['session_key'] = session_key
                conn_state['phase'] = 'secure_channel'
            
            # Send DH server response
            dh_response = DHServerMessage(B=server_public)
            self._send_message(conn, dh_response.model_dump())
            
            return True
            
        except Exception as e:
            print(f"Error handling DH exchange: {e}")
            return False
    
    def _handle_chat_message(self, conn: socket.socket, message: Dict[str, Any],
                           conn_state: Dict[str, Any]) -> bool:
        """Handle encrypted chat message."""
        try:
            chat_msg = ChatMessage(**message)
            
            # Verify sequence number (replay protection)
            last_seq = conn_state.get('last_seq', 0)
            # Try to get username from authenticated user or client cert fingerprint
            username = (conn_state.get('authenticated_user', {}).get('username') or 
                       conn_state.get('client_cert_fingerprint', 'unknown'))
            
            # Per-user sequence tracking
            user_last_seq = self.user_sequences.get(username, 0)
            
            # Check sequence number - must be greater than last seen for this user
            if chat_msg.seqno <= max(last_seq, user_last_seq):
                print(f"[SECURITY] MESSAGE REPLAY ATTACK DETECTED!")
                print(f"  - Sequence number: {chat_msg.seqno}")
                print(f"  - Connection last seq: {last_seq}")
                print(f"  - User global last seq: {user_last_seq}")
                print(f"  - User: {username}")
                print(f"  - Connection phase: {conn_state.get('phase', 'unknown')}")
                
                self._send_message(conn, {
                    "type": "status",
                    "status": "replay",
                    "message": "Message replay detected - sequence number violation"
                })
                return False
            
            # Update per-user sequence tracking
            self.user_sequences[username] = chat_msg.seqno
            
            # Verify signature
            data_to_verify = f"{chat_msg.seqno}|{chat_msg.ts}|{chat_msg.ct}"
            signature_bytes = b64d(chat_msg.sig)
            
            if not rsa_verify_with_cert(data_to_verify, signature_bytes, conn_state['client_cert']):
                self._send_message(conn, {
                    "type": "status",
                    "status": "sig_fail", 
                    "message": "Signature verification failed"
                })
                return False
            
            # Decrypt message
            ct_bytes = b64d(chat_msg.ct)
            session_key = conn_state['session_key']
            plaintext = aes_decrypt_to_string(ct_bytes, session_key)
            
            print(f"[CLIENT MESSAGE] {plaintext}")
            
            # Add to transcript
            transcript = conn_state['transcript']
            transcript.add_message(
                chat_msg.seqno, chat_msg.ts, chat_msg.ct, chat_msg.sig,
                conn_state['client_cert_fingerprint'], "received"
            )
            
            # Update sequence number
            conn_state['last_seq'] = chat_msg.seqno
            
            # Echo message back (encrypted)
            echo_msg = f"Server echo: {plaintext}"
            self._send_chat_message(conn, echo_msg, conn_state)
            
            return True
            
        except Exception as e:
            print(f"Error handling chat message: {e}")
            self._send_message(conn, {
                "type": "status",
                "status": "error",
                "message": "Message processing failed"
            })
            return False
    
    def _send_chat_message(self, conn: socket.socket, plaintext: str, 
                          conn_state: Dict[str, Any]):
        """Send encrypted chat message to client."""
        try:
            # Get next sequence number
            server_seq = conn_state.get('server_seq', 0) + 1
            conn_state['server_seq'] = server_seq
            
            # Encrypt message
            session_key = conn_state['session_key']
            ct_bytes = aes_encrypt(plaintext, session_key)
            ct_b64 = b64e(ct_bytes)
            
            # Create signature
            timestamp = now_ms()
            data_to_sign = f"{server_seq}|{timestamp}|{ct_b64}"
            signature = rsa_sign(data_to_sign, self.server_key_pem)
            sig_b64 = b64e(signature)
            
            # Create message
            chat_msg = ChatMessage(
                seqno=server_seq,
                ts=timestamp,
                ct=ct_b64,
                sig=sig_b64
            )
            
            # Send message
            self._send_message(conn, chat_msg.model_dump())
            
            # Add to transcript
            transcript = conn_state['transcript']
            transcript.add_message(
                server_seq, timestamp, ct_b64, sig_b64,
                conn_state['client_cert_fingerprint'], "sent"
            )
            
        except Exception as e:
            print(f"Error sending chat message: {e}")
    
    def _handle_client(self, conn: socket.socket, addr: tuple):
        """Handle individual client connection."""
        client_id = f"{addr[0]}:{addr[1]}"
        print(f"New client connected: {client_id}")
        
        # Initialize connection state
        conn_state = {
            'phase': 'init',
            'client_cert': None,
            'client_cert_fingerprint': None,
            'temp_session_key': None, 
            'session_key': None,
            'authenticated_user': None,
            'last_seq': 0,
            'server_seq': 0,
            'transcript': TranscriptManager(f"transcripts/server_{client_id.replace(':', '_')}.log")
        }
        
        self.active_connections[client_id] = conn_state
        
        try:
            while True:
                message = self._receive_message(conn)
                if not message:
                    break
                
                msg_type = message.get('type')
                
                if msg_type == 'hello':
                    if not self._handle_hello(conn, message, conn_state):
                        break
                        
                elif msg_type == 'dh_client':
                    if not self._handle_dh_client(conn, message, conn_state):
                        break
                        
                elif msg_type == 'encrypted':
                    # Handle encrypted register/login
                    if conn_state['phase'] == 'authenticated':
                        # Try to decrypt and determine if register or login
                        try:
                            ct_bytes = b64d(message['ct'])
                            temp_key = conn_state['temp_session_key']
                            decrypted = aes_decrypt_to_string(ct_bytes, temp_key)
                            payload = json.loads(decrypted)
                            
                            if payload.get('type') == 'register':
                                if not self._handle_register(conn, message, conn_state):
                                    break
                            elif payload.get('type') == 'login':
                                if not self._handle_login(conn, message, conn_state):
                                    break
                                    
                        except Exception as e:
                            print(f"Error handling encrypted payload: {e}")
                            break
                            
                elif msg_type == 'msg':
                    if conn_state['phase'] == 'secure_channel':
                        if not self._handle_chat_message(conn, message, conn_state):
                            break
                    else:
                        self._send_message(conn, {
                            "type": "status",
                            "status": "error",
                            "message": "Not in secure channel"
                        })
                        
                elif msg_type == 'quit':
                    break
                    
                else:
                    print(f"Unknown message type: {msg_type}")
        
        except Exception as e:
            print(f"Error handling client {client_id}: {e}")
        
        finally:
            # Generate session receipt
            if conn_state.get('transcript'):
                try:
                    receipt = create_session_receipt(
                        conn_state['transcript'], 
                        "server",
                        self.server_key_pem
                    )
                    
                    # Send receipt to client
                    self._send_message(conn, receipt)
                    
                    # Save receipt
                    receipt_path = f"transcripts/server_{client_id.replace(':', '_')}_receipt.json"
                    with open(receipt_path, 'w') as f:
                        json.dump(receipt, f, indent=2)
                        
                except Exception as e:
                    print(f"Error creating session receipt: {e}")
            
            conn.close()
            if client_id in self.active_connections:
                del self.active_connections[client_id]
            print(f"Client disconnected: {client_id}")
    
    def start(self):
        """Start the server."""
        print(f"Starting SecureChat Server on {self.host}:{self.port}")
        
        # Initialize database
        try:
            self.db.initialize_database()
            print("Database initialized")
        except Exception as e:
            print(f"Database initialization failed: {e}")
            return
        
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"Server listening on {self.host}:{self.port}")
            
            while True:
                conn, addr = server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\nServer shutting down...")
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            server_socket.close()


def main():
    """Main server function."""
    server = SecureChatServer()
    server.start()


if __name__ == "__main__":
    main()
