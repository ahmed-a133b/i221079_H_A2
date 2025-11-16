"""Client skeleton — plain TCP; no TLS. See assignment spec."""
import os
import json
import socket
import secrets
import getpass
import threading
from dotenv import load_dotenv
from typing import Dict, Any, Optional

from .common.protocol import *
from .common.utils import *
from .crypto.aes import aes_encrypt, aes_decrypt_to_string
from .crypto.dh import DHKeyExchange, derive_aes_key
from .crypto.pki import validate_certificate_chain, get_certificate_fingerprint, CertificateValidationError
from .crypto.sign import rsa_sign, rsa_verify_with_cert
from .storage.transcript import TranscriptManager, create_session_receipt

# Load environment variables
load_dotenv()


class SecureChatClient:
    """Secure chat client implementation."""
    
    def __init__(self, host: str = None, port: int = None):
        """Initialize client."""
        self.host = host or os.getenv('SERVER_HOST', 'localhost')
        self.port = port or int(os.getenv('SERVER_PORT', 8443))
        
        # Load certificates
        self.ca_cert_path = os.getenv('CA_CERT_PATH', 'certs/ca-cert.pem')
        self.client_cert_path = os.getenv('CLIENT_CERT_PATH', 'certs/client-cert.pem')
        self.client_key_path = os.getenv('CLIENT_KEY_PATH', 'certs/client-key.pem')
        
        # Load client certificate and private key
        self.client_cert_pem = self._load_file(self.client_cert_path)
        self.client_key_pem = self._load_file(self.client_key_path)
        self.ca_cert_pem = self._load_file(self.ca_cert_path)
        
        # Connection state
        self.socket = None
        self.server_cert = None
        self.server_cert_fingerprint = None
        self.temp_session_key = None
        self.session_key = None
        self.last_seq = 0
        self.client_seq = 0
        
        # Transcript
        self.transcript = None
        
        # Control flags
        self.running = False
        
    def _load_file(self, filepath: str) -> str:
        """Load file content."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            raise RuntimeError(f"Failed to load {filepath}: {e}")
    
    def _send_message(self, message: Dict[str, Any]):
        """Send JSON message to server."""
        try:
            json_data = json.dumps(message)
            message_bytes = json_data.encode('utf-8')
            
            # Send length prefix (4 bytes) + message
            length = len(message_bytes)
            self.socket.send(length.to_bytes(4, 'big'))
            self.socket.send(message_bytes)
            
        except Exception as e:
            print(f"Error sending message: {e}")
    
    def _receive_message(self) -> Optional[Dict[str, Any]]:
        """Receive JSON message from server."""
        try:
            # Receive length prefix (4 bytes)
            length_bytes = self._receive_exact(4)
            if not length_bytes:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            
            # Receive message
            message_bytes = self._receive_exact(length)
            if not message_bytes:
                return None
            
            json_data = message_bytes.decode('utf-8')
            return json.loads(json_data)
            
        except Exception as e:
            if self.running:  # Only print error if we're supposed to be running
                print(f"Error receiving message: {e}")
            return None
    
    def _receive_exact(self, length: int) -> Optional[bytes]:
        """Receive exact number of bytes."""
        data = b''
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def _perform_handshake(self) -> bool:
        """Perform initial handshake with server."""
        try:
            # Send client hello
            client_nonce = b64e(secrets.token_bytes(16))
            hello = HelloMessage(
                client_cert=self.client_cert_pem,
                nonce=client_nonce
            )
            
            self._send_message(hello.model_dump())
            
            # Receive server hello
            response = self._receive_message()
            if not response or response.get('type') != 'server_hello':
                print("Invalid server hello response")
                return False
            
            server_hello = ServerHelloMessage(**response)
            
            # Validate server certificate
            try:
                validate_certificate_chain(server_hello.server_cert, self.ca_cert_pem, "server.local")
                self.server_cert = server_hello.server_cert
                self.server_cert_fingerprint = get_certificate_fingerprint(server_hello.server_cert)
                
            except CertificateValidationError as e:
                print(f"Server certificate validation failed: {e}")
                return False
            
            print("Handshake completed successfully")
            return True
            
        except Exception as e:
            print(f"Handshake failed: {e}")
            return False
    
    def _perform_temp_dh_exchange(self) -> bool:
        """Perform temporary DH exchange for login/register."""
        try:
            # Create DH instance and generate client keypair
            dh = DHKeyExchange()
            client_private, client_public = dh.generate_keypair()
            
            # Send DH client message
            dh_msg = DHClientMessage(
                g=dh.g,
                p=dh.p,
                A=client_public
            )
            
            self._send_message(dh_msg.model_dump())
            
            # Receive DH server response
            response = self._receive_message()
            if not response or response.get('type') != 'dh_server':
                print("Invalid DH server response")
                return False
            
            dh_response = DHServerMessage(**response)
            
            # Compute shared secret and derive key
            shared_secret = dh.compute_shared_secret(dh_response.B)
            self.temp_session_key = dh.derive_session_key(shared_secret)
            
            print("Temporary DH exchange completed")
            return True
            
        except Exception as e:
            print(f"Temporary DH exchange failed: {e}")
            return False
    
    def _perform_session_dh_exchange(self) -> bool:
        """Perform DH exchange for main session."""
        try:
            # Create DH instance and generate client keypair
            dh = DHKeyExchange()
            client_private, client_public = dh.generate_keypair()
            
            # Send DH client message
            dh_msg = DHClientMessage(
                g=dh.g,
                p=dh.p,
                A=client_public
            )
            
            self._send_message(dh_msg.model_dump())
            
            # Receive DH server response
            response = self._receive_message()
            if not response or response.get('type') != 'dh_server':
                print("Invalid DH server response")
                return False
            
            dh_response = DHServerMessage(**response)
            
            # Compute shared secret and derive session key
            shared_secret = dh.compute_shared_secret(dh_response.B)
            self.session_key = dh.derive_session_key(shared_secret)
            
            print("Session DH exchange completed")
            return True
            
        except Exception as e:
            print(f"Session DH exchange failed: {e}")
            return False
    
    def _register_user(self) -> bool:
        """Register new user."""
        try:
            print("=== User Registration ===")
            email = input("Email: ")
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            
            # Create registration message with plain password (will be encrypted)
            register_msg = RegisterMessage(
                email=email,
                username=username,
                pwd=password,  # Send plain password (encrypted over secure channel)
                salt=""  # Server will generate salt
            )
            
            # Encrypt registration data
            register_json = register_msg.model_dump_json()
            ct_bytes = aes_encrypt(register_json, self.temp_session_key)
            
            encrypted_payload = EncryptedPayload(ct=b64e(ct_bytes))
            self._send_message(encrypted_payload.model_dump())
            
            # Wait for response
            response = self._receive_message()
            if response and response.get('status') == 'ok':
                print("Registration successful!")
                return True
            else:
                print(f"Registration failed: {response.get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            print(f"Registration error: {e}")
            return False
    
    def _login_user(self) -> bool:
        """Login existing user."""
        try:
            print("=== User Login ===")
            email = input("Email: ")
            password = getpass.getpass("Password: ")
            
            # Create login message with plain password (will be encrypted)
            login_nonce = b64e(secrets.token_bytes(16))
            login_msg = LoginMessage(
                email=email,
                pwd=password,  # Send plain password (encrypted over secure channel)
                nonce=login_nonce
            )
            
            # Encrypt login data
            login_json = login_msg.model_dump_json()
            ct_bytes = aes_encrypt(login_json, self.temp_session_key)
            
            encrypted_payload = EncryptedPayload(ct=b64e(ct_bytes))
            self._send_message(encrypted_payload.model_dump())
            
            # Wait for response
            response = self._receive_message()
            if response and response.get('status') == 'ok':
                print("Login successful!")
                return True
            else:
                print(f"Login failed: {response.get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            print(f"Login error: {e}")
            return False
    
    def _send_chat_message(self, plaintext: str):
        """Send encrypted chat message."""
        try:
            # Get next sequence number
            self.client_seq += 1
            
            # Encrypt message
            ct_bytes = aes_encrypt(plaintext, self.session_key)
            ct_b64 = b64e(ct_bytes)
            
            # Create signature
            timestamp = now_ms()
            data_to_sign = f"{self.client_seq}|{timestamp}|{ct_b64}"
            signature = rsa_sign(data_to_sign, self.client_key_pem)
            sig_b64 = b64e(signature)
            
            # Create message
            chat_msg = ChatMessage(
                seqno=self.client_seq,
                ts=timestamp,
                ct=ct_b64,
                sig=sig_b64
            )
            
            # Send message
            self._send_message(chat_msg.model_dump())
            
            # Add to transcript
            self.transcript.add_message(
                self.client_seq, timestamp, ct_b64, sig_b64,
                self.server_cert_fingerprint, "sent"
            )
            
        except Exception as e:
            print(f"Error sending chat message: {e}")
    
    def _handle_incoming_messages(self):
        """Handle incoming messages in separate thread."""
        try:
            while self.running:
                message = self._receive_message()
                if not message:
                    break
                
                msg_type = message.get('type')
                
                if msg_type == 'msg':
                    # Handle incoming chat message
                    chat_msg = ChatMessage(**message)
                    
                    # Verify sequence number
                    if chat_msg.seqno <= self.last_seq:
                        print("[WARNING] Replay detected!")
                        continue
                    
                    # Verify signature
                    data_to_verify = f"{chat_msg.seqno}|{chat_msg.ts}|{chat_msg.ct}"
                    signature_bytes = b64d(chat_msg.sig)
                    
                    if not rsa_verify_with_cert(data_to_verify, signature_bytes, self.server_cert):
                        print("[WARNING] Signature verification failed!")
                        continue
                    
                    # Decrypt message
                    ct_bytes = b64d(chat_msg.ct)
                    plaintext = aes_decrypt_to_string(ct_bytes, self.session_key)
                    
                    print(f"[SERVER] {plaintext}")
                    
                    # Add to transcript
                    self.transcript.add_message(
                        chat_msg.seqno, chat_msg.ts, chat_msg.ct, chat_msg.sig,
                        self.server_cert_fingerprint, "received"
                    )
                    
                    # Update sequence number
                    self.last_seq = chat_msg.seqno
                
                elif msg_type == 'receipt':
                    # Session receipt received
                    print("[INFO] Session receipt received from server")
                    
                    # Save receipt
                    receipt_path = "transcripts/client_receipt.json"
                    with open(receipt_path, 'w') as f:
                        json.dump(message, f, indent=2)
                    print(f"Session receipt saved to {receipt_path}")
                    
                elif msg_type == 'status':
                    status = message.get('status')
                    msg = message.get('message', '')
                    
                    if status == 'bad_cert':
                        print(f"[ERROR] Certificate validation failed: {msg}")
                    elif status == 'sig_fail':
                        print(f"[ERROR] Signature verification failed: {msg}")
                    elif status == 'replay':
                        print(f"[ERROR] Replay attack detected: {msg}")
                    else:
                        print(f"[STATUS] {status}: {msg}")
                        
        except Exception as e:
            print(f"Error in message handler: {e}")
    
    def _chat_loop(self):
        """Main chat loop."""
        print("\n=== Secure Chat Started ===")
        print("Type 'quit' to exit, 'help' for commands")
        
        # Set running flag
        self.running = True
        
        # Start message handler thread
        handler_thread = threading.Thread(target=self._handle_incoming_messages)
        handler_thread.daemon = True
        handler_thread.start()
        
        try:
            while True:
                user_input = input("> ").strip()
                
                if user_input.lower() == 'quit':
                    self._send_message({"type": "quit"})
                    self.running = False  # Stop message handler
                    break
                elif user_input.lower() == 'help':
                    print("Commands:")
                    print("  quit - Exit the chat")
                    print("  help - Show this help")
                    print("  Just type a message to send it")
                elif user_input:
                    self._send_chat_message(user_input)
                    
        except KeyboardInterrupt:
            print("\nExiting...")
            self.running = False  # Stop message handler
    
    def connect(self):
        """Connect to server and start secure chat."""
        try:
            print(f"Connecting to {self.host}:{self.port}")
            
            # Create socket and connect
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            # Initialize transcript
            self.transcript = TranscriptManager("transcripts/client_session.log")
            
            # Perform handshake
            if not self._perform_handshake():
                return False
            
            # Temporary DH exchange for login/register
            if not self._perform_temp_dh_exchange():
                return False
            
            # Ask user to login or register
            print("\n1. Login")
            print("2. Register")
            choice = input("Choose (1 or 2): ").strip()
            
            if choice == '2':
                if not self._register_user():
                    return False
                # After registration, login
                if not self._login_user():
                    return False
            elif choice == '1':
                if not self._login_user():
                    return False
            else:
                print("Invalid choice")
                return False
            
            # Session DH exchange for secure chat
            if not self._perform_session_dh_exchange():
                return False
            
            # Start chat
            self._chat_loop()
            
            # Create and save session receipt
            try:
                receipt = create_session_receipt(
                    self.transcript,
                    "client", 
                    self.client_key_pem
                )
                
                receipt_path = "transcripts/client_receipt.json"
                with open(receipt_path, 'w') as f:
                    json.dump(receipt, f, indent=2)
                    
                print(f"Session receipt saved to {receipt_path}")
                
            except Exception as e:
                print(f"Error creating session receipt: {e}")
            
            return True
            
        except Exception as e:
            print(f"Connection error: {e}")
            return False
        
        finally:
            if self.socket:
                self.socket.close()


def main():
    """Main client function."""
    client = SecureChatClient()
    client.connect()


if __name__ == "__main__":
    main()
