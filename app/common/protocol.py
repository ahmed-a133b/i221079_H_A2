"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""
from pydantic import BaseModel
from typing import Optional


class HelloMessage(BaseModel):
    """Client hello message containing client certificate and nonce."""
    type: str = "hello"
    client_cert: str  # PEM-encoded certificate
    nonce: str  # base64-encoded nonce


class ServerHelloMessage(BaseModel):
    """Server hello response containing server certificate and nonce."""
    type: str = "server_hello"
    server_cert: str  # PEM-encoded certificate
    nonce: str  # base64-encoded nonce


class RegisterMessage(BaseModel):
    """User registration message (encrypted)."""
    type: str = "register"
    email: str
    username: str
    pwd: str  # base64(sha256(salt||pwd))
    salt: str  # base64-encoded salt


class LoginMessage(BaseModel):
    """User login message (encrypted)."""
    type: str = "login"
    email: str
    pwd: str  # base64(sha256(salt||pwd))
    nonce: str  # base64-encoded nonce


class DHClientMessage(BaseModel):
    """Diffie-Hellman client message."""
    type: str = "dh_client"
    g: int
    p: int
    A: int  # g^a mod p


class DHServerMessage(BaseModel):
    """Diffie-Hellman server response."""
    type: str = "dh_server"
    B: int  # g^b mod p


class ChatMessage(BaseModel):
    """Encrypted chat message with signature."""
    type: str = "msg"
    seqno: int
    ts: int  # timestamp in milliseconds
    ct: str  # base64-encoded ciphertext
    sig: str  # base64-encoded RSA signature


class SessionReceipt(BaseModel):
    """Session receipt for non-repudiation."""
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex-encoded transcript hash
    sig: str  # base64-encoded RSA signature over transcript hash


class StatusMessage(BaseModel):
    """Status response message."""
    type: str = "status"
    status: str  # "ok", "error", "bad_cert", "sig_fail", "replay", etc.
    message: Optional[str] = None


class EncryptedPayload(BaseModel):
    """Encrypted payload wrapper."""
    type: str = "encrypted"
    ct: str  # base64-encoded ciphertext
