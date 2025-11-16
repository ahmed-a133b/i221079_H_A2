"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""
import base64
import time
import hashlib
from typing import Union


def now_ms() -> int:
    """Get current timestamp in milliseconds."""
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(b).decode('ascii')


def b64d(s: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(s)


def sha256_hex(data: Union[bytes, str]) -> str:
    """Compute SHA-256 hash and return as hex string."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: Union[bytes, str]) -> bytes:
    """Compute SHA-256 hash and return as bytes."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()


def int_to_bytes(value: int) -> bytes:
    """Convert integer to big-endian bytes."""
    # Calculate the number of bytes needed
    byte_length = (value.bit_length() + 7) // 8
    if byte_length == 0:
        byte_length = 1
    return value.to_bytes(byte_length, byteorder='big')


def bytes_to_int(data: bytes) -> int:
    """Convert big-endian bytes to integer."""
    return int.from_bytes(data, byteorder='big')
