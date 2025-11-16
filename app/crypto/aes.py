"""AES-128(ECB)+PKCS#7 helpers (use library)."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from typing import Union


def aes_encrypt(plaintext: Union[str, bytes], key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 ECB mode with PKCS#7 padding.
    
    Args:
        plaintext: Data to encrypt (string or bytes)
        key: 16-byte AES key
        
    Returns:
        Encrypted ciphertext as bytes
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Apply PKCS#7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext)
    padded_data += padder.finalize()
    
    # Create AES cipher in ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 ECB mode and remove PKCS#7 padding.
    
    Args:
        ciphertext: Encrypted data as bytes
        key: 16-byte AES key
        
    Returns:
        Decrypted plaintext as bytes
        
    Raises:
        ValueError: If decryption or padding removal fails
    """
    # Create AES cipher in ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext)
    plaintext += unpadder.finalize()
    
    return plaintext


def aes_decrypt_to_string(ciphertext: bytes, key: bytes) -> str:
    """
    Decrypt ciphertext and return as UTF-8 string.
    
    Args:
        ciphertext: Encrypted data as bytes
        key: 16-byte AES key
        
    Returns:
        Decrypted plaintext as string
    """
    plaintext_bytes = aes_decrypt(ciphertext, key)
    return plaintext_bytes.decode('utf-8')
