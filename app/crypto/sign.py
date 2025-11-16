"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from typing import Union


def rsa_sign(data: Union[str, bytes], private_key_pem: str) -> bytes:
    """
    Sign data using RSA-SHA256 with PKCS#1 v1.5 padding.
    
    Args:
        data: Data to sign (string or bytes)
        private_key_pem: RSA private key in PEM format
        
    Returns:
        RSA signature as bytes
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    # Sign the data
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    return signature


def rsa_verify(data: Union[str, bytes], signature: bytes, public_key_pem: str) -> bool:
    """
    Verify RSA-SHA256 signature with PKCS#1 v1.5 padding.
    
    Args:
        data: Original data that was signed
        signature: RSA signature to verify
        public_key_pem: RSA public key in PEM format
        
    Returns:
        True if signature is valid, False otherwise
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
            backend=default_backend()
        )
        
        # Verify the signature
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
        
    except InvalidSignature:
        return False
    except Exception:
        return False


def rsa_verify_with_cert(data: Union[str, bytes], signature: bytes, cert_pem: str) -> bool:
    """
    Verify RSA-SHA256 signature using public key from certificate.
    
    Args:
        data: Original data that was signed
        signature: RSA signature to verify
        cert_pem: X.509 certificate in PEM format
        
    Returns:
        True if signature is valid, False otherwise
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    try:
        # Load certificate and extract public key
        from cryptography import x509
        
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode() if isinstance(cert_pem, str) else cert_pem,
            backend=default_backend()
        )
        
        public_key = cert.public_key()
        
        # Verify the signature
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
        
    except InvalidSignature:
        return False
    except Exception:
        return False


def generate_rsa_keypair(key_size: int = 2048) -> tuple[str, str]:
    """
    Generate RSA keypair.
    
    Args:
        key_size: RSA key size in bits
        
    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Serialize public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem
