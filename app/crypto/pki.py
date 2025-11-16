"""X.509 validation: signed-by-CA, validity window, CN/SAN."""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone
from typing import Optional, List
import hashlib


class CertificateValidationError(Exception):
    """Exception raised when certificate validation fails."""
    pass


def load_certificate(cert_pem: str) -> x509.Certificate:
    """Load X.509 certificate from PEM string."""
    try:
        if isinstance(cert_pem, str):
            cert_pem = cert_pem.encode('utf-8')
        
        cert = x509.load_pem_x509_certificate(cert_pem, backend=default_backend())
        return cert
    except Exception as e:
        raise CertificateValidationError(f"Failed to parse certificate: {e}")


def validate_certificate_signature(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Validate that certificate is signed by the CA.
    
    Args:
        cert: Certificate to validate
        ca_cert: CA certificate
        
    Returns:
        True if signature is valid
        
    Raises:
        CertificateValidationError: If validation fails
    """
    try:
        # Get CA public key
        ca_public_key = ca_cert.public_key()
        
        # Verify the certificate signature using the appropriate hash algorithm
        from cryptography.hazmat.primitives import hashes
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
        
    except InvalidSignature:
        raise CertificateValidationError("Certificate signature validation failed")
    except Exception as e:
        raise CertificateValidationError(f"Certificate signature validation error: {e}")


def validate_certificate_validity(cert: x509.Certificate) -> bool:
    """
    Validate certificate is within its validity period.
    
    Args:
        cert: Certificate to validate
        
    Returns:
        True if certificate is currently valid
        
    Raises:
        CertificateValidationError: If certificate is expired or not yet valid
    """
    now = datetime.now(timezone.utc)
    
    # Use the new UTC properties to avoid deprecation warnings
    try:
        # Try the new UTC properties first (available in newer versions)
        not_valid_before = cert.not_valid_before_utc
        not_valid_after = cert.not_valid_after_utc
    except AttributeError:
        # Fall back to naive datetime and convert to UTC
        not_valid_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_valid_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    
    if now < not_valid_before:
        raise CertificateValidationError(f"Certificate not yet valid (valid from {not_valid_before})")
    
    if now > not_valid_after:
        raise CertificateValidationError(f"Certificate expired (expired on {not_valid_after})")
    
    return True


def validate_certificate_common_name(cert: x509.Certificate, expected_cn: str) -> bool:
    """
    Validate certificate Common Name matches expected value.
    
    Args:
        cert: Certificate to validate
        expected_cn: Expected Common Name
        
    Returns:
        True if CN matches
        
    Raises:
        CertificateValidationError: If CN doesn't match
    """
    try:
        # Get subject CN
        subject = cert.subject
        cn_attributes = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        
        if not cn_attributes:
            raise CertificateValidationError("Certificate has no Common Name")
        
        actual_cn = cn_attributes[0].value
        
        if actual_cn != expected_cn:
            raise CertificateValidationError(
                f"Certificate CN mismatch: expected '{expected_cn}', got '{actual_cn}'"
            )
        
        return True
        
    except CertificateValidationError:
        raise
    except Exception as e:
        raise CertificateValidationError(f"CN validation error: {e}")


def get_certificate_subject_alt_names(cert: x509.Certificate) -> List[str]:
    """
    Get Subject Alternative Names from certificate.
    
    Args:
        cert: Certificate to examine
        
    Returns:
        List of SAN values
    """
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return [name.value for name in san_ext.value]
    except x509.ExtensionNotFound:
        return []


def validate_certificate_chain(cert_pem: str, ca_cert_pem: str, expected_cn: Optional[str] = None) -> bool:
    """
    Perform full certificate validation.
    
    Args:
        cert_pem: Certificate to validate (PEM format)
        ca_cert_pem: CA certificate (PEM format)
        expected_cn: Expected Common Name (optional)
        
    Returns:
        True if all validations pass
        
    Raises:
        CertificateValidationError: If any validation fails
    """
    # Load certificates
    cert = load_certificate(cert_pem)
    ca_cert = load_certificate(ca_cert_pem)
    
    # Validate signature
    validate_certificate_signature(cert, ca_cert)
    
    # Validate validity period
    validate_certificate_validity(cert)
    
    # Validate CN if provided
    if expected_cn:
        validate_certificate_common_name(cert, expected_cn)
    
    return True


def get_certificate_fingerprint(cert_pem: str) -> str:
    """
    Get SHA-256 fingerprint of certificate.
    
    Args:
        cert_pem: Certificate in PEM format
        
    Returns:
        Hex-encoded SHA-256 fingerprint
    """
    cert = load_certificate(cert_pem)
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return fingerprint


def get_certificate_subject_cn(cert_pem: str) -> str:
    """
    Get Common Name from certificate subject.
    
    Args:
        cert_pem: Certificate in PEM format
        
    Returns:
        Common Name value
    """
    cert = load_certificate(cert_pem)
    subject = cert.subject
    cn_attributes = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    
    if not cn_attributes:
        raise CertificateValidationError("Certificate has no Common Name")
    
    return cn_attributes[0].value


def extract_public_key_pem(cert_pem: str) -> str:
    """
    Extract public key from certificate in PEM format.
    
    Args:
        cert_pem: Certificate in PEM format
        
    Returns:
        Public key in PEM format
    """
    cert = load_certificate(cert_pem)
    public_key = cert.public_key()
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return public_key_pem
