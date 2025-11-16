"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""
import os
import sys
import argparse
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def load_ca_files(ca_dir: str = "certs") -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Load CA private key and certificate.
    
    Args:
        ca_dir: Directory containing CA files
        
    Returns:
        Tuple of (ca_private_key, ca_certificate)
    """
    # Load CA private key
    ca_key_path = os.path.join(ca_dir, "ca-key.pem")
    if not os.path.exists(ca_key_path):
        raise FileNotFoundError(f"CA private key not found: {ca_key_path}")
    
    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    # Load CA certificate
    ca_cert_path = os.path.join(ca_dir, "ca-cert.pem")
    if not os.path.exists(ca_cert_path):
        raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")
    
    with open(ca_cert_path, "rb") as f:
        ca_certificate = x509.load_pem_x509_certificate(
            f.read(),
            backend=default_backend()
        )
    
    return ca_private_key, ca_certificate


def generate_entity_keypair(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """
    Generate RSA keypair for entity (client/server).
    
    Args:
        key_size: RSA key size in bits
        
    Returns:
        RSA private key
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key


def create_entity_certificate(entity_private_key: rsa.RSAPrivateKey, 
                             ca_private_key: rsa.RSAPrivateKey,
                             ca_certificate: x509.Certificate,
                             common_name: str,
                             validity_days: int = 365) -> x509.Certificate:
    """
    Create entity certificate signed by CA.
    
    Args:
        entity_private_key: Entity's private key
        ca_private_key: CA's private key
        ca_certificate: CA's certificate
        common_name: Entity's common name
        validity_days: Certificate validity period in days
        
    Returns:
        Entity certificate signed by CA
    """
    # Build subject name
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Computer Science"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Use CA subject as issuer
    issuer = ca_certificate.subject
    
    # Set validity period
    not_valid_before = datetime.now(timezone.utc)
    not_valid_after = not_valid_before + timedelta(days=validity_days)
    
    # Build certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        entity_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(entity_private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_certificate.public_key()),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=True,
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(common_name),
        ]),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256(), backend=default_backend())
    
    return cert


def save_entity_files(private_key: rsa.RSAPrivateKey, certificate: x509.Certificate, 
                     output_prefix: str):
    """
    Save entity private key and certificate to files.
    
    Args:
        private_key: Entity private key
        certificate: Entity certificate
        output_prefix: Output file prefix (e.g., "certs/server")
    """
    # Create output directory
    output_dir = os.path.dirname(output_prefix)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # Save private key
    private_key_path = f"{output_prefix}-key.pem"
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    cert_path = f"{output_prefix}-cert.pem"
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"Private key saved to: {private_key_path}")
    print(f"Certificate saved to: {cert_path}")
    
    # Set restrictive permissions on private key (Unix-like systems)
    try:
        os.chmod(private_key_path, 0o600)
    except:
        pass  # Windows doesn't support chmod


def main():
    """Main function to generate entity certificate."""
    parser = argparse.ArgumentParser(description="Generate client/server certificate signed by CA")
    parser.add_argument("--cn", "-c", required=True, 
                       help="Common Name for the certificate")
    parser.add_argument("--out", "-o", required=True, 
                       help="Output file prefix (e.g., certs/server)")
    parser.add_argument("--ca-dir", "-d", default="certs",
                       help="CA directory (default: certs)")
    parser.add_argument("--key-size", "-k", type=int, default=2048,
                       help="RSA key size in bits (default: 2048)")
    parser.add_argument("--validity", "-v", type=int, default=365,
                       help="Certificate validity in days (default: 365)")
    
    args = parser.parse_args()
    
    try:
        print(f"Generating certificate for: {args.cn}")
        print(f"Key size: {args.key_size} bits")
        print(f"Validity: {args.validity} days")
        print(f"CA directory: {args.ca_dir}")
        print(f"Output prefix: {args.out}")
        print()
        
        # Load CA files
        print("Loading CA certificate and private key...")
        ca_private_key, ca_certificate = load_ca_files(args.ca_dir)
        
        # Generate entity keypair
        print("Generating entity keypair...")
        entity_private_key = generate_entity_keypair(args.key_size)
        
        # Create entity certificate
        print("Creating certificate...")
        entity_certificate = create_entity_certificate(
            entity_private_key, ca_private_key, ca_certificate, 
            args.cn, args.validity
        )
        
        # Save files
        print("Saving certificate files...")
        save_entity_files(entity_private_key, entity_certificate, args.out)
        
        print()
        print("Certificate generated successfully!")
        print("IMPORTANT: Keep the private key secure and never commit it to version control!")
        
    except Exception as e:
        print(f"Error generating certificate: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
