"""Create Root CA (RSA + self-signed X.509) using cryptography."""
import os
import sys
import argparse
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def generate_ca_keypair(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """
    Generate RSA keypair for CA.
    
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


def create_ca_certificate(private_key: rsa.RSAPrivateKey, ca_name: str, 
                         validity_days: int = 3650) -> x509.Certificate:
    """
    Create self-signed CA certificate.
    
    Args:
        private_key: CA private key
        ca_name: CA common name
        validity_days: Certificate validity period in days
        
    Returns:
        Self-signed CA certificate
    """
    # Build subject name
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Computer Science"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])
    
    # Set validity period
    not_valid_before = datetime.now(timezone.utc)
    not_valid_after = not_valid_before + timedelta(days=validity_days)
    
    # Build certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(private_key, hashes.SHA256(), backend=default_backend())
    
    return cert


def save_ca_files(private_key: rsa.RSAPrivateKey, certificate: x509.Certificate, 
                  output_dir: str = "certs"):
    """
    Save CA private key and certificate to files.
    
    Args:
        private_key: CA private key
        certificate: CA certificate
        output_dir: Output directory
    """
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Save private key
    private_key_path = os.path.join(output_dir, "ca-key.pem")
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    cert_path = os.path.join(output_dir, "ca-cert.pem")
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"CA private key saved to: {private_key_path}")
    print(f"CA certificate saved to: {cert_path}")
    
    # Set restrictive permissions on private key (Unix-like systems)
    try:
        os.chmod(private_key_path, 0o600)
    except:
        pass  # Windows doesn't support chmod


def main():
    """Main function to generate CA."""
    parser = argparse.ArgumentParser(description="Generate Root CA certificate and private key")
    parser.add_argument("--name", "-n", default="FAST-NU Root CA", 
                       help="CA common name (default: FAST-NU Root CA)")
    parser.add_argument("--output", "-o", default="certs", 
                       help="Output directory (default: certs)")
    parser.add_argument("--key-size", "-k", type=int, default=2048,
                       help="RSA key size in bits (default: 2048)")
    parser.add_argument("--validity", "-v", type=int, default=3650,
                       help="Certificate validity in days (default: 3650)")
    
    args = parser.parse_args()
    
    try:
        print(f"Generating Root CA: {args.name}")
        print(f"Key size: {args.key_size} bits")
        print(f"Validity: {args.validity} days")
        print(f"Output directory: {args.output}")
        print()
        
        # Generate CA keypair
        print("Generating RSA keypair...")
        private_key = generate_ca_keypair(args.key_size)
        
        # Create self-signed certificate
        print("Creating self-signed certificate...")
        certificate = create_ca_certificate(private_key, args.name, args.validity)
        
        # Save files
        print("Saving CA files...")
        save_ca_files(private_key, certificate, args.output)
        
        print()
        print("Root CA generated successfully!")
        print("IMPORTANT: Keep the private key secure and never commit it to version control!")
        
    except Exception as e:
        print(f"Error generating CA: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
