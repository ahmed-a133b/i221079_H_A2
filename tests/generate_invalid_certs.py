#!/usr/bin/env python3
"""
Invalid Certificate Generator
Creates various types of invalid certificates for testing
"""

import os
import sys
import subprocess
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class InvalidCertificateGenerator:
    """Generate invalid certificates for testing"""
    
    def __init__(self, output_dir: str = "tests/certs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_self_signed_cert(self) -> tuple:
        """Generate self-signed certificate (invalid - not from CA)"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "TestCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SelfSigned Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "selfsigned.local"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("selfsigned.local"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Save certificate and key
        cert_path = self.output_dir / "self-signed-cert.pem"
        key_path = self.output_dir / "self-signed-key.pem"
        
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print(f"Generated self-signed certificate: {cert_path}")
        return str(cert_path), str(key_path)
    
    def generate_expired_cert(self) -> tuple:
        """Generate expired certificate"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Load CA certificate and key (to sign our expired cert)
        try:
            with open("certs/ca-cert.pem", "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            with open("certs/ca-key.pem", "rb") as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None)
        except Exception:
            # If CA not available, create self-signed expired cert
            return self._generate_self_signed_expired()
        
        # Create expired certificate (valid in the past)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "TestCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Expired Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "expired.local"),
        ])
        
        # Certificate was valid from 2 years ago to 1 year ago (now expired)
        not_valid_before = datetime.datetime.utcnow() - datetime.timedelta(days=730)
        not_valid_after = datetime.datetime.utcnow() - datetime.timedelta(days=365)
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("expired.local"),
            ]),
            critical=False,
        ).sign(ca_key, hashes.SHA256())
        
        # Save certificate and key
        cert_path = self.output_dir / "expired-cert.pem"
        key_path = self.output_dir / "expired-key.pem"
        
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print(f"Generated expired certificate: {cert_path}")
        return str(cert_path), str(key_path)
    
    def _generate_self_signed_expired(self) -> tuple:
        """Generate self-signed expired certificate"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "TestCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Expired Self-Signed"),
            x509.NameAttribute(NameOID.COMMON_NAME, "expired-selfsigned.local"),
        ])
        
        # Expired certificate
        not_valid_before = datetime.datetime.utcnow() - datetime.timedelta(days=730)
        not_valid_after = datetime.datetime.utcnow() - datetime.timedelta(days=365)
        
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
        ).sign(private_key, hashes.SHA256())
        
        cert_path = self.output_dir / "expired-cert.pem"
        key_path = self.output_dir / "expired-key.pem"
        
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        return str(cert_path), str(key_path)
    
    def generate_wrong_ca_cert(self) -> tuple:
        """Generate certificate signed by different (wrong) CA"""
        # Generate a fake CA
        fake_ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        fake_ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "FakeState"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "FakeCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Fake CA"),
        ])
        
        fake_ca_cert = x509.CertificateBuilder().subject_name(
            fake_ca_subject
        ).issuer_name(
            fake_ca_subject  # Self-signed CA
        ).public_key(
            fake_ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).sign(fake_ca_key, hashes.SHA256())
        
        # Generate client certificate signed by fake CA
        client_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        client_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "TestCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wrong CA Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "wrongca.local"),
        ])
        
        client_cert = x509.CertificateBuilder().subject_name(
            client_subject
        ).issuer_name(
            fake_ca_subject
        ).public_key(
            client_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("wrongca.local"),
            ]),
            critical=False,
        ).sign(fake_ca_key, hashes.SHA256())
        
        # Save certificates and keys
        fake_ca_cert_path = self.output_dir / "fake-ca-cert.pem"
        fake_ca_key_path = self.output_dir / "fake-ca-key.pem"
        forged_cert_path = self.output_dir / "forged-client-cert.pem"
        forged_key_path = self.output_dir / "forged-client-key.pem"
        
        with open(fake_ca_cert_path, "wb") as f:
            f.write(fake_ca_cert.public_bytes(serialization.Encoding.PEM))
        
        with open(fake_ca_key_path, "wb") as f:
            f.write(fake_ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(forged_cert_path, "wb") as f:
            f.write(client_cert.public_bytes(serialization.Encoding.PEM))
        
        with open(forged_key_path, "wb") as f:
            f.write(client_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print(f"Generated forged certificate (wrong CA): {forged_cert_path}")
        return str(forged_cert_path), str(forged_key_path)
    
    def generate_all_invalid_certs(self):
        """Generate all types of invalid certificates"""
        print("Generating invalid certificates for testing...")
        
        self.generate_self_signed_cert()
        self.generate_expired_cert()
        self.generate_wrong_ca_cert()
        
        print(f"All invalid certificates generated in: {self.output_dir}")


def main():
    """Generate invalid certificates for testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate invalid certificates for testing')
    parser.add_argument('--output', default='tests/certs', help='Output directory')
    parser.add_argument('--type', choices=['self-signed', 'expired', 'wrong-ca', 'all'], 
                       default='all', help='Type of invalid certificate to generate')
    
    args = parser.parse_args()
    
    generator = InvalidCertificateGenerator(args.output)
    
    if args.type == 'self-signed':
        generator.generate_self_signed_cert()
    elif args.type == 'expired':
        generator.generate_expired_cert()
    elif args.type == 'wrong-ca':
        generator.generate_wrong_ca_cert()
    else:  # all
        generator.generate_all_invalid_certs()


if __name__ == "__main__":
    main()