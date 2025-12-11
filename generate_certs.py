#!/usr/bin/env python3
"""
Generate self-signed certificates for AegisAI mTLS demonstration
"""

import os
import argparse
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import ipaddress

def generate_private_key():
    """Generate a private key"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key

def generate_ca_cert(private_key, subject_name):
    """Generate a CA certificate"""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AegisAI"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
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
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=True,
            crl_sign=True,
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).sign(private_key, hashes.SHA256())
    
    return cert

def generate_server_cert(private_key, ca_private_key, ca_cert, hostname="localhost"):
    """Generate a server certificate"""
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AegisAI"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    
    alt_names = [
        x509.DNSName(hostname),
        x509.DNSName("api.aegisai.local"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("0.0.0.0"))
    ]
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName(alt_names),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=True
    ).sign(ca_private_key, hashes.SHA256())
    
    return cert

def generate_client_cert(private_key, ca_private_key, ca_cert, client_name="aegisai-agent"):
    """Generate a client certificate"""
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AegisAI"),
        x509.NameAttribute(NameOID.COMMON_NAME, client_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=True
    ).sign(ca_private_key, hashes.SHA256())
    
    return cert

def save_private_key(private_key, filename):
    """Save private key to file"""
    with open(filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_certificate(cert, filename):
    """Save certificate to file"""
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def main():
    parser = argparse.ArgumentParser(description="Generate certificates for AegisAI mTLS")
    parser.add_argument("--hostname", default="localhost", help="Server hostname")
    parser.add_argument("--client-name", default="aegisai-agent", help="Client certificate name")
    parser.add_argument("--output-dir", default="./certs", help="Output directory for certificates")
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    print(f"Generating certificates for AegisAI mTLS...")
    print(f"Output directory: {args.output_dir}")
    print(f"Server hostname: {args.hostname}")
    print(f"Client name: {args.client_name}")
    
    # Generate CA
    print("Generating CA certificate...")
    ca_private_key = generate_private_key()
    ca_cert = generate_ca_cert(ca_private_key, "AegisAI CA")
    
    # Generate server certificate
    print("Generating server certificate...")
    server_private_key = generate_private_key()
    server_cert = generate_server_cert(server_private_key, ca_private_key, ca_cert, args.hostname)
    
    # Generate client certificate
    print("Generating client certificate...")
    client_private_key = generate_private_key()
    client_cert = generate_client_cert(client_private_key, ca_private_key, ca_cert, args.client_name)
    
    # Save certificates and keys
    print("Saving certificates and keys...")
    
    # Save CA
    save_private_key(ca_private_key, os.path.join(args.output_dir, "ca.key"))
    save_certificate(ca_cert, os.path.join(args.output_dir, "ca.crt"))
    
    # Save server
    save_private_key(server_private_key, os.path.join(args.output_dir, "server.key"))
    save_certificate(server_cert, os.path.join(args.output_dir, "server.crt"))
    
    # Save client
    save_private_key(client_private_key, os.path.join(args.output_dir, "client.key"))
    save_certificate(client_cert, os.path.join(args.output_dir, "client.crt"))
    
    print("Certificates generated successfully!")
    print(f"CA certificate: {os.path.join(args.output_dir, 'ca.crt')}")
    print(f"Server certificate: {os.path.join(args.output_dir, 'server.crt')}")
    print(f"Server private key: {os.path.join(args.output_dir, 'server.key')}")
    print(f"Client certificate: {os.path.join(args.output_dir, 'client.crt')}")
    print(f"Client private key: {os.path.join(args.output_dir, 'client.key')}")

if __name__ == "__main__":
    main()