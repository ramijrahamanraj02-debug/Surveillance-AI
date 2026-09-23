"""
Generates self-signed SSL/TLS certificates (cert.pem, key.pem) with Local LAN IP SAN
for running SecureVision AI over HTTPS for mobile browser camera access.
"""

import os
import sys
import socket
import datetime

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

def generate_self_signed_cert(cert_path='cert.pem', key_path='key.pem'):
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import ipaddress
    except ImportError:
        print("[ERROR] 'cryptography' library is required to generate certificates.")
        print("Please run: pip install cryptography")
        return False

    lan_ip = get_lan_ip()
    print(f"Generating TLS certificate for localhost & LAN IP: {lan_ip}...")

    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Subject & Issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureVision AI Surveillance"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureVision AI Local Hub"),
    ])

    # SAN (Subject Alternative Names)
    san_list = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    if lan_ip != "127.0.0.1":
        try:
            san_list.append(x509.IPAddress(ipaddress.IPv4Address(lan_ip)))
        except Exception:
            pass

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False
    ).sign(key, hashes.SHA256())

    # Write key
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Write cert
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[OK] Certificate created: {cert_path}")
    print(f"[OK] Private key created: {key_path}")
    print(f"[OK] SAN entries included: localhost, 127.0.0.1, {lan_ip}")
    print("You can now run SecureVision over HTTPS using:")
    print("  python server.py --https")
    return True

if __name__ == '__main__':
    generate_self_signed_cert()
