import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

CERTS_DIR = "certs"
os.makedirs(CERTS_DIR, exist_ok=True)

def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def save_key(key, filename):
    with open(os.path.join(CERTS_DIR, filename), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_cert(cert, filename):
    with open(os.path.join(CERTS_DIR, filename), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_key(filename):
    with open(os.path.join(CERTS_DIR, filename), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_cert(filepath):
    with open(filepath, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def create_root_ca():
    key = generate_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Mini Root CA Root"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(
        issuer).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=1), critical=True,
    ).sign(key, hashes.SHA256())

    save_key(key, "root_ca_key.pem")
    save_cert(cert, "root_ca_cert.pem")
    return key, cert

def create_intermediate_ca(root_key, root_cert):
    key = generate_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini Intermediate CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Mini Intermediate CA"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(
        root_cert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1825)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True
    ).sign(root_key, hashes.SHA256())

    save_key(key, "intermediate_key.pem")
    save_cert(cert, "intermediate_cert.pem")
    return key, cert

def issue_certificate(ca_key, ca_cert, subject_info: dict):
    key = generate_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, subject_info.get(
            "country", "VN")),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_info.get(
            "org", "End Entity")),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_info.get(
            "common_name", "user.example.com")),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(
        ca_cert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256())

    filename_prefix = subject_info.get("common_name", "entity").replace(" ", "_")
    save_key(key, f"{filename_prefix}_key.pem")
    save_cert(cert, f"{filename_prefix}_cert.pem")

    return key, cert

def verify_certificate_chain(cert_to_verify, chain):
    try:
        for issuer_cert in chain:
            issuer_public_key = issuer_cert.public_key()
            issuer_public_key.verify(
                cert_to_verify.signature,
                cert_to_verify.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_to_verify.signature_hash_algorithm,
            )
            cert_to_verify = issuer_cert
        return True
    except Exception as e:
        print("Verification failed:", e)
        return False
