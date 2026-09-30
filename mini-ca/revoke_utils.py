import os, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

CERTS_DIR = "certs"
CRL_FILE = os.path.join(CERTS_DIR, "ca_crl.pem")
os.makedirs(CERTS_DIR, exist_ok=True)

def load_cert(filepath):
    with open(filepath, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_key(filepath):
    with open(filepath, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def create_empty_crl(issuer_cert, issuer_key):
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(issuer_cert.subject)
    crl_builder = crl_builder.last_update(datetime.datetime.utcnow())
    crl_builder = crl_builder.next_update(datetime.datetime.utcnow()
                                          + datetime.timedelta(days=7))

    crl = crl_builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    with open(CRL_FILE, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    return crl

def revoke_certificate(cert_file: str,
                       issuer_cert_file: str, issuer_key_file: str,
                       reason=x509.ReasonFlags.key_compromise):
    cert = load_cert(cert_file)
    issuer_cert = load_cert(issuer_cert_file)
    issuer_key = load_key(issuer_key_file)
    if os.path.exists(CRL_FILE):
        with open(CRL_FILE, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
        revoked_certs = list(crl)
    else:
        revoked_certs = []

    revoked_cert = x509.RevokedCertificateBuilder().serial_number(
        cert.serial_number
    ).revocation_date(
        datetime.datetime.utcnow()
    ).add_extension(
        x509.CRLReason(reason), critical=False
    ).build()
    revoked_certs.append(revoked_cert)

    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(issuer_cert.subject)
    crl_builder = crl_builder.last_update(datetime.datetime.utcnow())
    crl_builder = crl_builder.next_update(datetime.datetime.utcnow()
                                          + datetime.timedelta(days=7))

    for rc in revoked_certs:
        crl_builder = crl_builder.add_revoked_certificate(rc)
    crl = crl_builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    with open(CRL_FILE, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    return crl

def check_revocation_status(cert_file: str):
    cert = load_cert(cert_file)
    if not os.path.exists(CRL_FILE):
        return False
    with open(CRL_FILE, "rb") as f:
        crl = x509.load_pem_x509_crl(f.read())
    for revoked in crl:
        if revoked.serial_number == cert.serial_number:
            return True
    return False
