from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data_rsa(data: bytes, private_key):
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

def verify_signature_rsa(data: bytes, signature: bytes, public_key):
    try:
        public_key.verify(signature, data, padding.PKCS1v15(),
                          hashes.SHA256())
        return True
    except Exception:
        return False
