import argparse
from securecrypto import aes_utils

def main():
    parser = argparse.ArgumentParser(description="SecureCrypto CLI")
    parser.add_argument('--encrypt', help='Encrypt file')
    parser.add_argument('--decrypt', help='Decrypt file')
    parser.add_argument('--password', required=True,
                        help='Password for AES encryption/decryption')
    args = parser.parse_args()

    if args.encrypt:
        res = aes_utils.encrypt_file_aes(args.encrypt, args.password)
        print(res)
    elif args.decrypt:
        out = aes_utils.decrypt_file_aes(args.decrypt, args.password)
        print(f"Decrypted. Output: {out}")
