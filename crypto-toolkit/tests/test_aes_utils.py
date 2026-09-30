import tempfile, os
from securecrypto import aes_utils

def test_encrypt_decrypt():
    original_content = "Hello World!".encode('utf-8')
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(original_content)
        tmp_path = tmp.name

    try:
        encoded_key = aes_utils.encrypt_file_aes(tmp_path, "unused_password")
        encrypted_path = tmp_path + ".enc"
        assert os.path.exists(encrypted_path), "File mã hóa không tồn tại"
        decrypted_path = aes_utils.decrypt_file_aes(encrypted_path, encoded_key)
        assert os.path.exists(decrypted_path), "File giải mã không tồn tại"
        with open(decrypted_path, "rb") as f:
            decrypted_content = f.read()
        assert decrypted_content == original_content, "Nội dung không khớp"
    finally:
        for path in [tmp_path, tmp_path + ".enc", tmp_path + ".dec"]:
            if os.path.exists(path):
                os.remove(path)
