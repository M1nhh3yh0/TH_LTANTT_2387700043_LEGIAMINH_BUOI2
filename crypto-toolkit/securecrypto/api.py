from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from cryptography.exceptions import InvalidTag
from securecrypto import aes_utils
import binascii
import os

app = Flask(__name__)
app.json.ensure_ascii = False  # trả thông báo tiếng Việt dễ đọc

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(BASE_DIR, 'upload')
os.makedirs(FILES_DIR, exist_ok=True)


def save_upload(require_ext=None):
    # Kiểm tra đủ trường và lưu file upload vào FILES_DIR với tên đã được làm sạch.
    # Trả về (save_path, secret, error_response)
    f = request.files.get('file')
    secret = request.form.get('password', '')
    if f is None or not f.filename:
        return None, None, (jsonify({"error": "Thiếu trường 'file'"}), 400)
    if not secret:
        return None, None, (jsonify({"error": "Thiếu trường 'password'"}), 400)
    # secure_filename bỏ '../', '/', '\' ... -> chặn path traversal khi ghi file
    filename = secure_filename(f.filename)
    if not filename:
        return None, None, (jsonify({"error": "Tên file không hợp lệ"}), 400)
    if require_ext and not filename.endswith(require_ext):
        return None, None, (jsonify({"error": f"File phải có đuôi {require_ext}"}), 400)
    save_path = os.path.join(FILES_DIR, filename)
    f.save(save_path)
    return save_path, secret, None


@app.route('/encrypt', methods=['POST'])
def encrypt():
    save_path, secret, error = save_upload()
    if error:
        return error
    key = aes_utils.encrypt_file_aes(save_path, secret)
    return jsonify({"key": key})


@app.route('/decrypt', methods=['POST'])
def decrypt():
    save_path, key_b64, error = save_upload(require_ext='.enc')
    if error:
        return error
    try:
        out_path = aes_utils.decrypt_file_aes(save_path, key_b64)
    except (binascii.Error, ValueError):
        return jsonify({"error": "Key không hợp lệ: trường 'password' phải chứa "
                                 "Key base64 (44 ký tự) nhận được từ /encrypt, "
                                 "không phải mật khẩu"}), 400
    except InvalidTag:
        return jsonify({"error": "Giải mã thất bại: sai Key hoặc file .enc "
                                 "đã bị sửa đổi"}), 400
    return jsonify({"output": out_path})


if __name__ == '__main__':
    app.run()
