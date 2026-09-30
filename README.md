# BÀI 2 — MÃ HOÁ & TRIỂN KHAI PKI

**Môn:** Lập trình An ninh thông tin
**Nội dung thực hành:**
- **2.2 CryptoToolkit** — thư viện mật mã `securecrypto` (AES-256-GCM, RSA, Argon2) kèm CLI, GUI Tkinter và REST API Flask.
- **2.4 Mini Certificate Authority** — hệ thống CA hai cấp (Root → Intermediate → End-entity), xác thực chuỗi và thu hồi chứng chỉ bằng CRL.

**Môi trường:** Windows (Python 3.14.0, VS Code) · Kali Linux VM (Burp Suite) · Git + GitSecure pre-commit hook.

---

## Mục lục

1. [Cấu trúc repo](#1-cấu-trúc-repo)
2. [Cài đặt](#2-cài-đặt)
3. [Phần 2.2 — CryptoToolkit](#3-phần-22--cryptotoolkit)
4. [Phần 2.4 — Mini CA](#4-phần-24--mini-ca)
5. [Đánh giá bảo mật & hạn chế còn lại](#5-đánh-giá-bảo-mật--hạn-chế-còn-lại)
6. [Kết luận](#6-kết-luận)

---

## 1. Cấu trúc repo

```
Buoi_2/
├── .githooks/pre-commit        # GitSecure (tái sử dụng từ Bài 1.4)
├── .gitignore                  # chặn certs/, *.pem, gitsecure.log, __pycache__/
├── README.md                   # báo cáo này
├── images/                     # ảnh minh chứng
├── crypto-toolkit/             # Phần 2.2
│   ├── setup.py                # đóng gói securecrypto + entry point securecrypto-cli
│   ├── requirements.txt        # pytest
│   ├── files/                  # data.txt, data-1.txt dùng để thử mã hoá
│   ├── securecrypto/
│   │   ├── aes_utils.py        # PBKDF2 + AES-256-GCM
│   │   ├── rsa_utils.py        # sinh khoá, ký, xác thực RSA
│   │   ├── hash_utils.py       # băm mật khẩu Argon2
│   │   ├── cli.py              # giao diện dòng lệnh
│   │   ├── app_gui.py          # giao diện Tkinter
│   │   └── api.py              # REST API Flask (/encrypt, /decrypt)
│   └── tests/                  # 6 unit test (pytest)
└── mini-ca/                    # Phần 2.4
    ├── requirements.txt        # cryptography
    ├── ca_utils.py             # tạo Root/Intermediate CA, cấp cert, xác thực chuỗi
    ├── revoke_utils.py         # CRL: thu hồi & kiểm tra trạng thái
    ├── demo.py                 # chạy toàn bộ quy trình trên terminal
    └── demo_ui.py              # giao diện Tkinter 5 nút
```

## 2. Cài đặt

```powershell
# Phần 2.2
cd crypto-toolkit
pip install -e .                  # cài securecrypto (cryptography, argon2-cffi, flask)
pip install -r requirements.txt   # pytest
pytest tests/

# Phần 2.4
cd ..\mini-ca
pip install -r requirements.txt
python demo.py

# Bật GitSecure cho repo (chạy ở thư mục gốc repo)
git config core.hooksPath .githooks
pip install bandit                # hook gọi bandit; thiếu bandit thì hook chặn mọi commit
```

Phiên bản thực tế khi làm bài: Python 3.14.0 · cryptography 50.0.1 · argon2-cffi 25.1.0 · Flask 2.3.3 / Werkzeug 3.1.8 · pytest 9.1.1.

---

## 3. Phần 2.2 — CryptoToolkit

### 3.1 Thiết kế thư viện `securecrypto`

| Hàm | Thuật toán & tham số | Lý do chọn |
|-----|----------------------|------------|
| `derive_key_from_password(password, salt)` | PBKDF2-HMAC-SHA256, 100 000 vòng, salt 16 byte ngẫu nhiên → khoá 32 byte | Biến mật khẩu (entropy thấp) thành khoá 256 bit. Salt làm mỗi lần mã hoá ra khoá khác nhau, chống rainbow table. Số vòng lặp làm chậm brute-force. |
| `encrypt_file_aes(filepath, password)` | AES-256-**GCM**, nonce 12 byte ngẫu nhiên | GCM là mã hoá xác thực (AEAD): vừa giữ bí mật vừa sinh **tag 16 byte** bảo đảm toàn vẹn. Sửa 1 bit của file `.enc` thì giải mã báo lỗi `InvalidTag` chứ không trả dữ liệu sai. |
| `decrypt_file_aes(encrypted_file, key_base64)` | Tách salt / nonce / ciphertext, giải mã bằng key base64 | Ghi kết quả ra file `.dec`. |
| `generate_rsa_keypair(key_size=2048)` | RSA 2048 bit, e = 65537 | 2048 bit là mức tối thiểu hiện được chấp nhận; 65537 là số mũ công khai chuẩn. |
| `sign_data_rsa` / `verify_signature_rsa` | RSA PKCS#1 v1.5 + SHA-256 | Ký bằng khoá riêng, xác thực bằng khoá công khai. Hàm verify trả `True/False` thay vì ném exception. |
| `hash_password_secure(password)` | Argon2id (`argon2-cffi`, tham số mặc định: t = 3, m = 64 MiB, p = 4, salt 16 byte) | Argon2 tốn cả CPU lẫn bộ nhớ nên chống tấn công bằng GPU/ASIC tốt hơn PBKDF2. Chuỗi hash tự chứa thuật toán, tham số và salt (`$argon2id$v=19$m=65536,t=3,p=4$...`). |

**Định dạng file `.enc`:**

| Byte | 0–15 | 16–27 | 28 … n−17 | 16 byte cuối |
|------|------|-------|-----------|--------------|
| Nội dung | salt | nonce | ciphertext | GCM tag |

Ví dụ `data.txt` (“HUTECH University”, 17 byte) → `data.txt.enc` dài 16 + 12 + 17 + 16 = **61 byte**.

### 3.2 Cài đặt package & chạy unit test

![Cấu trúc crypto-toolkit](images/01_cau_truc_crypto_toolkit.png)
*Hình 1 — Cấu trúc thư mục `crypto-toolkit` trong VS Code.*

`pip install -e .` cài ở chế độ **editable**: Python trỏ thẳng vào mã nguồn nên sửa code không cần cài lại. Lệnh này cũng tạo lệnh `securecrypto-cli` (từ `entry_points` trong `setup.py`) và thư mục `securecrypto.egg-info`. Khi chạy, pip tải thêm `cryptography` và `argon2-cffi` theo `install_requires`, rồi báo `Successfully installed securecrypto-0.1.0`.

> **Lưu ý:** `pytest` chỉ nằm trong `requirements.txt`, không nằm trong `install_requires` của `setup.py`. Vì vậy `pip install -e .` không cài pytest, phải chạy thêm `pip install -r requirements.txt`, nếu không lệnh `pytest` sẽ báo không tồn tại.

![pytest](images/03_pytest.png)
*Hình 2 — 6/6 test đạt: 1 test AES (mã hoá rồi giải mã phải ra đúng nội dung gốc), 2 test Argon2 (đúng mật khẩu → verify thành công, sai mật khẩu → `VerifyMismatchError`), 3 test RSA (sinh khoá, ký/xác thực, dữ liệu bị sửa → `False`).*

### 3.3 CLI

```powershell
securecrypto-cli --encrypt .\files\data.txt --password pass123
securecrypto-cli --decrypt .\files\data.txt.enc --password <KEY_BASE64_VỪA_NHẬN>
```

![CLI encrypt](images/04_cli_encrypt.png)
*Hình 3 — Mã hoá: CLI in ra Key base64 (32 byte → 44 ký tự); `data.txt.enc` mở trong editor chỉ còn ký tự rác.*

![CLI decrypt](images/05_cli_decrypt.png)
*Hình 4 — Giải mã bằng Key base64: `data.txt.dec` khôi phục đúng “HUTECH University”.*

Điểm cần chú ý: tuy tham số tên là `--password`, **khi giải mã phải truyền Key base64 chứ không phải mật khẩu**. Lý do nằm ở thiết kế của `aes_utils` (xem [CT-01](#5-đánh-giá-bảo-mật--hạn-chế-còn-lại)), và đây cũng là gốc của lỗi ở GUI và API bên dưới.

### 3.4 GUI Tkinter — debug chức năng giải mã

**Hiện tượng.** Mã hoá chạy bình thường. Khi giải mã, người dùng để nguyên mật khẩu trong ô duy nhất trên giao diện rồi chọn file `.enc`: giao diện **không phản hồi gì**, không tạo file `.dec`, còn terminal in traceback.

> Cửa sổ GUI gốc được đặt kích thước tối thiểu (`root.minsize`) cho dễ quan sát. Phần logic giữ nguyên theo tài liệu.

![GUI encrypt](images/06_gui_encrypt.png)
*Hình 5 — GUI gốc: mã hoá `data-1.txt` với mật khẩu `123` thành công, Key hiện ở dòng chữ dưới nút.*

![GUI decrypt lỗi](images/07_gui_decrypt_loi.png)
*Hình 6 — GUI gốc: bấm Decrypt khi ô vẫn là mật khẩu `123`. Giao diện không đổi gì, còn terminal in `Exception in Tkinter callback`, lỗi đi từ `app_gui.py` dòng 14 → `aes_utils.py` dòng 35 (`base64.b64decode`) → `binascii.Error: Incorrect padding`.*

**Root cause:**

1. **Nhầm “mật khẩu” với “khoá”.** `decrypt_file_aes()` cần Key base64, nhưng GUI chỉ có một ô nhập (không có nhãn) cho cả hai việc. Người dùng tự nhiên nhập mật khẩu, và `base64.b64decode("123")` ném `binascii.Error: Incorrect padding` vì 3 ký tự không đủ tạo thành một khối base64 4 ký tự. Nếu chuỗi nhập vào tình cờ đúng dạng base64 thì lỗi chuyển thành `ValueError: AESGCM key must be 128, 192, or 256 bits`, còn nếu là một key 32 byte sai thì thành `InvalidTag`.
2. **Không lấy được Key để dán.** Key hiện trên `tk.Label`, mà Label **không bôi đen / copy được**. Ô nhập lại có `show="*"`, nên muốn giải mã phải gõ tay 44 ký tự mà không nhìn thấy mình gõ gì.
3. **Lỗi bị nuốt im lặng.** Callback của nút không có `try/except`. Tkinter bắt exception trong callback và chỉ in ra stderr (`Exception in Tkinter callback`), nên cửa sổ vẫn chạy như không có gì xảy ra.
4. **Bấm Cancel** ở hộp chọn file thì `askopenfilename()` trả về chuỗi rỗng và `open('')` ném `FileNotFoundError`.

**Cách sửa** (`securecrypto/app_gui.py`):

- Tách thành hai ô có nhãn rõ ràng: **Password** (dùng khi Encrypt, vẫn che `*`) và **Key base64** (dùng khi Decrypt).
- Kết quả hiện trong `Entry` ở trạng thái `readonly`, bôi đen và copy được. Sau khi mã hoá, Key còn được tự động copy vào clipboard.
- Bắt đúng từng loại lỗi và báo bằng `messagebox`, không để lỗi im lặng:

```python
try:
    out = aes_utils.decrypt_file_aes(file, key)
except (binascii.Error, ValueError):   # không phải base64 / sai độ dài khoá
    messagebox.showerror("Lỗi", "Key không hợp lệ: phải là chuỗi base64 44 ký tự "
                                "nhận được khi Encrypt (không phải Password).")
    return
except InvalidTag:                      # sai key hoặc file .enc bị sửa
    messagebox.showerror("Lỗi", "Giải mã thất bại: sai Key hoặc file .enc đã bị sửa đổi.")
    return
```

- Xử lý trường hợp Cancel (`if not file: return`), lọc hộp chọn file theo `*.enc`.

**Kết quả sau khi sửa:**

![GUI fix encrypt](images/13_gui_fix_encrypt.png)
*Hình 7 — GUI sau sửa: mã hoá xong, Key nằm trong ô **Kết quả** (readonly) nên bôi đen copy được, đồng thời đã tự copy vào clipboard.*

![GUI fix decrypt ok](images/14_gui_fix_decrypt_ok.png)
*Hình 8 — Dán Key (`Ctrl+V`) vào ô “Key base64”, bấm Decrypt → ô Kết quả hiện đường dẫn `files/data-1.txt.dec`, giải mã thành công.*

![GUI fix decrypt sai](images/15_gui_fix_decrypt_sai.png)
*Hình 9 — Cùng thao tác như Hình 6 (nhập `123` vào ô Key) nhưng giờ GUI hiện hộp thoại “Key không hợp lệ…”, người dùng biết ngay mình sai ở đâu.*

### 3.5 REST API Flask — debug `/decrypt`

**Cách kiểm thử: dùng Burp Suite trên máy ảo Kali.** API chạy trên Windows, còn Burp Suite chạy trong máy ảo Kali (VMware, chế độ NAT). `app.run()` mặc định chỉ nghe ở `127.0.0.1`, nên máy ảo không gọi tới được. Vì vậy server được chạy bằng Flask CLI để nghe trên mọi interface (không phải sửa code), và Kali gọi API qua địa chỉ `10.12.23.241:5000`:

```powershell
flask --app securecrypto.api run --host 0.0.0.0 --port 5000
```

![Burp encrypt](images/09_burp_encrypt.png)
*Hình 10 — Burp Repeater gửi `POST /encrypt` (multipart: `file` = data.txt, `password` = pass123), server trả `200 OK` kèm `{"key": "..."}`. Header `Server: Werkzeug/3.1.8 Python/3.14.0` xác nhận request tới đúng server trên máy Windows.*

**Sự cố khi gửi file nhị phân bằng Burp Repeater, và cũng là bằng chứng về tính toàn vẹn của AES-GCM.** Endpoint `/decrypt` nhận file `.enc`, là dữ liệu nhị phân. Lần thử đầu, file được chèn vào Repeater bằng *Paste from file*. Burp coi nội dung là văn bản và mã hoá lại sang UTF-8: 23 byte có giá trị ≥ 0x80 bị biến thành 2 byte mỗi byte, nên file 61 byte thành **84 byte** khi tới server (đã đối chiếu file server nhận được với file gốc). Ciphertext bị biến đổi thì GCM tag không khớp, và `aesgcm.decrypt()` ném `cryptography.exceptions.InvalidTag` thay vì trả dữ liệu sai. Lần này cũng lỡ chọn file `.enc` của CLI, không phải file của API.

![File bị sửa](images/12b_decrypt_file_bi_sua.png)
*Hình 11 — Ciphertext bị biến đổi trên đường truyền → `InvalidTag` tại `aes_utils.py` dòng 37 → API gốc trả `500`.*

Để gửi đúng từng byte, các request `/decrypt` sau đó được gửi bằng `curl` trên Kali, đi qua Burp Proxy. Nhờ vậy request vẫn được ghi lại trong **Proxy → HTTP history** của Burp:

```bash
curl -x http://127.0.0.1:8080 -F "file=@data.txt.enc" -F "password=<KEY_BASE64>" http://10.12.23.241:5000/decrypt
```

![Burp decrypt ok](images/11_burp_decrypt_ok.png)
*Hình 12 — `POST /decrypt` gửi file `.enc` kèm **Key base64** tương ứng trong trường `password` → `200 OK`. File `upload\data.txt.dec` chứa đúng “HUTECH University”. Response trả về **đường dẫn tuyệt đối** trên server (`D:\TH_LTANTT\...`), tức là lộ cấu trúc thư mục máy chủ (xem CT-05).*

![Burp decrypt lỗi](images/12_burp_decrypt_loi.png)
*Hình 13 — API gốc: gửi mật khẩu `pass123` thay vì Key → `500 Internal Server Error`. Terminal server in traceback `binascii.Error: Incorrect padding` tại `aes_utils.py` dòng 35.*

**Root cause:**

1. **Không xử lý lỗi.** Cùng nguyên nhân với GUI: trường `password` thực chất phải chứa Key. Khi sai, `decrypt_file_aes` ném `binascii.Error`, `ValueError` hoặc `InvalidTag`, route không bắt nên Flask trả **500**. Client nhận trang HTML chung chung, không biết mình sai ở đâu. Thiếu trường `file`/`password` thì `request.files['file']` ném `KeyError` và client nhận 400 dạng HTML.
2. **Path traversal khi lưu file upload** (phát hiện thêm trong lúc debug). Tên file được ghép thẳng: `os.path.join(FILES_DIR, f.filename)`, mà `f.filename` do client tự đặt. Gửi `filename=../../PWNED.txt` thì file bị ghi ra **ngoài** `upload/` (lên thư mục `crypto-toolkit/`). Trên Windows, nếu filename là đường dẫn tuyệt đối như `C:\...` thì `os.path.join` còn bỏ hẳn `FILES_DIR`, tức là client **ghi được file vào vị trí tuỳ ý** mà tiến trình có quyền ghi (ví dụ ghi đè `aes_utils.py` → thực thi mã khi server khởi động lại). Lỗ hổng này càng nguy hiểm khi server được mở ra mạng (`--host 0.0.0.0`) như lúc test bằng máy ảo. Đã kiểm chứng trên môi trường chạy thử bằng request sau:

   ```powershell
   curl.exe -F "file=@files/data.txt;filename=../../PWNED.txt" -F "password=pass123" http://127.0.0.1:5000/encrypt
   ```

   Với code gốc, `PWNED.txt` và `PWNED.txt.enc` xuất hiện ở `crypto-toolkit/`. Với code đã sửa, cùng request chỉ tạo `upload/PWNED.txt`.

**Cách sửa** (`securecrypto/api.py`):

```python
from werkzeug.utils import secure_filename
...
def save_upload(require_ext=None):
    f = request.files.get('file')
    secret = request.form.get('password', '')
    if f is None or not f.filename:
        return None, None, (jsonify({"error": "Thiếu trường 'file'"}), 400)
    if not secret:
        return None, None, (jsonify({"error": "Thiếu trường 'password'"}), 400)
    filename = secure_filename(f.filename)          # bỏ ../ / \ -> chặn path traversal
    ...
@app.route('/decrypt', methods=['POST'])
def decrypt():
    save_path, key_b64, error = save_upload(require_ext='.enc')
    ...
    try:
        out_path = aes_utils.decrypt_file_aes(save_path, key_b64)
    except (binascii.Error, ValueError):
        return jsonify({"error": "Key không hợp lệ: ..."}), 400
    except InvalidTag:
        return jsonify({"error": "Giải mã thất bại: sai Key hoặc file .enc đã bị sửa đổi"}), 400
```

- Dùng `request.files.get` / `request.form.get` để kiểm tra đủ trường, thiếu thì trả JSON 400.
- `secure_filename()` làm sạch tên file cho cả `/encrypt` và `/decrypt`; `/decrypt` chỉ nhận file `.enc`, kiểm tra **trước** khi ghi đĩa.
- Bắt lỗi giải mã, trả **400 + JSON có thông báo cụ thể** thay cho 500.

![Burp fix lỗi](images/16_burp_fix_loi.png)
*Hình 14 — API sau sửa, cùng request `pass123` như Hình 13: server trả `400 BAD REQUEST`, `Content-Type: application/json`, thông báo “Key không hợp lệ: trường 'password' phải chứa Key base64 (44 ký tự)…” thay cho trang HTML 500.*

![Burp fix ok](images/17_burp_fix_ok.png)
*Hình 15 — API sau sửa vẫn trả `200 OK` và giải mã đúng khi gửi Key hợp lệ. Bản sửa không làm hỏng chức năng cũ.*

### 3.6 GitSecure chặn commit

Repo dùng lại hook GitSecure của Bài 1.4 (`.githooks/pre-commit`, bật bằng `git config core.hooksPath .githooks`). Hook quét mọi file đã `git add` bằng 5 regex (password, apikey, secret, token, AWS key), chạy thêm Bandit, và `exit 1` nếu có phát hiện.

Toàn bộ bài (`crypto-toolkit`, `mini-ca`, README, ảnh) được đưa lên GitHub trong **một commit**, gồm các bước:
1. `git add .` → commit → GitSecure chặn (Hình 16).
2. Sửa file test → commit lại → qua kiểm tra (Hình 17).
3. Thêm ảnh minh chứng vào cùng commit bằng `git commit --amend` (hook chạy lại và vẫn qua) → `git push` một lần.

![GitSecure chặn](images/18_gitsecure_blocked.png)
*Hình 16 — Commit bị chặn: `Sensitive info found in crypto-toolkit/tests/test_hash_utils.py: pattern password\s*=\s*['\"][^'\"]{4,}['\"]`.*

**Root cause.** File test gán chuỗi cứng cho biến mật khẩu ở **3 dòng**:

| Dòng | Biến | Vì sao khớp regex |
|------|------|-------------------|
| 6 | `password` (test hash & verify) | gán chuỗi dài ≥ 4 ký tự trong dấu nháy |
| 20 | `password` (test sai mật khẩu) | như trên |
| 21 | `wrong_password` | regex **không neo đầu từ** nên chuỗi con `password` trong `wrong_password` vẫn khớp |

Hook dùng `re.search` trên **toàn bộ nội dung file**, nên còn một dòng khớp là vẫn bị chặn. Tài liệu hướng dẫn chỉ sửa dòng 6 thành chuỗi rỗng; khi thử lại đúng như vậy, commit **vẫn bị chặn** vì dòng 20 và 21.

**Cách sửa.** Không hardcode chuỗi mật khẩu trong mã nguồn nữa, mà sinh ngẫu nhiên lúc chạy test:

```python
import secrets

def test_hash_password_and_verify():
    password = secrets.token_urlsafe(16)
    ...

def test_wrong_password_verification():
    password = secrets.token_urlsafe(16)
    wrong_password = secrets.token_urlsafe(16)
    ...
```

Cách này tốt hơn đổi thành chuỗi rỗng: test vẫn kiểm tra đúng hành vi (đúng mật khẩu → verify được, mật khẩu khác → `VerifyMismatchError`), mỗi lần chạy lại dùng giá trị mới, và trong code không còn chuỗi nào trông giống secret.

![Commit thành công](images/19_commit_ok.png)
*Hình 17 — Sau khi sửa: pytest vẫn 6/6, hook báo `GitSecure: All checks passed.` và commit được tạo.*

Repo đã được đẩy lên GitHub tại <https://github.com/M1nhh3yh0/TH_LTANTT_2387700043_LEGIAMINH_BUOI2>.

**Phòng chống:**
- Không đặt mật khẩu hay khoá thật trong code, kể cả code test. Dùng biến môi trường, fixture hoặc giá trị sinh ngẫu nhiên.
- Hook chạy phía client nên bỏ qua được bằng `git commit --no-verify`. Cần thêm một lớp kiểm tra phía server hoặc CI (GitHub push protection / secret scanning, gitleaks).

---

## 4. Phần 2.4 — Mini CA

### 4.1 Thiết kế

```mermaid
flowchart TD
    R["Root CA — CN=Mini Root CA Root<br/>tự ký · hiệu lực 10 năm<br/>BasicConstraints CA:TRUE, pathlen=1"]
    I["Intermediate CA — CN=Mini Intermediate CA<br/>hiệu lực 5 năm<br/>BasicConstraints CA:TRUE, pathlen=0"]
    U["End-entity — CN=Phuoc_Nguyen<br/>hiệu lực 1 năm<br/>BasicConstraints CA:FALSE"]
    C["CRL certs/ca_crl.pem<br/>do Intermediate ký · next_update 7 ngày"]
    R -->|ký| I
    I -->|ký| U
    I -->|ký| C
    C -.->|serial bị thu hồi| U
```

| Yêu cầu của đề | Hiện thực | Ghi chú |
|----------------|-----------|---------|
| `create_root_ca()` | `ca_utils.create_root_ca()` | RSA 2048, subject = issuer (tự ký), SHA-256 |
| `create_intermediate_ca(root_ca)` | `ca_utils.create_intermediate_ca(root_key, root_cert)` | Root ký; `pathlen=0` nên Intermediate không được cấp CA con |
| `issue_certificate(ca, subject_info)` | `ca_utils.issue_certificate(ca_key, ca_cert, subject_info)` | `CA:FALSE`, lưu `<CN>_cert.pem` / `<CN>_key.pem` |
| `verify_certificate_chain(cert, ca_chain)` | `ca_utils.verify_certificate_chain(cert, chain)` | Kiểm chữ ký từng mắt xích bằng public key của issuer |
| `revoke_certificate(cert_serial, reason)` | `revoke_utils.revoke_certificate(cert_file, issuer_cert_file, issuer_key_file, reason)` | Thêm serial vào CRL rồi ký lại CRL bằng khoá Intermediate |
| `check_ocsp_status(cert_serial)` | `revoke_utils.check_revocation_status(cert_file)` | Thực chất là **tra CRL cục bộ**, không phải giao thức OCSP |

**Vì sao phân cấp 2 tầng:** khoá Root chỉ dùng để ký Intermediate, nên có thể cất offline. Công việc cấp cert hằng ngày do Intermediate làm. Nếu Intermediate bị lộ, Root thu hồi riêng nó mà không phải thay toàn bộ hệ thống tin cậy. `pathlen` giới hạn độ sâu chuỗi, để một CA cấp dưới không tự tạo thêm CA con.

### 4.2 Chạy `demo.py`

`demo.py` chạy tuần tự: tạo Root → tạo Intermediate → cấp cert cho `Phuoc_Nguyen` → kiểm tra chuỗi → thu hồi → kiểm tra trạng thái.

![demo.py](images/20_mini_ca_demo.png)
*Hình 18 — Kết quả `python demo.py`: `Chuỗi hợp lệ: True`, sau khi thu hồi `Trạng thái: Revoked`.*

Thư mục `certs/` sinh ra 7 file: `root_ca_key.pem`, `root_ca_cert.pem`, `intermediate_key.pem`, `intermediate_cert.pem`, `Phuoc_Nguyen_key.pem`, `Phuoc_Nguyen_cert.pem` và `ca_crl.pem`.

### 4.3 Giao diện `demo_ui.py`

Trình tự thao tác: **1 → 2 → 3 → 4 → 5 → 3**. Khung log giữ lại toàn bộ lịch sử nên thấy được trạng thái trước và sau khi thu hồi.

![demo_ui tạo CA](images/22_demo_ui_tao_ca.png)
*Hình 19 — Nút 1: tạo Root & Intermediate CA thành công.*

![demo_ui kiểm tra chuỗi](images/23_demo_ui_kiem_tra_chuoi.png)
*Hình 20 — Nút 2 cấp cert người dùng (log: `Đã phát hành: certs\Phuoc_Nguyen_cert.pem…`), nút 3 xác thực chuỗi → `True`.*

![demo_ui thu hồi](images/24_demo_ui_thu_hoi.png)
*Hình 21 — Từ trái sang phải: nút 4 thu hồi cert; nút 5 → “Trạng thái: Đã thu hồi”; nút 3 lần cuối **vẫn báo “Chuỗi chứng chỉ hợp lệ: True”** dù cert đã nằm trong CRL (xem CA-02).*

> Trong khung log của Tkinter, dấu `\` trong đường dẫn hiển thị thành `¥`. Đây chỉ là do font hiển thị, đường dẫn thật vẫn là `certs\...`.
>
> Mỗi lần bấm nút 1 sẽ sinh **cặp CA mới** và ghi đè file khoá cũ. Vì vậy sau khi mở lại `demo_ui.py` phải bấm nút 1 trước nút 2, và cert cấp bởi CA cũ sẽ không còn xác thực được với CA mới.

**Đối chiếu bằng OpenSSL** trên chính các file `certs/` sau khi chạy `demo_ui.py`:

```text
$ openssl verify -CAfile root_ca_cert.pem -untrusted intermediate_cert.pem Phuoc_Nguyen_cert.pem
Phuoc_Nguyen_cert.pem: OK                                  # chỉ kiểm chữ ký: hợp lệ

$ openssl verify -crl_check -CAfile root_ca_cert.pem -untrusted intermediate_cert.pem \
                 -CRLfile ca_crl.pem Phuoc_Nguyen_cert.pem
error 23 at 0 depth lookup: certificate revoked            # có kiểm CRL: bị từ chối
```

Như vậy chữ ký trong chuỗi đúng, nhưng một bộ xác thực chuẩn có kiểm CRL sẽ **từ chối** cert này. `verify_certificate_chain` thì vẫn trả `True` (Hình 21).

Cũng trong `ca_crl.pem` có **2 serial** bị thu hồi: `2EE3CE…` là cert của lần chạy `demo_ui.py`, còn `4124E7…` là cert của lần chạy `demo.py` trước đó, do một Intermediate CA **khác** cấp. `revoke_certificate` đọc CRL cũ và chép lại mọi dòng mà không kiểm tra CRL đó do ai ký, nên CRL mới gộp cả serial của CA cũ (xem CA-03).

### 4.4 Bảo vệ khoá riêng khi commit

**Root cause.** `save_key()` ghi khoá riêng bằng `serialization.NoEncryption()`, nên các file `root_ca_key.pem`, `intermediate_key.pem`, `Phuoc_Nguyen_key.pem` là **khoá RSA dạng rõ**, ai có file là có khoá. Mặt khác, 5 regex của GitSecure **không có mẫu nào cho khối `-----BEGIN RSA PRIVATE KEY-----`** (đã thử chạy các regex trên `root_ca_key.pem`: không khớp mẫu nào). Nếu lỡ `git add certs/`, hook vẫn báo “All checks passed” và khoá Root bị đẩy lên GitHub.

**Biện pháp đã áp dụng:** thêm `certs/` và `*.pem` vào `.gitignore` để git bỏ qua hoàn toàn thư mục khoá:

```gitignore
__pycache__/
*.pyc
.vscode/
.DS_Store
gitsecure.log
certs/
*.pem
```

Kết quả: trong danh sách file của commit, phần `mini-ca` chỉ có 5 file mã nguồn (`ca_utils.py`, `demo.py`, `demo_ui.py`, `requirements.txt`, `revoke_utils.py`), không có file nào trong `certs/` và không có file `.pem` nào. Hook vẫn chạy qua bình thường (Hình 17).

**Đề xuất thêm:** mã hoá khoá riêng bằng `serialization.BestAvailableEncryption(passphrase)` với passphrase lấy từ biến môi trường; bổ sung regex `-----BEGIN [A-Z ]*PRIVATE KEY-----` vào GitSecure; trong thực tế, khoá Root phải được giữ offline hoặc trong HSM.

---

## 5. Đánh giá bảo mật & hạn chế còn lại

| Mã | Thành phần | Vấn đề | Mức độ | Trạng thái |
|----|-----------|--------|--------|------------|
| CT-01 | `aes_utils` | Giải mã không dùng mật khẩu | Cao | Giữ theo đề |
| CT-02 | `api.py` | Path traversal / ghi file tuỳ ý qua `filename` | Cao | **Đã sửa** |
| CT-03 | `api.py` | Lỗi giải mã / thiếu trường → 500 HTML | Trung bình | **Đã sửa** |
| CT-04 | `app_gui.py` | Không copy được Key, lỗi bị nuốt im lặng | Trung bình | **Đã sửa** |
| CT-05 | `api.py` | Không xác thực, không TLS, không giới hạn dung lượng upload, trả đường dẫn tuyệt đối của server (Hình 12, Hình 15) | Trung bình | Ghi nhận |
| CT-06 | `aes_utils` | PBKDF2 100 000 vòng, thấp hơn khuyến nghị OWASP (600 000 cho PBKDF2-HMAC-SHA256) | Thấp | Ghi nhận |
| CT-07 | `aes_utils` | `replace('.enc', '.dec')` thay mọi chỗ trong đường dẫn | Thấp | Ghi nhận |
| CT-08 | `rsa_utils` | Chữ ký PKCS#1 v1.5; hệ thống mới nên dùng RSA-PSS | Thấp | Ghi nhận |
| GS-A | GitSecure | Dương tính giả (chuỗi con `wrong_password`) và âm tính giả (không nhận ra khoá PEM) | Trung bình | Ghi nhận |
| CA-01 | `ca_utils` | Khoá riêng lưu không mã hoá | Cao | Giảm thiểu bằng `.gitignore` |
| CA-02 | `ca_utils` | `verify_certificate_chain` chỉ kiểm chữ ký | Cao | Ghi nhận |
| CA-03 | `revoke_utils` | “OCSP” thực chất là tra CRL cục bộ; không kiểm chữ ký/issuer của CRL, gộp nhầm serial của CA cũ | Trung bình | Ghi nhận |
| CA-04 | `demo_ui` | Nút 1 tạo lại CA, ghi đè khoá Root không cảnh báo | Thấp | Ghi nhận |
| CA-05 | `ca_utils`, `revoke_utils` | `datetime.utcnow()` deprecated từ Python 3.12 | Thấp | Ghi nhận |

**CT-01 — Giải mã không dùng mật khẩu (Cao).** `encrypt_file_aes` sinh khoá từ mật khẩu + salt rồi **trả về chính khoá đó**. `decrypt_file_aes` đọc salt ra nhưng **không dùng**, mà nhận thẳng khoá. Hệ quả: (1) mật khẩu mất ý nghĩa sau khi mã hoá, ai có chuỗi Key là giải mã được; (2) chuỗi Key là secret thật nhưng bị in ra terminal, hiện trên GUI và trả qua HTTP; (3) người dùng dễ nhầm, đây chính là root cause của lỗi ở GUI và API. Cách đúng: `decrypt_file_aes(encrypted_file, password)` đọc salt 16 byte đầu, gọi lại `derive_key_from_password(password, salt)` rồi giải mã, không bao giờ trả khoá ra ngoài. Báo cáo giữ nguyên hàm theo đề để CLI và unit test khớp tài liệu.

**CA-02 — Xác thực chuỗi chỉ kiểm chữ ký (Cao).** Hàm chỉ lấy public key của issuer để verify chữ ký, **không** kiểm: thời hạn hiệu lực, `BasicConstraints` / `pathlen`, KeyUsage, trạng thái thu hồi, và Root có phải trust anchor đáng tin hay không. Trường hợp thứ nhất thấy trực tiếp ở Hình 21 và phần đối chiếu OpenSSL. Hai trường hợp còn lại được kiểm thử thêm bằng script gọi chính hàm này:

| Trường hợp | Kết quả mong đợi | `verify_certificate_chain` |
|------------|------------------|----------------------------|
| Cert đã bị thu hồi trong CRL | Không hợp lệ (OpenSSL: `certificate revoked`) | `True` |
| Cert đã hết hạn | Không hợp lệ | `True` |
| Cert do một **end-entity (`CA:FALSE`)** ký | Không hợp lệ | `True` |

Trường hợp thứ ba nguy hiểm nhất: bất kỳ ai được cấp một cert người dùng đều có thể dùng khoá của mình để ký cert khác, và hàm vẫn chấp nhận. Cách sửa: kiểm `not_valid_before/after`, bắt buộc issuer có `CA:TRUE` và tuân `pathlen`, tra CRL, hoặc dùng bộ xác thực chuẩn (`cryptography.x509.verification.PolicyBuilder`, `openssl verify -crl_check`).

**CA-03 — “OCSP” không phải OCSP (Trung bình).** `check_revocation_status` chỉ đọc file CRL và so serial. Hàm không kiểm chữ ký CRL, không kiểm issuer, không kiểm `next_update`, nên một CRL giả hoặc đã hết hạn vẫn được tin. `revoke_certificate` cũng chép nguyên các dòng của CRL cũ sang CRL mới mà không kiểm CRL cũ do ai ký, nên CRL hiện tại chứa cả serial `4124E7…` của một Intermediate CA đã bị thay thế. OCSP thật là truy vấn trực tuyến tới responder và nhận phản hồi có ký.

---

## 6. Kết luận

- Hoàn thành thư viện `securecrypto` với AES-256-GCM, RSA, Argon2 và 3 giao diện (CLI, GUI, API); 6/6 unit test đạt.
- Debug GUI và API: root cause chung là **thiết kế nhầm lẫn giữa mật khẩu và khoá**, cộng với việc **không xử lý exception**. Đã sửa để báo lỗi rõ ràng, copy được Key, và chặn thêm lỗ hổng path traversal ở API.
- GitSecure chặn commit do mật khẩu hardcode trong test. Đã sửa tận gốc bằng cách sinh ngẫu nhiên lúc chạy, thay vì chỉ xoá một dòng như tài liệu.
- Dựng được CA hai cấp, cấp, xác thực và thu hồi chứng chỉ; khoá riêng được loại khỏi git bằng `.gitignore`. Đối chiếu bằng OpenSSL cho thấy hàm xác thực chuỗi của bài bỏ qua CRL.
- Test API từ máy ảo Kali bằng Burp Suite. Sự cố Burp làm hỏng file nhị phân vô tình trở thành bằng chứng thực tế: AES-GCM phát hiện ciphertext bị sửa (`InvalidTag`).
- Bài học chính: dùng thuật toán mạnh chưa đủ an toàn. Cần quản lý khoá đúng cách (không trả khoá ra ngoài, không lưu khoá dạng rõ) và xác thực đầy đủ (chuỗi chứng chỉ phải kiểm thời hạn, ràng buộc CA, thu hồi).
