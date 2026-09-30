import secrets
import pytest
from securecrypto import hash_utils
from argon2.exceptions import VerifyMismatchError

# Mật khẩu test được sinh ngẫu nhiên lúc chạy -> không hardcode chuỗi bí mật
# trong mã nguồn (GitSecure chặn commit nếu có).

def test_hash_password_and_verify():
    password = secrets.token_urlsafe(16)
    hashed = hash_utils.hash_password_secure(password)
    assert hashed is not None

    from argon2 import PasswordHasher
    ph = PasswordHasher()
    try:
        ph.verify(hashed, password)
        verified = True
    except VerifyMismatchError:
        verified = False
    assert verified == True

def test_wrong_password_verification():
    password = secrets.token_urlsafe(16)
    wrong_password = secrets.token_urlsafe(16)
    hashed = hash_utils.hash_password_secure(password)

    from argon2 import PasswordHasher
    ph = PasswordHasher()
    try:
        ph.verify(hashed, wrong_password)
        verified = True
    except VerifyMismatchError:
        verified = False
    assert verified == False
