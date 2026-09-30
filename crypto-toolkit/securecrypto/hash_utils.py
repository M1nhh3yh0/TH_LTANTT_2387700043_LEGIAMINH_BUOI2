from argon2 import PasswordHasher

ph = PasswordHasher()
def hash_password_secure(password):
    return ph.hash(password)
