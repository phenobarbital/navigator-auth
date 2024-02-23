import secrets
import hashlib
import base64
from ...exceptions import AuthException
from ...conf import (
    AUTH_PWD_DIGEST,
    AUTH_PWD_LENGTH,
    AUTH_PWD_ALGORITHM,
    AUTH_PWD_SALT_LENGTH
)

def set_basic_password(
    password: str, token_num: int = 6, iterations: int = 80000, salt: str = None
):
    if not salt:
        salt = secrets.token_hex(token_num)
    key = hashlib.pbkdf2_hmac(
        AUTH_PWD_DIGEST,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
        dklen=AUTH_PWD_LENGTH,
    )
    hst = base64.b64encode(key).decode("utf-8").strip()
    return f"{AUTH_PWD_ALGORITHM}${iterations}${salt}${hst}"


def check_password(current_password, password):
    if not password:
        return False
    try:
        algorithm, iterations, salt, _ = current_password.split("$", 3)
    except ValueError as ex:
        raise AuthException("Invalid Password Algorithm: {ex}") from ex
    assert algorithm == AUTH_PWD_ALGORITHM
    compare_hash = set_basic_password(
        password, iterations=int(iterations), salt=salt, token_num=AUTH_PWD_SALT_LENGTH
    )
    return secrets.compare_digest(current_password, compare_hash)
