"""密码、TOTP 与令牌编码工具。

- 口令：PBKDF2-HMAC-SHA256 + 随机盐（本地模拟，不依赖外部库）。
- 随机令牌：secrets.token_urlsafe。
- TOTP：RFC 4226/6238 风格 HOTP/TOTP，base32 密钥。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct

_PBKDF2_ROUNDS = 200_000


def generate_secret() -> str:
    """生成 20 字节随机 base32 TOTP 密钥。"""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def new_token() -> str:
    """生成不可猜测的随机令牌字符串。"""
    return secrets.token_urlsafe(32)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, rounds_s, salt_b64, digest_b64 = password_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        rounds = int(rounds_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return hmac.compare_digest(candidate, expected)


def _decode_b32(secret: str) -> bytes:
    # 补齐 base32 padding。
    padding = "=" * (-len(secret) % 8)
    return base64.b32decode(secret.upper() + padding, casefold=True)


def _hotp(secret: str, counter: int, digits: int) -> str:
    key = _decode_b32(secret)
    msg = struct.pack(">Q", counter)
    mac = hmac.new(key, msg, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFF_FFFF
    return str(binary % (10 ** digits)).zfill(digits)


def totp_code(secret: str, timestamp: float, *, step: int = 30, digits: int = 6) -> str:
    return _hotp(secret, int(timestamp) // step, digits)


def verify_totp(
    secret: str,
    code: str,
    timestamp: float,
    *,
    step: int = 30,
    digits: int = 6,
) -> bool:
    if not code or not code.isdigit():
        return False
    counter = int(timestamp) // step
    # 允许前后一个时间步的时钟漂移。
    for candidate_counter in (counter - 1, counter, counter + 1):
        if hmac.compare_digest(_hotp(secret, candidate_counter, digits), code.zfill(digits)):
            return True
    return False
