"""凭据签发与校验：HMAC 签名的短期访问凭据与可轮换刷新凭据。

凭据格式：base64url(payload_json).base64url(hmac_sha256)
- 访问凭据 payload: {"typ": "access", "jti", "sub", "sid", "ver", "pver", "exp"}
- 刷新凭据 payload: {"typ": "refresh", "jti", "sid", "exp"}
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid

from app.models import AccessTokenClaims


class TokenError(Exception):
    """凭据校验失败，reason 可区分：malformed / expired / bad_signature。"""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


class TokenService:
    def __init__(self, secret: str) -> None:
        self._key = secret.encode()

    def _sign(self, payload_b64: str) -> str:
        return _b64e(hmac.new(self._key, payload_b64.encode(), hashlib.sha256).digest())

    def _issue(self, payload: dict) -> str:
        body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
        return f"{body}.{self._sign(body)}"

    def _parse(self, token: str, expected_type: str) -> dict:
        try:
            body, sig = token.split(".")
            payload = json.loads(_b64d(body))
        except Exception as exc:
            raise TokenError("malformed") from exc
        if not hmac.compare_digest(sig, self._sign(body)):
            raise TokenError("bad_signature")
        if payload.get("typ") != expected_type:
            raise TokenError("malformed")
        if float(payload.get("exp", 0)) < time.time():
            raise TokenError("expired")
        return payload

    def issue_access_token(self, user_id: str, session_id: str, token_version: int,
                           policy_version: int, ttl: float) -> str:
        return self._issue({
            "typ": "access",
            "jti": uuid.uuid4().hex,
            "sub": user_id,
            "sid": session_id,
            "ver": token_version,
            "pver": policy_version,
            "exp": time.time() + ttl,
        })

    def issue_refresh_token(self, session_id: str, jti: str, ttl: float) -> str:
        return self._issue({
            "typ": "refresh",
            "jti": jti,
            "sid": session_id,
            "exp": time.time() + ttl,
        })

    def verify_access_token(self, token: str) -> AccessTokenClaims:
        payload = self._parse(token, "access")
        return AccessTokenClaims(
            jti=payload["jti"],
            user_id=payload["sub"],
            session_id=payload["sid"],
            token_version=int(payload["ver"]),
            policy_version=int(payload["pver"]),
            expires_at=float(payload["exp"]),
        )

    def parse_refresh_token(self, token: str) -> tuple[str, str]:
        payload = self._parse(token, "refresh")
        return payload["sid"], payload["jti"]
