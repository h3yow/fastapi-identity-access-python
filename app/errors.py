"""领域错误码与异常类型。

错误码即“可解释的失败原因”，调用方（测试、审计、HTTP 层）
一律依据 ErrorCode 区分不同失败语义，而不是解析自然语言消息。
"""

from __future__ import annotations

import enum


class ErrorCode(str, enum.Enum):
    # ---- 登录 / MFA ----
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_DISABLED = "account_disabled"
    MFA_REQUIRED = "mfa_required"
    MFA_INVALID = "mfa_invalid"
    MFA_CHALLENGE_EXPIRED = "mfa_challenge_expired"

    # ---- 访问凭据 ----
    ACCESS_TOKEN_INVALID = "access_token_invalid"
    ACCESS_TOKEN_EXPIRED = "access_token_expired"

    # ---- 会话 / 刷新令牌 ----
    SESSION_NOT_FOUND = "session_not_found"
    SESSION_REVOKED = "session_revoked"
    REFRESH_EXPIRED = "refresh_expired"
    # 使用了已被撤销（登出 / 禁用 / 连带作废）的刷新令牌。
    REFRESH_TOKEN_REVOKED = "refresh_token_revoked"
    # 已轮换的旧令牌在非并发窗口再次出现：重放攻击，整族会话作废。
    REFRESH_REUSE_DETECTED = "refresh_reuse_detected"
    # 同一令牌并发使用，仅一个请求能赢；输的一方得到此原因。
    REFRESH_CONCURRENT = "refresh_concurrent"
    USER_NOT_FOUND = "user_not_found"

    # ---- 即时生效的状态漂移 ----
    # 访问凭据签发后策略被更新：拒绝，要求用刷新令牌换取新凭据。
    POLICY_REVISION_STALE = "policy_revision_stale"
    # 访问凭据携带的角色版本落后：拒绝，避免沿用旧角色权限。
    ROLE_REVISION_STALE = "role_revision_stale"

    # ---- 授权判定 ----
    UNAUTHENTICATED = "unauthenticated"
    FORBIDDEN = "forbidden"
    RESOURCE_NOT_FOUND = "resource_not_found"


class DomainError(Exception):
    """可解释的领域错误，携带稳定错误码与 HTTP 状态码。"""

    def __init__(self, code: ErrorCode, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code

    def to_dict(self) -> dict[str, str]:
        return {"error": self.code.value, "message": self.message}
