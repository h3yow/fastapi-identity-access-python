"""核心领域模型：用户、角色、会话、凭据与判定结果类型。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class LoginFailureReason(enum.Enum):
    """登录失败原因，需可区分。"""

    USER_NOT_FOUND = "user_not_found"
    BAD_PASSWORD = "bad_password"
    BAD_MFA = "bad_mfa"
    ACCOUNT_DISABLED = "account_disabled"


class RefreshFailureReason(enum.Enum):
    """会话续期失败原因，需可区分。"""

    TOKEN_MALFORMED = "token_malformed"
    TOKEN_EXPIRED = "token_expired"
    SESSION_NOT_FOUND = "session_not_found"
    # 并发撞车：jti 刚被另一个在途请求消费（冲突窗口内），可重试的临时冲突
    CONCURRENT_CONFLICT = "concurrent_conflict"
    # 复用：jti 早已被消费（超出冲突窗口）或来路不明，按安全事件处理，
    # 一经判定，该会话永久作废，不得再签出任何新凭据
    SESSION_REUSED = "session_reused"
    SESSION_REVOKED = "session_revoked"
    ACCOUNT_DISABLED = "account_disabled"


class AuthzDecision(enum.Enum):
    """授权判定三种语义明确的结果。"""

    UNAUTHENTICATED = "unauthenticated"  # 未认证
    FORBIDDEN = "forbidden"  # 已认证但未授权
    NOT_FOUND = "not_found"  # 目标资源不存在
    ALLOWED = "allowed"


@dataclass(frozen=True)
class Role:
    name: str
    permissions: frozenset[str]  # 形如 "document:read"


@dataclass
class User:
    user_id: str
    username: str
    password_hash: str
    mfa_secret: str
    roles: set[str] = field(default_factory=set)
    disabled: bool = False
    token_version: int = 0  # 权限/状态变更时递增，使旧访问凭据立即失效


@dataclass
class Session:
    session_id: str
    user_id: str
    current_refresh_id: str  # 当前唯一有效的 refresh token jti
    token_version: int  # 签发会话时的用户 token_version 快照
    expires_at: float
    revoked: bool = False


@dataclass(frozen=True)
class AccessTokenClaims:
    jti: str
    user_id: str
    session_id: str
    token_version: int
    expires_at: float


@dataclass(frozen=True)
class Resource:
    resource_id: str
    owner_id: str
    attributes: frozenset[str]  # 资源属性，如 "confidential"
