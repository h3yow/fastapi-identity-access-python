"""核心领域模型（仅类型定义）。"""

from __future__ import annotations

import dataclasses
import enum


@dataclasses.dataclass
class User:
    id: str
    username: str
    password_hash: str
    roles: list[str]
    enabled: bool
    mfa_secret: str
    roles_version: int = 0


class PrincipalType(str, enum.Enum):
    USER = "user"
    ROLE = "role"
    OWNER = "owner"


@dataclasses.dataclass
class Policy:
    id: str
    principal_type: PrincipalType
    principal: str
    action: str
    resource_owner: str
    resource_tags: frozenset[str]
    effect_allow: bool
    version: int


@dataclasses.dataclass
class Resource:
    id: str
    owner: str
    tags: frozenset[str]
    exists: bool = True


@dataclasses.dataclass
class AccessTokenRecord:
    jti: str
    user_id: str
    session_id: str
    expires_at: float
    roles: tuple[str, ...]
    roles_version: int
    policy_version: int
    revoked: bool = False


@dataclasses.dataclass
class MfaChallenge:
    challenge_id: str
    user_id: str
    expires_at: float
    consumed: bool = False


@dataclasses.dataclass
class RefreshToken:
    jti: str
    session_id: str
    family_id: str
    issued_at: float
    expires_at: float
    consumed_at: float | None = None
    revoked: bool = False
    replaced_by: str | None = None
    in_flight: bool = False
    in_flight_deadline: float = 0.0


@dataclasses.dataclass
class Session:
    session_id: str
    family_id: str
    user_id: str
    created_at: float
    absolute_expires_at: float
    revoked: bool = False
    revoke_reason: str = ""
    current_refresh_jti: str = ""


@dataclasses.dataclass
class Decision:
    request_id: str
    allowed: bool
    reason: str
    user_id: str | None
    action: str
    resource_id: str
    billed: bool
