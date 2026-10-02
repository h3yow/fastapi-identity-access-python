"""认证服务：多因素登录、会话续期（单次使用轮换）、登出与账号禁用。

并发一致性：会话轮换的"校验旧 jti + 作废 + 写入新 jti"在 store 锁内原子完成，
因此并发续期最多只有一个成功。失败原因细分：
- 落败方在宽限窗口内持刚被消费的旧 jti 到达 → REFRESH_CONFLICT（可安全重试）；
- 宽限窗口外重放已消费的 jti → SESSION_REUSED（安全事件），会话立即终止，
  之后不得再签出任何新凭据。
"""
from __future__ import annotations

import hashlib
import hmac
import struct
import time
import uuid
from collections.abc import Callable

from app.models import LoginFailureReason, RefreshFailureReason, Role, Session
from app.store import Store
from app.tokens import TokenError, TokenService

ACCESS_TOKEN_TTL = 300.0  # 短期访问凭据：5 分钟
REFRESH_TOKEN_TTL = 7 * 24 * 3600.0  # 长期会话：7 天


def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


def totp_code(secret: str, at: float | None = None, window: int = 0) -> str:
    """基于时间的动态口令（TOTP, HMAC-SHA1, 30 秒步长, 6 位）。"""
    counter = int((at if at is not None else time.time()) // 30) + window
    digest = hmac.new(secret.encode(), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


class LoginError(Exception):
    def __init__(self, reason: LoginFailureReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class RefreshError(Exception):
    def __init__(self, reason: RefreshFailureReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class AuthService:
    def __init__(self, store: Store, tokens: TokenService,
                 rotation_leeway: float = 2.0, clock: Callable[[], float] = time.time) -> None:
        self._store = store
        self._tokens = tokens
        # 撞车宽限窗口：上一次轮换发生后这么短的时间内，旧 jti 再次被提交，
        # 视为"几乎同时续期"的并发落败方（可重试），而非凭据重放。
        self._rotation_leeway = rotation_leeway
        self._clock = clock

    def _issue_pair(self, session: Session, token_version: int) -> dict:
        jti = uuid.uuid4().hex
        session.current_refresh_id = jti
        return {
            "access_token": self._tokens.issue_access_token(
                session.user_id, session.session_id, token_version,
                self._store.policy_version, ACCESS_TOKEN_TTL
            ),
            "refresh_token": self._tokens.issue_refresh_token(
                session.session_id, jti, session.expires_at - time.time()
            ),
        }

    def login(self, username: str, password: str, mfa_code: str) -> dict:
        """校验口令 + MFA，签发访问凭据与新会话。"""
        store = self._store
        with store.lock:
            user = next((u for u in store.users.values() if u.username == username), None)
            if user is None:
                raise LoginError(LoginFailureReason.USER_NOT_FOUND)
            if user.disabled:
                raise LoginError(LoginFailureReason.ACCOUNT_DISABLED)
            if not hmac.compare_digest(user.password_hash, hash_password(password, user.user_id)):
                raise LoginError(LoginFailureReason.BAD_PASSWORD)
            if mfa_code not in {totp_code(user.mfa_secret, window=w) for w in (-1, 0, 1)}:
                raise LoginError(LoginFailureReason.BAD_MFA)
            session = Session(
                session_id=uuid.uuid4().hex,
                user_id=user.user_id,
                current_refresh_id="",
                token_version=user.token_version,
                expires_at=time.time() + REFRESH_TOKEN_TTL,
            )
            store.sessions[session.session_id] = session
            return self._issue_pair(session, user.token_version)

    def refresh(self, refresh_token: str) -> dict:
        """单次使用轮换：旧 refresh token 立即作废，返回新凭据对。"""
        try:
            session_id, jti = self._tokens.parse_refresh_token(refresh_token)
        except TokenError as exc:
            reason = (
                RefreshFailureReason.TOKEN_EXPIRED
                if exc.reason == "expired"
                else RefreshFailureReason.TOKEN_MALFORMED
            )
            raise RefreshError(reason) from exc

        store = self._store
        with store.lock:
            session = store.sessions.get(session_id)
            if session is None:
                raise RefreshError(RefreshFailureReason.SESSION_NOT_FOUND)
            if session.revoked:
                raise RefreshError(RefreshFailureReason.SESSION_REVOKED)
            if session.expires_at < time.time():
                raise RefreshError(RefreshFailureReason.TOKEN_EXPIRED)
            user = store.users[session.user_id]
            if user.disabled:
                raise RefreshError(RefreshFailureReason.ACCOUNT_DISABLED)
            # 单次使用语义：按 jti 状态分三种情况，失败原因必须可区分。
            now = self._clock()
            if jti == session.current_refresh_id and jti not in store.used_refresh_ids:
                # 正常轮换：作废旧 jti，记录本次轮换（供撞车判定），签发新凭据对。
                store.used_refresh_ids.add(jti)
                session.last_consumed_jti = jti
                session.last_consumed_at = now
                # 权限快照随续期刷新：角色调整后的新凭据携带新 token_version。
                session.token_version = user.token_version
                return self._issue_pair(session, user.token_version)
            if jti in store.used_refresh_ids:
                if (jti == session.last_consumed_jti
                        and now - session.last_consumed_at <= self._rotation_leeway):
                    # 上一次轮换后宽限窗口内再次提交同一旧凭据：
                    # 并发撞车的落败方（或在途重试），可安全重试，会话不受影响。
                    raise RefreshError(RefreshFailureReason.REFRESH_CONFLICT)
                # 宽限窗口之外重放已消费凭据：按安全事件处理。
                # 会话立即终止——之后不得再签出任何新凭据，
                # 绝不出现重放方与持方两个都还能用的会话。
                session.revoked = True
                raise RefreshError(RefreshFailureReason.SESSION_REUSED)
            # 签名有效但从未签发过的 jti：异常凭据，按复用处理并终止会话。
            session.revoked = True
            raise RefreshError(RefreshFailureReason.SESSION_REUSED)

    def logout(self, session_id: str) -> None:
        with self._store.lock:
            session = self._store.sessions.get(session_id)
            if session is not None:
                session.revoked = True

    def disable_user(self, user_id: str) -> None:
        """禁用账号：撤销其全部会话并递增 token_version。"""
        with self._store.lock:
            user = self._store.users[user_id]
            user.disabled = True
            user.token_version += 1
            for session in self._store.sessions.values():
                if session.user_id == user_id:
                    session.revoked = True

    def set_roles(self, user_id: str, roles: set[str]) -> None:
        """调整角色：递增 token_version 使旧访问凭据立即失效。"""
        with self._store.lock:
            user = self._store.users[user_id]
            user.roles = set(roles)
            user.token_version += 1

    def set_role_permissions(self, role_name: str, permissions: set[str]) -> None:
        """修改角色本身的权限集合：递增全局 policy_version。

        用户持有的角色不变，但判定依据已变：按旧权限集合签发的访问凭据
        立即失效——收窄后不得继续放行已移除的权限，放开后也不得静默
        获得新权限，必须续期拿到携带新 policy_version 的凭据。
        """
        with self._store.lock:
            role = self._store.roles[role_name]
            self._store.roles[role_name] = Role(role.name, frozenset(permissions))
            self._store.policy_version += 1
