"""登录、MFA、会话轮换、凭据校验与会话管理。

刷新令牌状态机（单次使用语义）：
    ACTIVE ──轮换成功──> CONSUMED(replaced_by=新jti) ──> 再次出现:
        距离 consumed_at <= 并发窗口 且 出示者拿到的正是 replaced_by 的新令牌
            -> REFRESH_CONCURRENT（输的并发方，幂等返回同一份新凭据由 HTTP 层处理，
               这里直接以并发失败拒绝，语义可区分，绝不签发第二份）
        否则 -> REFRESH_REUSE_DETECTED（重放：整族会话与全部令牌立即作废）
    ACTIVE 上的并发轮换由 session 级互斥锁串行化，只有一个赢家。
    已撤销 / 已过期 -> REFRESH_TOKEN_REVOKED / REFRESH_EXPIRED。
"""

from __future__ import annotations

import logging

from app.errors import DomainError, ErrorCode
from app.models import (
    AccessTokenRecord,
    MfaChallenge,
    RefreshToken,
    Session,
)
from app.security import (
    hash_password,
    new_token,
    totp_code,
    verify_password,
    verify_totp,
)
from app.settings import Settings
from app.storage import Store

logger = logging.getLogger("iac.auth")


# ---------------------------------------------------------------- 内部工具

def _fail(code: ErrorCode, message: str, *, status_code: int = 401) -> DomainError:
    logger.warning("auth fail reason=%s detail=%s", code.value, message)
    return DomainError(code, message, status_code=status_code)


def _revoke_session_locked(
    store: Store, session: Session, reason: str, *, revoke_refresh: bool = True
) -> None:
    """调用方须持有 store.lock。撤销会话并连带作废其刷新/访问凭据。"""
    session.revoked = True
    session.revoke_reason = reason
    for rt in store.refresh_tokens.values():
        if rt.session_id == session.session_id and revoke_refresh:
            rt.revoked = True
    for at in store.access_tokens.values():
        if at.session_id == session.session_id:
            at.revoked = True


def _revoke_family_locked(store: Store, family_id: str, reason: str) -> None:
    """重放检测：作废整族会话（同一会话家族只有一个活动会话，防御性遍历）。"""
    for sess in store.sessions.values():
        if sess.family_id == family_id:
            _revoke_session_locked(store, sess, reason)


def _issue_tokens_locked(
    store: Store,
    settings: Settings,
    session: Session,
    now: float,
    *,
    previous_refresh_jti: str | None,
) -> tuple[AccessTokenRecord, str, RefreshToken]:
    """调用方须持有 store.lock。签发一对新的访问凭据 + 刷新令牌。"""
    user = store.users[session.user_id]
    access_jti = new_token()
    access = AccessTokenRecord(
        jti=access_jti,
        user_id=user.id,
        session_id=session.session_id,
        expires_at=now + settings.access_token_ttl_seconds,
        roles=tuple(user.roles),
        roles_version=user.roles_version,
        policy_version=store.policy_version,
    )
    store.access_tokens[access_jti] = access

    refresh_jti = new_token()
    refresh = RefreshToken(
        jti=refresh_jti,
        session_id=session.session_id,
        family_id=session.family_id,
        issued_at=now,
        expires_at=min(
            now + settings.refresh_token_ttl_seconds, session.absolute_expires_at
        ),
    )
    store.refresh_tokens[refresh_jti] = refresh
    session.current_refresh_jti = refresh_jti

    if previous_refresh_jti is not None:
        prev = store.refresh_tokens.get(previous_refresh_jti)
        if prev is not None:
            prev.consumed_at = now
            prev.replaced_by = refresh_jti
    return access, refresh_jti, refresh


# ---------------------------------------------------------------- 登录 / MFA

def begin_login(
    store: Store, settings: Settings, *, username: str, password: str, now: float
) -> MfaChallenge:
    """第一步：校验口令，通过则下发一次性 MFA 挑战。"""
    with store.lock:
        user_id = store.users_by_username.get(username)
        user = store.users.get(user_id) if user_id else None
        # 用户不存在与口令错误给出同一原因，避免账号枚举。
        if user is None or not verify_password(password, user.password_hash):
            raise _fail(
                ErrorCode.INVALID_CREDENTIALS,
                f"username={username!r} 口令校验失败",
                status_code=401,
            )
        if not user.enabled:
            raise _fail(
                ErrorCode.ACCOUNT_DISABLED,
                f"username={username!r} 账号已被禁用",
                status_code=403,
            )
        challenge = MfaChallenge(
            challenge_id=new_token(),
            user_id=user.id,
            expires_at=now + settings.mfa_challenge_ttl_seconds,
        )
        store.mfa_challenges[challenge.challenge_id] = challenge
        logger.info(
            "login begin ok username=%s user_id=%s challenge_id=%s",
            username, user.id, challenge.challenge_id,
        )
        return challenge


def complete_login(
    store: Store,
    settings: Settings,
    *,
    challenge_id: str,
    mfa_code: str,
    now: float,
) -> tuple[AccessTokenRecord, str]:
    """第二步：校验 MFA，建立会话家族并签发首对凭据。"""
    with store.lock:
        challenge = store.mfa_challenges.get(challenge_id)
        if challenge is None:
            raise _fail(
                ErrorCode.MFA_INVALID,
                f"challenge_id={challenge_id!r} 不存在",
                status_code=401,
            )
        if challenge.consumed:
            raise _fail(
                ErrorCode.MFA_INVALID,
                f"challenge_id={challenge_id!r} 已使用，挑战一次性",
                status_code=401,
            )
        if now >= challenge.expires_at:
            raise _fail(
                ErrorCode.MFA_CHALLENGE_EXPIRED,
                f"challenge_id={challenge_id!r} 已过期",
                status_code=401,
            )
        user = store.users.get(challenge.user_id)
        if user is None or not user.enabled:
            raise _fail(
                ErrorCode.ACCOUNT_DISABLED,
                f"user_id={challenge.user_id} 不可用",
                status_code=403,
            )
        expected = totp_code(
            user.mfa_secret,
            now,
            step=settings.mfa_time_step_seconds,
            digits=settings.mfa_digits,
        )
        if not verify_totp(
            user.mfa_secret,
            mfa_code,
            now,
            step=settings.mfa_time_step_seconds,
            digits=settings.mfa_digits,
        ):
            raise _fail(
                ErrorCode.MFA_INVALID,
                f"challenge_id={challenge_id!r} TOTP 不匹配 expected~={expected}",
                status_code=401,
            )

        challenge.consumed = True
        session_id = new_token()
        family_id = new_token()
        session = Session(
            session_id=session_id,
            family_id=family_id,
            user_id=user.id,
            created_at=now,
            absolute_expires_at=now + settings.session_absolute_ttl_seconds,
        )
        store.sessions[session_id] = session
        access, refresh_jti, _ = _issue_tokens_locked(
            store, settings, session, now, previous_refresh_jti=None
        )
        logger.info(
            "login complete user_id=%s session_id=%s family_id=%s access_jti=%s refresh_jti=%s",
            user.id, session_id, family_id, access.jti, refresh_jti,
        )
        return access, refresh_jti


# ---------------------------------------------------------------- 刷新轮换

def rotate_refresh_token(
    store: Store,
    settings: Settings,
    *,
    refresh_token: str,
    now: float,
) -> tuple[AccessTokenRecord, str]:
    """用一次性刷新令牌换取新的访问凭据 + 新刷新令牌（轮换）。"""
    with store.lock:
        rt = store.refresh_tokens.get(refresh_token)
        if rt is None:
            raise _fail(
                ErrorCode.SESSION_NOT_FOUND,
                "刷新令牌无法识别",
                status_code=401,
            )
        session = store.sessions.get(rt.session_id)
        if session is None:
            raise _fail(
                ErrorCode.SESSION_NOT_FOUND,
                f"session_id={rt.session_id} 不存在",
                status_code=401,
            )

    # 会话级互斥：同一刷新令牌的并发轮换严格串行，只有一个赢家。
    with store.session_lock(session.session_id):
        with store.lock:
            rt = store.refresh_tokens[refresh_token]
            session = store.sessions[rt.session_id]
            user = store.users.get(session.user_id)

            if session.revoked:
                raise _fail(
                    ErrorCode.SESSION_REVOKED,
                    f"session_id={session.session_id} 已撤销: {session.revoke_reason}",
                    status_code=401,
                )
            if rt.revoked:
                raise _fail(
                    ErrorCode.REFRESH_TOKEN_REVOKED,
                    f"refresh_jti={rt.jti} 已被撤销，不得使用",
                    status_code=401,
                )
            if now >= rt.expires_at or now >= session.absolute_expires_at:
                raise _fail(
                    ErrorCode.REFRESH_EXPIRED,
                    f"refresh_jti={rt.jti} 已过期",
                    status_code=401,
                )
            if user is None or not user.enabled:
                _revoke_session_locked(store, session, "account_disabled")
                raise _fail(
                    ErrorCode.ACCOUNT_DISABLED,
                    f"user_id={session.user_id} 已禁用，会话即时失效",
                    status_code=403,
                )

            # 单次使用：该令牌已被轮换过。
            if rt.consumed_at is not None:
                within_window = (
                    now - rt.consumed_at
                    <= settings.concurrent_refresh_window_seconds
                )
                successor = (
                    store.refresh_tokens.get(rt.replaced_by)
                    if rt.replaced_by
                    else None
                )
                if within_window and successor is not None and not successor.revoked:
                    # 并发竞态：旧令牌在窗口内重复出现。输家不得得到新凭据。
                    raise _fail(
                        ErrorCode.REFRESH_CONCURRENT,
                        (
                            f"refresh_jti={rt.jti} 在并发窗口内重复使用，"
                            f"已由赢家轮换为 {rt.replaced_by}"
                        ),
                        status_code=409,
                    )
                # 窗口外（或后继令牌也异常）：重放攻击，整族作废。
                _revoke_family_locked(
                    store, rt.family_id, "refresh_token_reuse_detected"
                )
                raise _fail(
                    ErrorCode.REFRESH_REUSE_DETECTED,
                    (
                        f"refresh_jti={rt.jti} 为已消费旧令牌，疑似重放，"
                        f"family_id={rt.family_id} 已整族撤销"
                    ),
                    status_code=401,
                )

            access, new_refresh_jti, _ = _issue_tokens_locked(
                store, settings, session, now, previous_refresh_jti=rt.jti
            )
            logger.info(
                "refresh rotated session_id=%s old_jti=%s new_jti=%s access_jti=%s",
                session.session_id, rt.jti, new_refresh_jti, access.jti,
            )
            return access, new_refresh_jti


# ---------------------------------------------------------------- 访问凭据校验

def verify_access_token(
    store: Store,
    settings: Settings,
    *,
    access_token: str,
    now: float,
) -> AccessTokenRecord:
    """即时校验访问凭据。

    除自身有效性外，还会比对身份源当前状态：
    账号禁用 / 会话撤销 / 角色版本落后 / 策略版本落后，一律拒绝，
    保证禁用、登出、角色调整、策略更新即时生效，绝不静默放行或静默沿用旧权。
    """
    with store.lock:
        record = store.access_tokens.get(access_token)
        if record is None:
            raise _fail(
                ErrorCode.ACCESS_TOKEN_INVALID,
                "访问凭据无法识别",
                status_code=401,
            )
        if now >= record.expires_at:
            raise _fail(
                ErrorCode.ACCESS_TOKEN_EXPIRED,
                f"access_jti={record.jti} 已过期",
                status_code=401,
            )
        # 先识别根因“账号禁用”（即便令牌同时被连带撤销），保证失败原因可区分。
        user = store.users.get(record.user_id)
        if user is None or not user.enabled:
            session = store.sessions.get(record.session_id)
            if session is not None and not session.revoked:
                _revoke_session_locked(store, session, "account_disabled")
            raise _fail(
                ErrorCode.ACCOUNT_DISABLED,
                f"user_id={record.user_id} 已禁用，凭据即时失效",
                status_code=403,
            )
        session = store.sessions.get(record.session_id)
        if session is None or session.revoked:
            raise _fail(
                ErrorCode.SESSION_REVOKED,
                f"凭据所属会话已撤销({session.revoke_reason if session else 'missing'})",
                status_code=401,
            )
        if record.revoked:
            raise _fail(
                ErrorCode.ACCESS_TOKEN_INVALID,
                f"access_jti={record.jti} 已被撤销",
                status_code=401,
            )
        if user.roles_version != record.roles_version:
            raise _fail(
                ErrorCode.ROLE_REVISION_STALE,
                (
                    f"access_jti={record.jti} 角色版本陈旧 "
                    f"(token={record.roles_version}, now={user.roles_version})，"
                    "请续期换取新凭据，不得沿用旧角色权限"
                ),
                status_code=401,
            )
        if store.policy_version != record.policy_version:
            raise _fail(
                ErrorCode.POLICY_REVISION_STALE,
                (
                    f"access_jti={record.jti} 策略版本陈旧 "
                    f"(token={record.policy_version}, now={store.policy_version})，"
                    "请续期后按新策略判定，避免静默降级/越权"
                ),
                status_code=401,
            )
        return record


# ---------------------------------------------------------------- 登出 / 管理操作

def logout(store: Store, *, access_token: str, now: float) -> None:
    """主动登出：会话与其全部未过期访问凭据即时失效。"""
    with store.lock:
        record = store.access_tokens.get(access_token)
        if record is None:
            raise _fail(
                ErrorCode.ACCESS_TOKEN_INVALID,
                "访问凭据无法识别，无法登出",
                status_code=401,
            )
        session = store.sessions.get(record.session_id)
        if session is None:
            raise _fail(
                ErrorCode.SESSION_NOT_FOUND,
                f"session_id={record.session_id} 不存在",
                status_code=401,
            )
        _revoke_session_locked(store, session, "user_logout")
        logger.info(
            "logout session_id=%s user_id=%s 会话与全部凭据即时撤销",
            session.session_id, record.user_id,
        )


def admin_set_user_enabled(
    store: Store, settings: Settings, *, username: str, enabled: bool
) -> None:
    """启用/禁用账号；禁用时该用户全部会话与未过期凭据即时失效。"""
    with store.lock:
        user_id = store.users_by_username.get(username)
        user = store.users.get(user_id) if user_id else None
        if user is None:
            raise DomainError(
                ErrorCode.USER_NOT_FOUND,
                f"username={username!r} 不存在",
                status_code=404,
            )
        user.enabled = enabled
        if not enabled:
            for sess in store.sessions.values():
                if sess.user_id == user.id and not sess.revoked:
                    _revoke_session_locked(store, sess, "account_disabled_by_admin")
        logger.info(
            "admin set_enabled username=%s enabled=%s (在途会话已即时失效)",
            username, enabled,
        )


def admin_set_user_roles(
    store: Store, settings: Settings, *, username: str, roles: list[str]
) -> None:
    """调整角色：角色版本递增，旧访问凭据立刻因版本陈旧被拒（即时生效）。"""
    with store.lock:
        user_id = store.users_by_username.get(username)
        user = store.users.get(user_id) if user_id else None
        if user is None:
            raise DomainError(
                ErrorCode.USER_NOT_FOUND,
                f"username={username!r} 不存在",
                status_code=404,
            )
        user.roles = list(roles)
        user.roles_version += 1
        logger.info(
            "admin set_roles username=%s roles=%s roles_version=%s (旧凭据即刻失效)",
            username, roles, user.roles_version,
        )
