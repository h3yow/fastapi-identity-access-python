"""登录 / MFA / 会话轮换链路测试。"""

from __future__ import annotations

import pytest

from app.errors import DomainError, ErrorCode
from app.services import authentication as auth
from tests.conftest import login


def expect(code: ErrorCode):
    return pytest.raises(DomainError, match=code.value)


def test_login_mfa_success_and_wrong_password(store, settings, clock):
    access, refresh = login(store, settings, clock, "alice", "alice-pw")
    assert access.user_id == "user-alice"
    assert refresh

    with pytest.raises(DomainError) as ei:
        auth.begin_login(store, settings, username="alice", password="bad", now=clock())
    assert ei.value.code is ErrorCode.INVALID_CREDENTIALS

    with pytest.raises(DomainError) as ei:
        auth.begin_login(store, settings, username="ghost", password="x", now=clock())
    assert ei.value.code is ErrorCode.INVALID_CREDENTIALS  # 不泄露用户存在性


def test_mfa_wrong_code_and_one_time_challenge(store, settings, clock):
    ch = auth.begin_login(
        store, settings, username="bob", password="bob-pw", now=clock()
    )
    with pytest.raises(DomainError) as ei:
        auth.complete_login(
            store, settings, challenge_id=ch.challenge_id, mfa_code="000000", now=clock()
        )
    assert ei.value.code is ErrorCode.MFA_INVALID

    # 过期挑战
    clock.advance(settings.mfa_challenge_ttl_seconds + 1)
    code = "000000"
    with pytest.raises(DomainError) as ei:
        auth.complete_login(
            store, settings, challenge_id=ch.challenge_id, mfa_code=code, now=clock()
        )
    assert ei.value.code is ErrorCode.MFA_CHALLENGE_EXPIRED

    # 全新挑战成功后不可再用
    clock.t = 1_000_000.0
    ch2 = auth.begin_login(
        store, settings, username="bob", password="bob-pw", now=clock()
    )
    from app.security import totp_code
    good = totp_code(
        store.users[ch2.user_id].mfa_secret, clock(),
        step=settings.mfa_time_step_seconds, digits=settings.mfa_digits,
    )
    auth.complete_login(
        store, settings, challenge_id=ch2.challenge_id, mfa_code=good, now=clock()
    )
    with pytest.raises(DomainError) as ei:
        auth.complete_login(
            store, settings, challenge_id=ch2.challenge_id, mfa_code=good, now=clock()
        )
    assert ei.value.code is ErrorCode.MFA_INVALID


def test_refresh_rotation_single_use(store, settings, clock):
    access1, rt1 = login(store, settings, clock, "alice", "alice-pw")
    access2, rt2 = auth.rotate_refresh_token(
        store, settings, refresh_token=rt1, now=clock()
    )
    assert rt2 != rt1
    assert access2.jti != access1.jti

    # 旧令牌在并发窗口外重用 => 重放攻击，整族撤销
    clock.advance(settings.concurrent_refresh_window_seconds + 1)
    with pytest.raises(DomainError) as ei:
        auth.rotate_refresh_token(store, settings, refresh_token=rt1, now=clock())
    assert ei.value.code is ErrorCode.REFRESH_REUSE_DETECTED

    # 整族作废：连新令牌也被连带撤销
    with pytest.raises(DomainError) as ei:
        auth.rotate_refresh_token(store, settings, refresh_token=rt2, now=clock())
    assert ei.value.code in (
        ErrorCode.REFRESH_TOKEN_REVOKED,
        ErrorCode.SESSION_REVOKED,
    )


def test_refresh_concurrent_window_only_one_winner(store, settings, clock):
    _access, rt1 = login(store, settings, clock, "alice", "alice-pw")
    access2, rt2 = auth.rotate_refresh_token(
        store, settings, refresh_token=rt1, now=clock()
    )
    # 仍在并发窗口内立即重放旧令牌 => 并发竞态（区别于重放攻击）
    with pytest.raises(DomainError) as ei:
        auth.rotate_refresh_token(store, settings, refresh_token=rt1, now=clock())
    assert ei.value.code is ErrorCode.REFRESH_CONCURRENT
    # 赢家的新令牌仍然有效（没有产生两个会话，也没误杀赢家）
    access3, rt3 = auth.rotate_refresh_token(
        store, settings, refresh_token=rt2, now=clock()
    )
    assert access3.session_id == access2.session_id


def test_concurrent_refresh_threads_exactly_one_winner(store, settings, clock):
    import threading

    _access, rt1 = login(store, settings, clock, "alice", "alice-pw")
    results: list = []
    errors: list = []

    def worker():
        try:
            _a, new_rt = auth.rotate_refresh_token(
                store, settings, refresh_token=rt1, now=clock()
            )
            results.append(new_rt)
        except DomainError as e:
            errors.append(e.code)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 1, f"应只有一个赢家, 实际 {len(results)}"
    assert all(c is ErrorCode.REFRESH_CONCURRENT for c in errors), errors
    # 仅存在一个活动会话
    active_sessions = [s for s in store.sessions.values() if not s.revoked]
    assert len(active_sessions) == 1


def test_refresh_revoked_and_expired_distinguishable(store, settings, clock):
    access, rt = login(store, settings, clock, "alice", "alice-pw")
    # 主动登出后刷新令牌被撤销
    auth.logout(store, access_token=access.jti, now=clock())
    with pytest.raises(DomainError) as ei:
        auth.rotate_refresh_token(store, settings, refresh_token=rt, now=clock())
    assert ei.value.code is ErrorCode.SESSION_REVOKED

    # 全新会话，刷新令牌过期
    clock.t += 10
    access2, rt2 = login(store, settings, clock, "bob", "bob-pw")
    clock.advance(settings.refresh_token_ttl_seconds + 1)
    with pytest.raises(DomainError) as ei:
        auth.rotate_refresh_token(store, settings, refresh_token=rt2, now=clock())
    assert ei.value.code is ErrorCode.REFRESH_EXPIRED
