"""登录与续期：各类失败原因可区分，单次使用语义成立。"""
import pytest

from app.auth import AuthService, LoginError, RefreshError, totp_code
from tests.conftest import MFA_SECRET


def test_login_failure_reasons_are_distinguishable(auth: AuthService):
    cases = [
        ("nobody", "pw", "000000", "user_not_found"),
        ("alice", "wrong", "000000", "bad_password"),
        ("alice", "pw", "000000", "bad_mfa"),
    ]
    for username, password, mfa, expected in cases:
        with pytest.raises(LoginError) as exc_info:
            auth.login(username, password, mfa)
        print(f"login({username!r}, pw={password!r}, mfa={mfa!r}) -> {exc_info.value.reason.value}")
        assert exc_info.value.reason.value == expected


def test_login_disabled_account(auth: AuthService):
    auth.disable_user("u1")
    with pytest.raises(LoginError) as exc_info:
        auth.login("alice", "pw", totp_code(MFA_SECRET))
    print(f"disabled login -> {exc_info.value.reason.value}")
    assert exc_info.value.reason.value == "account_disabled"


def test_refresh_rotation_single_use(auth: AuthService, logged_in: dict, clock):
    pair2 = auth.refresh(logged_in["refresh_token"])
    assert pair2["refresh_token"] != logged_in["refresh_token"]
    # 旧 refresh token 在宽限窗口内再次出现 -> 可重试的并发冲突
    with pytest.raises(RefreshError) as exc_info:
        auth.refresh(logged_in["refresh_token"])
    print(f"immediate re-submit old refresh_token -> {exc_info.value.reason.value}")
    assert exc_info.value.reason.value == "refresh_conflict"
    # 新 token 可用
    pair3 = auth.refresh(pair2["refresh_token"])
    # 宽限窗口之外重放已消费的凭据 -> 判定为复用（安全事件），会话被终止
    clock.advance(10.0)
    with pytest.raises(RefreshError) as exc_info2:
        auth.refresh(pair2["refresh_token"])
    print(f"replay consumed token after leeway -> {exc_info2.value.reason.value}")
    assert exc_info2.value.reason.value == "session_reused"
    # 复用判定后这条会话不能再签出任何新凭据
    with pytest.raises(RefreshError) as exc_info3:
        auth.refresh(pair3["refresh_token"])
    print(f"current token after reuse detected -> {exc_info3.value.reason.value}")
    assert exc_info3.value.reason.value == "session_revoked"


def test_refresh_failures_distinguishable(auth: AuthService, logged_in: dict, tokens):
    with pytest.raises(RefreshError) as e1:
        auth.refresh("not-a-token")
    with pytest.raises(RefreshError) as e2:
        auth.refresh(tokens.issue_refresh_token("ghost-session", "j", 60))
    auth.logout(tokens.parse_refresh_token(logged_in["refresh_token"])[0])
    with pytest.raises(RefreshError) as e3:
        auth.refresh(logged_in["refresh_token"])
    reasons = [e1.value.reason.value, e2.value.reason.value, e3.value.reason.value]
    print(f"malformed/unknown/revoked -> {reasons}")
    assert reasons == ["token_malformed", "session_not_found", "session_revoked"]


def test_disable_user_revokes_sessions_and_blocks_refresh(auth: AuthService, logged_in: dict):
    auth.disable_user("u1")
    with pytest.raises(RefreshError) as exc_info:
        auth.refresh(logged_in["refresh_token"])
    print(f"refresh after disable -> {exc_info.value.reason.value}")
    assert exc_info.value.reason.value == "session_revoked"
