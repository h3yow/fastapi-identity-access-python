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


def test_refresh_rotation_single_use(auth: AuthService, logged_in: dict):
    pair2 = auth.refresh(logged_in["refresh_token"])
    assert pair2["refresh_token"] != logged_in["refresh_token"]
    # 旧 refresh token 在冲突窗口内被重复提交 -> 可重试的并发撞车
    with pytest.raises(RefreshError) as exc_info:
        auth.refresh(logged_in["refresh_token"])
    print(f"immediate re-submit of consumed refresh_token -> {exc_info.value.reason.value}")
    assert exc_info.value.reason.value == "concurrent_conflict"
    # 撞车不杀伤会话：新 token 仍可用
    auth.refresh(pair2["refresh_token"])


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
