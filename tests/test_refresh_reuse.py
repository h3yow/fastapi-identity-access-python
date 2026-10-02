"""续期失败原因细分：并发撞车（可重试）vs 凭据复用（安全事件，会话终止）。"""
import threading
from collections import Counter

import pytest

from app.auth import AuthService, RefreshError
from app.tokens import TokenService

THREADS = 8
ROUNDS = 10


def _hammer_refresh(auth: AuthService, token: str) -> list[str]:
    """多线程同时提交同一个 refresh token，返回各线程的结果。"""
    outcomes: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(THREADS)

    def worker():
        barrier.wait()
        try:
            auth.refresh(token)
            result = "success"
        except RefreshError as exc:
            result = exc.reason.value
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=worker) for _ in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return outcomes


def test_conflict_loser_can_retry_with_new_token(auth: AuthService, logged_in: dict):
    """撞车落败方拿到 refresh_conflict 后，用赢家签出的新凭据重试即可成功。"""
    old = logged_in["refresh_token"]
    pair = auth.refresh(old)  # 赢家完成轮换
    with pytest.raises(RefreshError) as exc_info:
        auth.refresh(old)  # 落败方在宽限窗口内到达
    print(f"loser re-submit -> {exc_info.value.reason.value}")
    assert exc_info.value.reason.value == "refresh_conflict"
    # 会话未被波及：持新凭据重试成功
    pair2 = auth.refresh(pair["refresh_token"])
    assert pair2["refresh_token"] != pair["refresh_token"]


def test_reuse_kills_session_and_blocks_any_new_credentials(
    auth: AuthService, logged_in: dict, clock
):
    """宽限窗口外重放已消费凭据 -> 复用判定，会话终止，当前有效凭据也签不出新凭据。"""
    pair = auth.refresh(logged_in["refresh_token"])
    clock.advance(10.0)  # 越过撞车宽限窗口
    with pytest.raises(RefreshError) as e1:
        auth.refresh(logged_in["refresh_token"])
    print(f"replayed consumed token -> {e1.value.reason.value}")
    assert e1.value.reason.value == "session_reused"
    # 复用判定后：这条会话不能再签出任何新凭据
    with pytest.raises(RefreshError) as e2:
        auth.refresh(pair["refresh_token"])
    print(f"legit current token after reuse -> {e2.value.reason.value}")
    assert e2.value.reason.value == "session_revoked"


def test_unknown_jti_treated_as_reuse_and_kills_session(
    auth: AuthService, logged_in: dict, tokens: TokenService
):
    """签名有效但从未签发过的 jti：按复用处理并终止会话。"""
    session_id = tokens.parse_refresh_token(logged_in["refresh_token"])[0]
    forged = tokens.issue_refresh_token(session_id, "never-issued-jti", 60)
    with pytest.raises(RefreshError) as exc_info:
        auth.refresh(forged)
    print(f"unknown jti -> {exc_info.value.reason.value}")
    assert exc_info.value.reason.value == "session_reused"
    with pytest.raises(RefreshError) as e2:
        auth.refresh(logged_in["refresh_token"])
    assert e2.value.reason.value == "session_revoked"


def test_concurrent_refresh_multiple_rounds(auth: AuthService, logged_in: dict):
    """多轮压测：每轮用上一轮赢家签出的凭据并发续期，每轮恰好一个赢家，
    落败方均为可重试冲突；全程会话保持可用，绝不出现两个都能用的会话。"""
    current = logged_in["refresh_token"]
    for rnd in range(ROUNDS):
        outcomes = _hammer_refresh(auth, current)
        counts = Counter(outcomes)
        print(f"round {rnd}: token=...{current[-8:]} -> {dict(counts)}")
        assert counts["success"] == 1, f"第 {rnd} 轮必须恰好一个赢家"
        assert counts["refresh_conflict"] == THREADS - 1, \
            f"第 {rnd} 轮落败方必须全部是可重试冲突"
        # 拿到本轮赢家签出的新凭据，进入下一轮
        current = _current_refresh_token(auth, current)
    # 多轮之后会话仍然可用
    auth.refresh(current)


def _current_refresh_token(auth: AuthService, old_token: str) -> str:
    """测试辅助：从 store 中重建当前有效 refresh token（等价于赢家客户端
    持有的新凭据）。"""
    store = auth._store
    session_id = auth._tokens.parse_refresh_token(old_token)[0]
    session = store.sessions[session_id]
    return auth._tokens.issue_refresh_token(
        session_id, session.current_refresh_id, 3600)


def test_replay_old_token_kills_session_no_two_live_sessions(
    auth: AuthService, logged_in: dict, clock
):
    """复用判定后不存在'两个都还能用'：旧链路与新链路全部失效。"""
    pair1 = auth.refresh(logged_in["refresh_token"])
    pair2 = auth.refresh(pair1["refresh_token"])
    clock.advance(10.0)
    # 重放最早已消费的凭据
    with pytest.raises(RefreshError) as exc_info:
        auth.refresh(logged_in["refresh_token"])
    assert exc_info.value.reason.value == "session_reused"
    # 链条上所有凭据（含最新的一对）都无法再续期
    for token in (logged_in["refresh_token"], pair1["refresh_token"],
                  pair2["refresh_token"]):
        with pytest.raises(RefreshError) as e:
            auth.refresh(token)
        print(f"post-kill refresh ...{token[-8:]} -> {e.value.reason.value}")
        assert e.value.reason.value in ("session_revoked", "session_reused")
