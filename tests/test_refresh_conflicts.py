"""续期失败细分：并发撞车（可重试）vs 凭据复用（安全事件，会话永久作废）。

多轮 × 多线程压测撞车判定；用可控时钟精确越过冲突窗口制造复现场景。
"""
import threading
from collections import Counter

import pytest

from app.auth import AuthService, RefreshError, totp_code
from app.authz import AuthzService
from app.models import AuthzDecision
from tests.conftest import MFA_SECRET, FakeClock

THREADS = 16
ROUNDS = 10


def _run_concurrent_refresh(auth: AuthService, token: str) -> Counter:
    outcomes: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(THREADS)

    def worker():
        barrier.wait()
        try:
            pair = auth.refresh(token)
            outcome = ("success", pair)
        except RefreshError as exc:
            outcome = (exc.reason.value, None)
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    winners = [p for r, p in outcomes if r == "success"]
    return Counter(r for r, _ in outcomes), winners[0] if winners else None


def test_concurrent_refresh_conflict_is_retryable_multi_round(auth: AuthService):
    """多轮压测：每轮恰好 1 个赢家，其余全部为可重试撞车；会话始终存活可继续续期。"""
    pair = auth.login("alice", "pw", totp_code(MFA_SECRET))
    for rnd in range(ROUNDS):
        counts, winner = _run_concurrent_refresh(auth, pair["refresh_token"])
        print(f"round {rnd}: token=...{pair['refresh_token'][-8:]} -> {dict(counts)}")
        assert counts["success"] == 1, f"第 {rnd} 轮必须恰好一个赢家"
        assert counts["concurrent_conflict"] == THREADS - 1, (
            f"第 {rnd} 轮落败方必须全部判定为可重试撞车，不得误判为复用")
        assert "session_reused" not in counts
        pair = winner  # 撞车不杀伤会话：赢家签出的新凭据继续参与下一轮


def test_replay_after_conflict_window_is_reuse_and_kills_session(
    store, tokens, authz: AuthzService, fake_clock: FakeClock
):
    """越过冲突窗口的重放 -> 复用；一经判定，会话永久作废，任何凭据都签不出、用不了。"""
    auth = AuthService(store, tokens, clock=fake_clock)
    pair = auth.login("alice", "pw", totp_code(MFA_SECRET))
    old_refresh = pair["refresh_token"]
    pair2 = auth.refresh(old_refresh)  # t=1000：旧 jti 被消费，pair2 为当前有效凭据

    fake_clock.advance(10.0)  # 越过 2s 冲突窗口，模拟事后重放
    with pytest.raises(RefreshError) as exc_info:
        auth.refresh(old_refresh)
    print(f"replay after window -> {exc_info.value.reason.value}")
    assert exc_info.value.reason.value == "session_reused"

    # 会话已被复用判定永久作废：当前仍有效的 refresh token 也签不出新凭据
    with pytest.raises(RefreshError) as exc_info2:
        auth.refresh(pair2["refresh_token"])
    print(f"current refresh token after reuse detected -> {exc_info2.value.reason.value}")
    assert exc_info2.value.reason.value == "session_revoked"

    # 该会话签出的访问凭据同样立即失效：绝不出现两个都还能用的会话
    decision = authz.authorize(pair2["access_token"], "document:read", "doc-plain")
    print(f"access token of killed session -> {decision.value}")
    assert decision == AuthzDecision.UNAUTHENTICATED


def test_reuse_of_unknown_jti_kills_session(store, tokens, fake_clock: FakeClock):
    """来路不明（合法签名但从未登记）的 jti 同样按复用处理并作废会话。"""
    auth = AuthService(store, tokens, clock=fake_clock)
    pair = auth.login("alice", "pw", totp_code(MFA_SECRET))
    session_id = tokens.parse_refresh_token(pair["refresh_token"])[0]
    forged = tokens.issue_refresh_token(session_id, "never-issued-jti", 3600)

    with pytest.raises(RefreshError) as exc_info:
        auth.refresh(forged)
    print(f"unknown jti -> {exc_info.value.reason.value}")
    assert exc_info.value.reason.value == "session_reused"

    with pytest.raises(RefreshError) as exc_info2:
        auth.refresh(pair["refresh_token"])
    assert exc_info2.value.reason.value == "session_revoked"


def test_conflict_within_window_does_not_kill_session(
    store, tokens, fake_clock: FakeClock
):
    """窗口内的重复提交只算撞车：会话不受伤，新凭据照常可用。"""
    auth = AuthService(store, tokens, clock=fake_clock)
    pair = auth.login("alice", "pw", totp_code(MFA_SECRET))
    old_refresh = pair["refresh_token"]
    pair2 = auth.refresh(old_refresh)

    fake_clock.advance(1.0)  # 仍在 2s 冲突窗口内
    with pytest.raises(RefreshError) as exc_info:
        auth.refresh(old_refresh)
    print(f"re-submit within window -> {exc_info.value.reason.value}")
    assert exc_info.value.reason.value == "concurrent_conflict"

    pair3 = auth.refresh(pair2["refresh_token"])  # 会话存活，继续轮换
    assert pair3["refresh_token"] != pair2["refresh_token"]
