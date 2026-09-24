"""并发链路：并发续期只有一个赢家；并发判定结果与审计一致、不重复记账。"""
import threading
from collections import Counter

from app.auth import AuthService, RefreshError
from app.authz import AuthzService
from app.models import AuthzDecision

THREADS = 16


def test_concurrent_refresh_exactly_one_winner(auth: AuthService, logged_in: dict):
    token = logged_in["refresh_token"]
    outcomes: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(THREADS)

    def worker(i: int):
        barrier.wait()  # 同时放行，最大化竞争
        try:
            auth.refresh(token)
            result = "success"
        except RefreshError as exc:
            result = exc.reason.value
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    counts = Counter(outcomes)
    print(f"concurrent refresh x{THREADS} on same token -> {dict(counts)}")
    assert counts["success"] == 1, "并发续期不得产生两个同时有效的会话"
    assert counts["session_reused"] == THREADS - 1


def test_concurrent_authorize_consistent_and_single_audit(
    authz: AuthzService, store, logged_in: dict
):
    token = logged_in["access_token"]
    results: list[AuthzDecision] = []
    lock = threading.Lock()
    barrier = threading.Barrier(THREADS)

    def worker():
        barrier.wait()
        decision = authz.authorize(token, "document:read", "doc-plain")
        with lock:
            results.append(decision)

    threads = [threading.Thread(target=worker) for _ in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    counts = Counter(results)
    audits = [e for e in store.audit_log if e["resource_id"] == "doc-plain"]
    print(f"concurrent authorize x{THREADS} -> {dict(counts)}; audit entries={len(audits)}")
    assert counts == {AuthzDecision.ALLOWED: THREADS}, "同一请求判定必须一致"
    assert len(audits) == THREADS, "每次判定恰好一条审计，不得重复或遗漏"
    assert len({id(e) for e in audits}) == THREADS


def test_concurrent_refresh_and_revoke(auth: AuthService, logged_in: dict, tokens):
    """登出与续期并发：要么续期成功一次，要么全部因撤销失败，绝不出现部分成功。"""
    token = logged_in["refresh_token"]
    session_id = tokens.parse_refresh_token(token)[0]
    outcomes: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(THREADS + 1)

    def refresher():
        barrier.wait()
        try:
            auth.refresh(token)
            result = "success"
        except RefreshError as exc:
            result = exc.reason.value
        with lock:
            outcomes.append(result)

    def revoker():
        barrier.wait()
        auth.logout(session_id)

    threads = [threading.Thread(target=refresher) for _ in range(THREADS)]
    threads.append(threading.Thread(target=revoker))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    counts = Counter(outcomes)
    print(f"refresh vs logout -> {dict(counts)}")
    assert counts["success"] <= 1, "撤销并发下最多一个续期成功"
    # 之后会话必然不可用
    try:
        auth.refresh(token)
        raise AssertionError("重放必须失败")
    except RefreshError as exc:
        assert exc.reason.value in ("session_reused", "session_revoked")
