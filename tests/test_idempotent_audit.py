"""幂等记账：同一请求（request_id）的重复投递返回一致结论，且账面上只记一次。"""
import threading
from collections import Counter

from app.auth import AuthService
from app.authz import AuthzService
from app.models import AuthzDecision

THREADS = 16
ROUNDS = 10


def _audits_for(store, request_id: str) -> list[dict]:
    return [e for e in store.audit_log if e.get("request_id") == request_id]


def test_sequential_retries_single_audit(authz: AuthzService, store, logged_in: dict):
    at = logged_in["access_token"]
    decisions = [authz.authorize(at, "document:read", "doc-plain", request_id="req-1")
                 for _ in range(5)]
    audits = _audits_for(store, "req-1")
    print(f"5 sequential retries of req-1 -> decisions={[d.value for d in decisions]},"
          f" audit entries={len(audits)}")
    assert decisions == [AuthzDecision.ALLOWED] * 5, "重试必须拿到一致结论"
    assert len(audits) == 1, "同一请求重试只记一次账"


def test_concurrent_duplicate_delivery_single_audit_multi_round(
    authz: AuthzService, store, logged_in: dict
):
    """多轮压测：每轮同一 request_id 并发投递 THREADS 次，结论一致且只记一次账。"""
    at = logged_in["access_token"]
    for rnd in range(ROUNDS):
        rid = f"req-concurrent-{rnd}"
        results: list[AuthzDecision] = []
        lock = threading.Lock()
        barrier = threading.Barrier(THREADS)

        def worker():
            barrier.wait()
            d = authz.authorize(at, "document:read", "doc-plain", request_id=rid)
            with lock:
                results.append(d)

        threads = [threading.Thread(target=worker) for _ in range(THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        counts = Counter(results)
        audits = _audits_for(store, rid)
        print(f"round {rnd}: {rid} x{THREADS} concurrent -> {dict(counts)},"
              f" audit entries={len(audits)}")
        assert counts == {AuthzDecision.ALLOWED: THREADS}, "并发重复投递结论必须一致"
        assert len(audits) == 1, "不得因重复投递多记，也不得因去重少记"


def test_distinct_request_ids_each_recorded(authz: AuthzService, store, logged_in: dict):
    at = logged_in["access_token"]
    for i in range(3):
        authz.authorize(at, "document:read", "doc-plain", request_id=f"req-distinct-{i}")
    total = [e for e in store.audit_log if (e.get("request_id") or "").startswith("req-distinct-")]
    print(f"3 distinct request_ids -> audit entries={len(total)}")
    assert len(total) == 3, "不同请求必须各自记账，去重不得误伤"


def test_retry_returns_consistent_conclusion_across_policy_change(
    auth: AuthService, authz: AuthzService, store, logged_in: dict
):
    """首次判定后权限被收窄：同一请求的重试仍返回首次结论，且不重复记账。"""
    at = logged_in["access_token"]
    first = authz.authorize(at, "document:read", "doc-plain", request_id="req-stable")
    auth.set_role_permissions("reader", set())  # 权限收窄，凭据已失效
    retry = authz.authorize(at, "document:read", "doc-plain", request_id="req-stable")
    audits = _audits_for(store, "req-stable")
    print(f"first={first.value}, retry after policy change={retry.value},"
          f" audit entries={len(audits)}")
    assert first == AuthzDecision.ALLOWED
    assert retry == first, "同一请求的重试必须拿到一致的判定结论"
    assert len(audits) == 1


def test_deny_decisions_also_deduped(authz: AuthzService, store, logged_in: dict):
    at = logged_in["access_token"]
    decisions = [authz.authorize(at, "document:write", "doc-plain", request_id="req-deny")
                 for _ in range(4)]
    audits = _audits_for(store, "req-deny")
    print(f"4 retries of a forbidden request -> {[d.value for d in decisions]},"
          f" audit entries={len(audits)}")
    assert decisions == [AuthzDecision.FORBIDDEN] * 4
    assert len(audits) == 1


def test_dedup_key_isolated_per_caller(authz: AuthzService, store, tokens, logged_in: dict):
    """不同调用方使用相同 request_id 互不影响：各自判定、各自记账。"""
    from app.auth import hash_password, totp_code
    from app.models import User
    from tests.conftest import MFA_SECRET

    store.users["u2"] = User("u2", "carol", hash_password("pw2", "u2"), MFA_SECRET,
                             roles=set())  # 无任何权限
    auth = AuthService(store, tokens)
    pair_u2 = auth.login("carol", "pw2", totp_code(MFA_SECRET))

    d1 = authz.authorize(logged_in["access_token"], "document:read", "doc-plain",
                         request_id="req-shared")
    d2 = authz.authorize(pair_u2["access_token"], "document:read", "doc-plain",
                         request_id="req-shared")
    audits = _audits_for(store, "req-shared")
    print(f"alice req-shared -> {d1.value}; carol req-shared -> {d2.value};"
          f" audit entries={len(audits)}")
    assert d1 == AuthzDecision.ALLOWED and d2 == AuthzDecision.FORBIDDEN
    assert len(audits) == 2, "不同调用方的相同 request_id 必须各自记账"


def test_no_request_id_keeps_per_call_audit(authz: AuthzService, store, logged_in: dict):
    """兼容旧行为：不带 request_id 时每次判定都记账。"""
    at = logged_in["access_token"]
    for _ in range(3):
        authz.authorize(at, "document:read", "doc-plain")
    audits = [e for e in store.audit_log if e.get("request_id") is None]
    print(f"3 calls without request_id -> audit entries={len(audits)}")
    assert len(audits) == 3
