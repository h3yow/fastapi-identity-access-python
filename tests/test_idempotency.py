"""授权幂等：同一请求的重复投递结论一致、账面只记一次，不多记也不少记。"""
import threading
from collections import Counter

import pytest

from app.auth import AuthService
from app.authz import AuthzService
from app.models import AuthzDecision

THREADS = 16
ROUNDS = 10


def _audit_entries(store, request_id: str) -> list[dict]:
    return [e for e in store.audit_log if e.get("request_id") == request_id]


def test_sequential_retries_single_audit(authz: AuthzService, store, logged_in: dict):
    at = logged_in["access_token"]
    decisions = [authz.authorize(at, "document:read", "doc-plain", request_id="req-1")
                 for _ in range(5)]
    entries = _audit_entries(store, "req-1")
    print(f"5 sequential retries -> {[d.value for d in decisions]}, audit={len(entries)}")
    assert decisions == [AuthzDecision.ALLOWED] * 5, "重试结论必须一致"
    assert len(entries) == 1, "同一请求只记一次账"


def test_denied_decision_also_deduped(authz: AuthzService, store, logged_in: dict):
    at = logged_in["access_token"]
    decisions = [authz.authorize(at, "document:write", "doc-plain", request_id="req-deny")
                 for _ in range(3)]
    entries = _audit_entries(store, "req-deny")
    print(f"3 denied retries -> {[d.value for d in decisions]}, audit={len(entries)}")
    assert decisions == [AuthzDecision.FORBIDDEN] * 3
    assert len(entries) == 1


def test_concurrent_retries_single_audit_multi_round(authz: AuthzService, store,
                                                     logged_in: dict):
    """多轮压测：每轮 16 线程并发投递同一 request_id，结论一致且只记一次账。"""
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
        entries = _audit_entries(store, rid)
        print(f"round {rnd}: request_id={rid} -> {dict(counts)}, audit={len(entries)}")
        assert counts == {AuthzDecision.ALLOWED: THREADS}, "并发重试结论必须一致"
        assert len(entries) == 1, "并发重复投递不得多记，也不得因去重少记"


def test_distinct_request_ids_audited_separately(authz: AuthzService, store,
                                                 logged_in: dict):
    at = logged_in["access_token"]
    for i in range(3):
        authz.authorize(at, "document:read", "doc-plain", request_id=f"req-distinct-{i}")
    entries = [e for e in store.audit_log
               if (e.get("request_id") or "").startswith("req-distinct-")]
    print(f"3 distinct request_ids -> audit={len(entries)}")
    assert len(entries) == 3, "不同请求不得被去重而少记"


def test_request_id_reuse_with_different_params_rejected(authz: AuthzService,
                                                         logged_in: dict):
    at = logged_in["access_token"]
    authz.authorize(at, "document:read", "doc-plain", request_id="req-x")
    with pytest.raises(ValueError):
        authz.authorize(at, "document:write", "doc-plain", request_id="req-x")
    print("request_id reused with different params -> ValueError")


def test_retry_returns_cached_decision_despite_policy_change(
    auth: AuthService, authz: AuthzService, store, logged_in: dict
):
    """重试拿到的是首次判定的结论：即使中途权限被收窄，同一请求的结论不变。"""
    at = logged_in["access_token"]
    first = authz.authorize(at, "document:read", "doc-plain", request_id="req-stable")
    auth.set_role_permissions("reader", set())  # 收窄权限
    retry = authz.authorize(at, "document:read", "doc-plain", request_id="req-stable")
    entries = _audit_entries(store, "req-stable")
    print(f"first={first.value}, retry after narrowing={retry.value}, audit={len(entries)}")
    assert retry == first, "同一请求的重试必须拿到一致的判定结论"
    assert len(entries) == 1
    # 新请求（不同 request_id）则按最新状态判定
    fresh = authz.authorize(at, "document:read", "doc-plain", request_id="req-fresh")
    print(f"new request_id after narrowing -> {fresh.value}")
    assert fresh == AuthzDecision.UNAUTHENTICATED
