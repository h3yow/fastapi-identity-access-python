"""授权判定 / 即时生效 / 幂等记账测试。"""

from __future__ import annotations

import threading

import pytest

from app.errors import DomainError, ErrorCode
from app.services import authz
from app.services import authentication as auth
from tests.conftest import login


def decide(store, settings, clock, token, resource, action="read", rid="req"):
    return authz.decide(
        store, settings,
        request_id=rid, access_token=token,
        action=action, resource_id=resource, now=clock(),
    )


def test_four_distinguishable_outcomes(store, settings, clock):
    # 未认证
    d = decide(store, settings, clock, None, "doc-alice-1", rid="r-none")
    assert not d.allowed and d.reason.startswith("unauthenticated")

    access, _rt = login(store, settings, clock, "bob", "bob-pw")
    # 已认证且授权：bob(member) 可读 alice 的普通 doc
    d = decide(store, settings, clock, access.jti, "doc-alice-1", rid="r-allow")
    assert d.allowed and d.billed and d.reason.startswith("allow")

    # 已认证但未授权：member 对 secret 资源命中显式 deny
    d = decide(store, settings, clock, access.jti, "doc-alice-secret", rid="r-deny")
    assert not d.allowed and not d.billed and d.reason.startswith("forbidden")

    # 资源不存在
    d = decide(store, settings, clock, access.jti, "nope", rid="r-404")
    assert not d.allowed and d.reason.startswith("resource_not_found")


def test_owner_and_role_rules(store, settings, clock):
    access_alice, _ = login(store, settings, clock, "alice", "alice-pw")
    # owner 策略让属主可读自己的 secret，但 member 的显式 deny 优先 => 仍拒绝
    d = decide(store, settings, clock, access_alice.jti, "doc-alice-secret", rid="own")
    assert not d.allowed and "显式拒绝" in d.reason
    # admin 角色通配允许
    access_admin, _ = login(store, settings, clock, "admin", "admin-pw")
    d = decide(store, settings, clock, access_admin.jti, "doc-alice-secret", rid="adm")
    assert d.allowed


def test_disabled_account_invalidates_access_immediately(store, settings, clock):
    access, _rt = login(store, settings, clock, "alice", "alice-pw")
    assert decide(store, settings, clock, access.jti, "doc-alice-1", rid="before").allowed

    auth.admin_set_user_enabled(
        store, settings, username="alice", enabled=False
    )
    # 访问凭据尚未过期，但必须立即失效
    d = decide(store, settings, clock, access.jti, "doc-alice-1", rid="after")
    assert not d.allowed and d.reason == "unauthenticated:account_disabled"


def test_logout_invalidates_access_immediately(store, settings, clock):
    access, rt = login(store, settings, clock, "alice", "alice-pw")
    auth.logout(store, access_token=access.jti, now=clock())
    d = decide(store, settings, clock, access.jti, "doc-alice-1", rid="lo")
    assert not d.allowed and d.reason.startswith("unauthenticated")
    # 会话撤销后刷新也失败
    with pytest.raises(DomainError) as ei:
        auth.rotate_refresh_token(store, settings, refresh_token=rt, now=clock())
    assert ei.value.code is ErrorCode.SESSION_REVOKED


def test_role_change_takes_effect_and_requires_refresh(store, settings, clock):
    # bob 当前是 member，可读普通 doc
    access, rt = login(store, settings, clock, "bob", "bob-pw")
    assert decide(store, settings, clock, access.jti, "doc-bob-1", rid="r1").allowed

    # 管理员提升 bob 为 admin；旧凭据因角色版本陈旧立即不能继续判定
    auth.admin_set_user_roles(store, settings, username="bob", roles=["admin"])
    d = decide(store, settings, clock, access.jti, "doc-bob-1", rid="r2")
    assert not d.allowed and d.reason == "unauthenticated:role_revision_stale"

    # 续期拿到携带新角色版本的新凭据后按新角色判定（可访问 secret）
    new_access, _new_rt = auth.rotate_refresh_token(
        store, settings, refresh_token=rt, now=clock()
    )
    d = decide(store, settings, clock, new_access.jti, "doc-alice-secret", rid="r3")
    assert d.allowed


def test_policy_update_invalidates_stale_tokens_no_silent_downgrade(store, settings, clock):
    access, _rt = login(store, settings, clock, "bob", "bob-pw")
    assert decide(store, settings, clock, access.jti, "doc-bob-1", rid="p1").allowed

    # 策略发生任何变更 => 旧凭据策略版本陈旧，拒绝并要求续期（不静默放行）
    from app.models import PrincipalType
    from app.services import admin as admin_service
    admin_service.upsert_policy(
        store, policy_id="p-temp",
        principal_type=PrincipalType.ROLE, principal="member",
        action="write", effect_allow=True,
    )
    d = decide(store, settings, clock, access.jti, "doc-bob-1", rid="p2")
    assert not d.allowed and d.reason == "unauthenticated:policy_revision_stale"

    # 续期后按新策略快照重新判定
    new_access, _ = auth.rotate_refresh_token(
        store, settings, refresh_token=_rt, now=clock()
    )
    d = decide(store, settings, clock, new_access.jti, "doc-bob-1", rid="p3")
    assert d.allowed


def test_idempotent_decision_concurrent_single_billing(store, settings, clock):
    access, _rt = login(store, settings, clock, "bob", "bob-pw")
    outcomes: list = []

    def worker():
        d = decide(
            store, settings, clock, access.jti, "doc-bob-1",
            rid="same-request-id",
        )
        outcomes.append((d.allowed, d.billed))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 所有并发请求看到完全一致的结论
    assert set(outcomes) == {(True, True)}
    # 同一 request_id 只记账一次
    assert store.bill_counters["doc-bob-1"] == 1
    assert len(store.decisions_by_request) == 1
