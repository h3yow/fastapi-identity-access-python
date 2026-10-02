"""角色权限集合变更：判定依据跟随角色权限变动，旧凭据既不保留旧权限也不静默获得新权限。"""
import pytest

from app.auth import AuthService
from app.authz import AuthzService
from app.models import AuthzDecision


def test_narrowing_role_permissions_blocks_old_token_immediately(
    auth: AuthService, authz: AuthzService, store, logged_in: dict
):
    """收窄：reader 被拿掉 document:read 后，旧凭据不得继续放行该权限。"""
    at = logged_in["access_token"]
    assert authz.authorize(at, "document:read", "doc-plain") == AuthzDecision.ALLOWED

    auth.set_role_permissions("reader", set())  # 用户角色未变，只改角色的权限集合
    decision = authz.authorize(at, "document:read", "doc-plain")
    audit = store.audit_log[-1]
    print(f"old token after role-permission narrowing -> {decision.value}"
          f" (reason={audit.get('reason')})")
    assert decision == AuthzDecision.UNAUTHENTICATED, "旧凭据不得继续放行已被拿掉的权限"
    assert audit["reason"] == "stale_token_version"

    # 续期后拿到更新后的判定依据：权限确实没了 -> forbidden 而非 allowed
    pair = auth.refresh(logged_in["refresh_token"])
    decision2 = authz.authorize(pair["access_token"], "document:read", "doc-plain")
    print(f"refreshed token after narrowing -> {decision2.value}")
    assert decision2 == AuthzDecision.FORBIDDEN


def test_widening_role_permissions_not_silent_for_old_token(
    auth: AuthService, authz: AuthzService, store, logged_in: dict
):
    """放开：reader 获得 document:write 后，旧凭据不得静默多出该权限，续期后才生效。"""
    at = logged_in["access_token"]
    auth.set_role_permissions("reader", {"document:read", "document:write"})

    decision = authz.authorize(at, "document:write", "doc-plain")
    audit = store.audit_log[-1]
    print(f"old token after role-permission widening -> {decision.value}"
          f" (reason={audit.get('reason')})")
    assert decision == AuthzDecision.UNAUTHENTICATED, "旧凭据不得静默获得新放开的权限"

    pair = auth.refresh(logged_in["refresh_token"])
    decision2 = authz.authorize(pair["access_token"], "document:write", "doc-plain")
    print(f"refreshed token after widening -> {decision2.value}")
    assert decision2 == AuthzDecision.ALLOWED


def test_role_permission_change_only_affects_holders(
    auth: AuthService, authz: AuthzService, store, tokens, logged_in: dict
):
    """未持有该角色的用户：凭据不受角色权限变更影响。"""
    from app.auth import hash_password, totp_code
    from app.models import User
    from tests.conftest import MFA_SECRET

    store.users["u2"] = User("u2", "carol", hash_password("pw2", "u2"), MFA_SECRET,
                             roles={"conf-reader"})
    pair_u2 = auth.login("carol", "pw2", totp_code(MFA_SECRET))

    auth.set_role_permissions("reader", set())  # 只影响 reader 持有者 u1

    decision_u2 = authz.authorize(pair_u2["access_token"], "document:read", "doc-conf")
    decision_u1 = authz.authorize(logged_in["access_token"], "document:read", "doc-plain")
    print(f"non-holder u2 -> {decision_u2.value}; holder u1 -> {decision_u1.value}")
    assert decision_u2 == AuthzDecision.ALLOWED, "未持有该角色的用户不受影响"
    assert decision_u1 == AuthzDecision.UNAUTHENTICATED


def test_unknown_role_rejected(auth: AuthService):
    with pytest.raises(KeyError):
        auth.set_role_permissions("no-such-role", {"document:read"})
