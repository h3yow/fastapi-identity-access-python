"""角色权限集合变更：判定依据跟随角色权限版本，而非仅跟随用户角色分配。"""
from app.auth import AuthService
from app.authz import AuthzService
from app.models import AuthzDecision


def test_permission_narrowed_invalidates_issued_token(
    auth: AuthService, authz: AuthzService, logged_in: dict
):
    """收窄：角色被拿掉一项权限后，旧凭据不得继续按老规矩放行。"""
    at = logged_in["access_token"]
    assert authz.authorize(at, "document:read", "doc-plain") == AuthzDecision.ALLOWED
    # 用户角色未动，仅收窄 reader 角色的权限集合（清空）
    auth.set_role_permissions("reader", set())
    decision = authz.authorize(at, "document:read", "doc-plain")
    audit = authz._store.audit_log[-1]
    print(f"narrow role perms, old token -> {decision.value} (reason={audit.get('reason')})")
    assert decision == AuthzDecision.UNAUTHENTICATED
    assert audit["reason"] == "stale_policy_version"


def test_permission_widened_not_silently_granted(
    auth: AuthService, authz: AuthzService, logged_in: dict
):
    """放开：角色新增权限后，旧凭据不得静默获得新权限，续期后才生效。"""
    at = logged_in["access_token"]
    assert authz.authorize(at, "document:write", "doc-plain") == AuthzDecision.FORBIDDEN
    auth.set_role_permissions("reader", {"document:read", "document:write"})
    decision = authz.authorize(at, "document:write", "doc-plain")
    print(f"widen role perms, old token -> {decision.value}")
    assert decision == AuthzDecision.UNAUTHENTICATED, "不得静默放行新权限"
    # 续期后拿到新判定依据，新权限生效
    pair = auth.refresh(logged_in["refresh_token"])
    decision2 = authz.authorize(pair["access_token"], "document:write", "doc-plain")
    print(f"after refresh -> {decision2.value}")
    assert decision2 == AuthzDecision.ALLOWED


def test_refresh_after_narrowing_applies_new_set(
    auth: AuthService, authz: AuthzService, logged_in: dict
):
    """收窄后续期：新凭据按新权限集合判定，已移除的权限变为 forbidden。"""
    auth.set_role_permissions("reader", set())
    pair = auth.refresh(logged_in["refresh_token"])
    decision = authz.authorize(pair["access_token"], "document:read", "doc-plain")
    print(f"refreshed token after narrowing -> {decision.value}")
    assert decision == AuthzDecision.FORBIDDEN


def test_unrelated_role_change_does_not_invalidate(
    auth: AuthService, authz: AuthzService, logged_in: dict
):
    """用户未持有的角色变更不影响其凭据？——本实现采用全局策略版本，
    任何角色权限变更都会使旧凭据失效（保守失效，续期即恢复）。"""
    at = logged_in["access_token"]
    auth.set_role_permissions("editor", {"document:read", "document:write", "document:delete"})
    decision = authz.authorize(at, "document:read", "doc-plain")
    print(f"unrelated role changed, old token -> {decision.value}")
    assert decision == AuthzDecision.UNAUTHENTICATED
    pair = auth.refresh(logged_in["refresh_token"])
    assert authz.authorize(pair["access_token"], "document:read", "doc-plain") \
        == AuthzDecision.ALLOWED
