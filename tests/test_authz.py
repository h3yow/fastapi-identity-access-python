"""授权判定：三种结果语义可区分；权限撤销即时生效；不得静默越权。"""
from app.auth import AuthService, totp_code
from app.authz import AuthzService
from app.models import AuthzDecision
from tests.conftest import MFA_SECRET


def test_three_outcomes_distinguishable(authz: AuthzService, logged_in: dict):
    at = logged_in["access_token"]
    cases = [
        (None, "document:read", "doc-plain", AuthzDecision.UNAUTHENTICATED),
        (at, "document:write", "doc-plain", AuthzDecision.FORBIDDEN),
        (at, "document:read", "no-such-doc", AuthzDecision.NOT_FOUND),
        (at, "document:read", "doc-plain", AuthzDecision.ALLOWED),
    ]
    for token, perm, rid, expected in cases:
        decision = authz.authorize(token, perm, rid)
        audit = authz._store.audit_log[-1]
        print(f"authorize(perm={perm!r}, resource={rid!r}) -> {decision.value}"
              f" (basis/reason: {audit.get('basis') or audit.get('reason')})")
        assert decision == expected


def test_resource_attributes_required(authz: AuthzService, logged_in: dict):
    at = logged_in["access_token"]
    decision = authz.authorize(at, "document:read", "doc-conf")
    audit = authz._store.audit_log[-1]
    print(f"reader vs confidential doc -> {decision.value}, missing={audit.get('missing')}")
    assert decision == AuthzDecision.FORBIDDEN
    assert audit["missing"] == ["document:read:confidential"]


def test_role_change_invalidates_old_token_immediately(
    auth: AuthService, authz: AuthzService, logged_in: dict
):
    at = logged_in["access_token"]
    assert authz.authorize(at, "document:read", "doc-plain") == AuthzDecision.ALLOWED
    auth.set_roles("u1", set())  # 撤销全部角色
    decision = authz.authorize(at, "document:read", "doc-plain")
    print(f"access with pre-revocation token -> {decision.value}")
    assert decision == AuthzDecision.UNAUTHENTICATED, "旧凭据不得继续获得旧权限"


def test_no_silent_privilege_change_on_policy_update(
    auth: AuthService, authz: AuthzService, logged_in: dict
):
    """角色被提权后，旧凭据不得静默获得新权限；必须续期后才生效。"""
    at = logged_in["access_token"]
    auth.set_roles("u1", {"editor"})
    decision = authz.authorize(at, "document:write", "doc-plain")
    print(f"old token after privilege grant -> {decision.value}")
    assert decision == AuthzDecision.UNAUTHENTICATED, "不得静默放行新权限"
    pair = auth.refresh(logged_in["refresh_token"])  # 续期刷新权限快照
    decision2 = authz.authorize(pair["access_token"], "document:write", "doc-plain")
    print(f"refreshed token -> {decision2.value}")
    assert decision2 == AuthzDecision.ALLOWED


def test_logout_invalidates_access_token(auth: AuthService, authz: AuthzService,
                                         logged_in: dict, tokens):
    at = logged_in["access_token"]
    session_id = tokens.parse_refresh_token(logged_in["refresh_token"])[0]
    auth.logout(session_id)
    decision = authz.authorize(at, "document:read", "doc-plain")
    print(f"access after logout -> {decision.value}")
    assert decision == AuthzDecision.UNAUTHENTICATED


def test_disable_invalidates_access_token(auth: AuthService, authz: AuthzService,
                                          logged_in: dict):
    at = logged_in["access_token"]
    auth.disable_user("u1")
    decision = authz.authorize(at, "document:read", "doc-plain")
    print(f"access after disable -> {decision.value}")
    assert decision == AuthzDecision.UNAUTHENTICATED


def test_audit_matches_decision_per_call(authz: AuthzService, logged_in: dict):
    at = logged_in["access_token"]
    before = len(authz._store.audit_log)
    expected = [
        authz.authorize(at, "document:read", "doc-plain"),
        authz.authorize(at, "document:write", "doc-plain"),
        authz.authorize(None, "document:read", "doc-plain"),
    ]
    entries = authz._store.audit_log[before:]
    print(f"decisions={[d.value for d in expected]}; audit={[e['decision'] for e in entries]}")
    assert [e["decision"] for e in entries] == [d.value for d in expected]
