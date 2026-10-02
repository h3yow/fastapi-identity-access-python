"""授权服务：基于角色与资源属性的判定，结果与审计原子落账。

规则：
- 未携带凭据、凭据无效/过期/版本过期（权限已变更）或会话已撤销 → UNAUTHENTICATED
- 目标资源不存在 → NOT_FOUND（仅对已认证者返回，避免向未认证者泄露资源存在性）
- 资源属主隐式拥有该资源的一切权限
- 普通资源需要 permission；带属性（如 confidential）的资源需要 permission:attribute
- 角色含 "*" 视为通配，授予一切权限
判定与审计写入在同一把 store 锁内完成：并发下不会出现部分授权或重复记账。

幂等：调用方可携带 request_id（幂等键）。同一 request_id 的重复投递——无论
串行重试还是并发同时到达——都返回首次判定的结论，且账面上只记一次；
request_id 不得换参数复用（否则抛 ValueError）。不带 request_id 时保持
原有语义：每次调用独立判定、独立记账。
"""
from __future__ import annotations

from app.audit import AuditLog
from app.models import AuthzDecision
from app.store import Store
from app.tokens import TokenError, TokenService


class AuthzService:
    def __init__(self, store: Store, tokens: TokenService, audit: AuditLog) -> None:
        self._store = store
        self._tokens = tokens
        self._audit = audit

    def authorize(self, access_token: str | None, permission: str, resource_id: str,
                  request_id: str | None = None) -> AuthzDecision:
        store = self._store
        with store.lock:
            if request_id is not None:
                cached = store.authz_results.get(request_id)
                if cached is not None:
                    # 同一请求的重复投递：直接返回首次判定结论，不再记账。
                    if cached["fingerprint"] != (access_token, permission, resource_id):
                        raise ValueError(
                            f"request_id {request_id!r} 已被不同参数的请求占用")
                    return cached["decision"]
            decision = self._evaluate(access_token, permission, resource_id, request_id)
            if request_id is not None:
                store.authz_results[request_id] = {
                    "decision": decision,
                    "fingerprint": (access_token, permission, resource_id),
                }
            return decision

    def _evaluate(self, access_token: str | None, permission: str, resource_id: str,
                  request_id: str | None = None) -> AuthzDecision:
        """实际判定；调用方须已持有 store.lock。"""
        store = self._store
        # 1. 认证
        if access_token is None:
            return self._deny(AuthzDecision.UNAUTHENTICATED, permission, resource_id,
                              reason="no_token", request_id=request_id)
        try:
            claims = self._tokens.verify_access_token(access_token)
        except TokenError as exc:
            return self._deny(AuthzDecision.UNAUTHENTICATED, permission, resource_id,
                              reason=f"token_{exc.reason}", request_id=request_id)
        user = store.users.get(claims.user_id)
        session = store.sessions.get(claims.session_id)
        if user is None or user.disabled:
            return self._deny(AuthzDecision.UNAUTHENTICATED, permission, resource_id,
                              user_id=claims.user_id, reason="account_disabled",
                              request_id=request_id)
        if session is None or session.revoked:
            return self._deny(AuthzDecision.UNAUTHENTICATED, permission, resource_id,
                              user_id=user.user_id, reason="session_revoked",
                              request_id=request_id)
        if claims.token_version != user.token_version:
            # 权限/角色已变更：旧凭据立即失效，绝不静默放行旧权限。
            return self._deny(AuthzDecision.UNAUTHENTICATED, permission, resource_id,
                              user_id=user.user_id, reason="stale_token_version",
                              request_id=request_id)
        if claims.policy_version != store.policy_version:
            # 角色权限集合已变更（用户角色未变）：旧凭据同样立即失效，
            # 收窄不放行旧权限、放开不静默给新权限，续期后才按新集合判定。
            return self._deny(AuthzDecision.UNAUTHENTICATED, permission, resource_id,
                              user_id=user.user_id, reason="stale_policy_version",
                              request_id=request_id)

        # 2. 资源存在性
        resource = store.resources.get(resource_id)
        if resource is None:
            return self._deny(AuthzDecision.NOT_FOUND, permission, resource_id,
                              user_id=user.user_id, reason="resource_not_found",
                              request_id=request_id)

        # 3. 授权判定
        granted = self._collect_permissions(user)
        if resource.owner_id == user.user_id:
            return self._allow(permission, resource_id, user.user_id, basis="owner",
                               request_id=request_id)
        if "*" in granted:
            return self._allow(permission, resource_id, user.user_id,
                               basis="wildcard_role", request_id=request_id)
        required = {permission} | {f"{permission}:{attr}" for attr in resource.attributes}
        missing = required - granted
        if missing:
            return self._deny(AuthzDecision.FORBIDDEN, permission, resource_id,
                              user_id=user.user_id, reason="missing_permission",
                              missing=sorted(missing), request_id=request_id)
        return self._allow(permission, resource_id, user.user_id,
                           basis=f"permissions:{sorted(required)}", request_id=request_id)

    def _collect_permissions(self, user) -> set[str]:
        perms: set[str] = set()
        for role_name in user.roles:
            role = self._store.roles.get(role_name)
            if role is not None:
                perms |= role.permissions
        return perms

    def _allow(self, permission: str, resource_id: str, user_id: str, basis: str,
               request_id: str | None = None) -> AuthzDecision:
        self._audit.record("authz", decision=AuthzDecision.ALLOWED.value,
                           permission=permission, resource_id=resource_id,
                           user_id=user_id, basis=basis, request_id=request_id)
        return AuthzDecision.ALLOWED

    def _deny(self, decision: AuthzDecision, permission: str, resource_id: str,
              request_id: str | None = None, **fields: object) -> AuthzDecision:
        self._audit.record("authz", decision=decision.value,
                           permission=permission, resource_id=resource_id,
                           request_id=request_id, **fields)
        return decision
