"""授权服务：基于角色与资源属性的判定，结果与审计原子落账。

规则：
- 未携带凭据、凭据无效/过期/版本过期（权限已变更）或会话已撤销 → UNAUTHENTICATED
- 目标资源不存在 → NOT_FOUND（仅对已认证者返回，避免向未认证者泄露资源存在性）
- 资源属主隐式拥有该资源的一切权限
- 普通资源需要 permission；带属性（如 confidential）的资源需要 permission:attribute
- 角色含 "*" 视为通配，授予一切权限
判定与审计写入在同一把 store 锁内完成：并发下不会出现部分授权或重复记账。

幂等投递：调用方可携带 request_id（幂等键）。同一调用方对同一 request_id 的
重试（含并发同时到达）返回首次判定的结论，且账面上只记一次——不因重复投递多记，
也不因去重少记。dedup 键按调用方作用域（用户或 anonymous）隔离，避免不同
调用方撞键互相拿到对方的结论。
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
            cache_key = self._dedup_key(access_token, request_id)
            if cache_key is not None and cache_key in store.completed_authz:
                # 同一请求的重复投递：返回首次判定结论，不再重复记账。
                return store.completed_authz[cache_key]
            decision = self._evaluate(access_token, permission, resource_id, request_id)
            if cache_key is not None:
                store.completed_authz[cache_key] = decision
            return decision

    def _dedup_key(self, access_token: str | None, request_id: str | None) -> str | None:
        """dedup 键 = 调用方作用域 + request_id；未提供 request_id 时不去重。"""
        if request_id is None:
            return None
        scope = "anonymous"
        if access_token is not None:
            try:
                scope = self._tokens.verify_access_token(access_token).user_id
            except TokenError:
                pass
        return f"{scope}:{request_id}"

    def _evaluate(self, access_token: str | None, permission: str, resource_id: str,
                  request_id: str | None = None) -> AuthzDecision:
        store = self._store
        # 调用方须已持有 store.lock（由 authorize 进入），保证判定与记账原子。
        # 1. 认证
        if access_token is None:
            return self._deny(AuthzDecision.UNAUTHENTICATED, permission, resource_id,
                              request_id, reason="no_token")
        try:
            claims = self._tokens.verify_access_token(access_token)
        except TokenError as exc:
            return self._deny(AuthzDecision.UNAUTHENTICATED, permission, resource_id,
                              request_id, reason=f"token_{exc.reason}")
        user = store.users.get(claims.user_id)
        session = store.sessions.get(claims.session_id)
        if user is None or user.disabled:
            return self._deny(AuthzDecision.UNAUTHENTICATED, permission, resource_id,
                              request_id, user_id=claims.user_id, reason="account_disabled")
        if session is None or session.revoked:
            return self._deny(AuthzDecision.UNAUTHENTICATED, permission, resource_id,
                              request_id, user_id=user.user_id, reason="session_revoked")
        if claims.token_version != user.token_version:
            # 权限/角色已变更：旧凭据立即失效，绝不静默放行旧权限。
            return self._deny(AuthzDecision.UNAUTHENTICATED, permission, resource_id,
                              request_id, user_id=user.user_id, reason="stale_token_version")

        # 2. 资源存在性
        resource = store.resources.get(resource_id)
        if resource is None:
            return self._deny(AuthzDecision.NOT_FOUND, permission, resource_id,
                              request_id, user_id=user.user_id, reason="resource_not_found")

        # 3. 授权判定
        granted = self._collect_permissions(user)
        if resource.owner_id == user.user_id:
            return self._allow(permission, resource_id, user.user_id, request_id, basis="owner")
        if "*" in granted:
            return self._allow(permission, resource_id, user.user_id, request_id,
                               basis="wildcard_role")
        required = {permission} | {f"{permission}:{attr}" for attr in resource.attributes}
        missing = required - granted
        if missing:
            return self._deny(AuthzDecision.FORBIDDEN, permission, resource_id,
                              request_id, user_id=user.user_id, reason="missing_permission",
                              missing=sorted(missing))
        return self._allow(permission, resource_id, user.user_id, request_id,
                           basis=f"permissions:{sorted(required)}")

    def _collect_permissions(self, user) -> set[str]:
        perms: set[str] = set()
        for role_name in user.roles:
            role = self._store.roles.get(role_name)
            if role is not None:
                perms |= role.permissions
        return perms

    def _allow(self, permission: str, resource_id: str, user_id: str,
               request_id: str | None, basis: str) -> AuthzDecision:
        self._audit.record("authz", decision=AuthzDecision.ALLOWED.value,
                           permission=permission, resource_id=resource_id,
                           user_id=user_id, basis=basis, request_id=request_id)
        return AuthzDecision.ALLOWED

    def _deny(self, decision: AuthzDecision, permission: str, resource_id: str,
              request_id: str | None, **fields: object) -> AuthzDecision:
        self._audit.record("authz", decision=decision.value,
                           permission=permission, resource_id=resource_id,
                           request_id=request_id, **fields)
        return decision
