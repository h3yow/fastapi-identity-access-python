"""基于角色与资源属性的授权判定。

判定顺序（四种语义可区分的结论）：
    1. 未认证：无凭据 / 凭据无效 / 过期 / 已撤销 / 版本陈旧 -> unauthenticated:<具体原因>
    2. 资源不存在：资源 ID 不存在或已标记删除 -> resource_not_found
    3. 已认证未授权：无匹配策略或命中显式拒绝 -> forbidden:<依据>
    4. 允许：命中允许策略且无拒绝 -> allow:<依据>

策略模型：主体可为用户或角色；资源维度含 owner 与 tags 属性；
多策略命中时“显式拒绝优先（deny-overrides）”。
同一 request_id 的判定与记账幂等：并发/重试返回同一结论且只计一次费。
"""

from __future__ import annotations

import logging

from app.audit import record_decision
from app.errors import DomainError
from app.models import Decision, Policy, PrincipalType
from app.services import authentication
from app.settings import Settings
from app.storage import Store

logger = logging.getLogger("iac.authz")


def _policy_matches(
    policy: Policy,
    *,
    user_id: str,
    roles: tuple[str, ...],
    action: str,
    resource_owner: str,
    resource_tags: frozenset[str],
) -> bool:
    if policy.action != action and policy.action != "*":
        return False
    if policy.principal_type is PrincipalType.USER:
        if policy.principal != user_id and policy.principal != "*":
            return False
    elif policy.principal_type is PrincipalType.ROLE:
        if policy.principal not in roles and policy.principal != "*":
            return False
    else:  # PrincipalType.OWNER：主体即资源属主本人
        if user_id != resource_owner:
            return False
    if policy.resource_owner not in ("*", resource_owner):
        return False
    # 策略要求的标签必须是资源标签的子集（资源属性匹配）。
    if not policy.resource_tags <= resource_tags:
        return False
    return True


def _evaluate_locked(
    store: Store,
    *,
    user_id: str,
    roles: tuple[str, ...],
    action: str,
    resource_owner: str,
    resource_tags: frozenset[str],
) -> tuple[bool, str]:
    """调用方持有 store.lock，基于同一份策略快照判定，拒绝优先。"""
    matched: list[Policy] = []
    for policy in store.policies.values():
        if _policy_matches(
            policy,
            user_id=user_id,
            roles=roles,
            action=action,
            resource_owner=resource_owner,
            resource_tags=resource_tags,
        ):
            matched.append(policy)

    denies = [p for p in matched if not p.effect_allow]
    allows = [p for p in matched if p.effect_allow]
    basis = ", ".join(
        f"{p.id}:{'allow' if p.effect_allow else 'deny'}:v{p.version}" for p in matched
    ) or "无匹配策略"

    if denies:
        ids = ",".join(p.id for p in denies)
        return False, f"forbidden:显式拒绝策略命中 [{ids}]; 匹配集=[{basis}]"
    if allows:
        ids = ",".join(p.id for p in allows)
        return True, f"allow:允许策略命中 [{ids}]; 匹配集=[{basis}]"
    return False, f"forbidden:无任何允许策略; {basis}"


def decide(
    store: Store,
    settings: Settings,
    *,
    request_id: str,
    access_token: str | None,
    action: str,
    resource_id: str,
    now: float,
) -> Decision:
    # 幂等短路：同一逻辑请求在并发/重试下直接复用首次权威结论。
    with store.lock:
        existing = store.decisions_by_request.get(request_id)
    if existing is not None:
        logger.info(
            "decide idempotent request_id=%s -> 复用首次结论 allowed=%s reason=%s",
            request_id, existing.allowed, existing.reason,
        )
        return existing

    def finalize(
        *,
        allowed: bool,
        reason: str,
        user_id: str | None,
        billed: bool,
    ) -> Decision:
        decision = Decision(
            request_id=request_id,
            allowed=allowed,
            reason=reason,
            user_id=user_id,
            action=action,
            resource_id=resource_id,
            billed=billed,
        )
        logger.info(
            "decide request_id=%s input(user=%s,action=%s,resource=%s) => allowed=%s 依据=%s",
            request_id, user_id, action, resource_id, allowed, reason,
        )
        return record_decision(store, decision)

    # 1) 认证
    if not access_token:
        return finalize(
            allowed=False,
            reason="unauthenticated:缺少访问凭据",
            user_id=None,
            billed=False,
        )
    try:
        record = authentication.verify_access_token(
            store, settings, access_token=access_token, now=now
        )
    except DomainError as exc:
        return finalize(
            allowed=False,
            reason=f"unauthenticated:{exc.code.value}",
            user_id=None,
            billed=False,
        )

    # 2/3) 资源存在性 + 授权（同一把锁内取快照，保证并发下依据一致）
    with store.lock:
        resource = store.resources.get(resource_id)
        if resource is None or not resource.exists:
            return finalize(
                allowed=False,
                reason="resource_not_found:目标资源不存在或已删除",
                user_id=record.user_id,
                billed=False,
            )
        allowed, reason = _evaluate_locked(
            store,
            user_id=record.user_id,
            roles=record.roles,
            action=action,
            resource_owner=resource.owner,
            resource_tags=resource.tags,
        )
    return finalize(
        allowed=allowed, reason=reason, user_id=record.user_id, billed=allowed
    )
