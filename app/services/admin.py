"""策略与资源的本地管理接口。

任何策略写操作都会让全局 policy_version 前进，
从而使签发于旧版本的访问凭据在判定时被识别为“策略版本陈旧”并拒绝。
"""

from __future__ import annotations

import logging

from app.models import Policy, PrincipalType, Resource
from app.storage import Store

logger = logging.getLogger("iac.admin")


def upsert_policy(
    store: Store,
    *,
    policy_id: str,
    principal_type: PrincipalType,
    principal: str,
    action: str,
    resource_owner: str = "*",
    resource_tags: frozenset[str] | None = None,
    effect_allow: bool = True,
) -> Policy:
    with store.lock:
        existing = store.policies.get(policy_id)
        version = existing.version + 1 if existing else 1
        policy = Policy(
            id=policy_id,
            principal_type=principal_type,
            principal=principal,
            action=action,
            resource_owner=resource_owner,
            resource_tags=resource_tags or frozenset(),
            effect_allow=effect_allow,
            version=version,
        )
        store.policies[policy_id] = policy
        store.policy_version += 1
        logger.info(
            "admin upsert_policy id=%s effect=%s version=%s global_policy_version=%s",
            policy_id, "allow" if effect_allow else "deny",
            version, store.policy_version,
        )
        return policy


def delete_policy(store: Store, *, policy_id: str) -> None:
    with store.lock:
        store.policies.pop(policy_id, None)
        store.policy_version += 1
        logger.info(
            "admin delete_policy id=%s global_policy_version=%s",
            policy_id, store.policy_version,
        )


def create_resource(
    store, *, resource_id: str, owner: str, tags: frozenset[str] | None = None
) -> Resource:
    with store.lock:
        resource = Resource(id=resource_id, owner=owner, tags=tags or frozenset())
        store.resources[resource_id] = resource
        logger.info("admin create_resource id=%s owner=%s tags=%s", resource_id, owner, sorted(tags or []))
        return resource


def delete_resource(store: Store, *, resource_id: str) -> None:
    """软删除：授权判定据此给出明确的 resource_not_found。"""
    with store.lock:
        resource = store.resources.get(resource_id)
        if resource is not None:
            resource.exists = False
            logger.info("admin delete_resource id=%s (soft-deleted)", resource_id)
