"""本地演示种子数据。

账号（口令 + TOTP 均为演示用途）：
    admin / admin-pw   角色 admin
    alice / alice-pw   角色 member，资源 owner
    bob   / bob-pw     角色 member
所有账号共享同一个演示 TOTP 密钥，可用 scripts 中的辅助命令生成当前验证码。
"""

from __future__ import annotations

import logging

from app.models import PrincipalType, User
from app.security import hash_password
from app.services import admin as admin_service
from app.settings import Settings
from app.storage import Store

logger = logging.getLogger("iac.seed")

SEED_MFA_SECRET = "JBSWY3DPEHPK3PXP"  # 演示用固定 TOTP 密钥（base32）

DEMO_ACCOUNTS = {
    "admin": ("admin-pw", ["admin"]),
    "alice": ("alice-pw", ["member"]),
    "bob": ("bob-pw", ["member"]),
}


def seed(store: Store, settings: Settings) -> dict[str, str]:
    # 用户
    for username, (password, roles) in DEMO_ACCOUNTS.items():
        user = User(
            id=f"user-{username}",
            username=username,
            password_hash=hash_password(password),
            roles=list(roles),
            enabled=True,
            mfa_secret=SEED_MFA_SECRET,
        )
        store.users[user.id] = user
        store.users_by_username[username] = user.id

    # 资源：alice 拥有一个普通对象与一个机密对象；bob 拥有一个普通对象
    admin_service.create_resource(
        store, resource_id="doc-alice-1", owner="user-alice", tags=frozenset({"doc"})
    )
    admin_service.create_resource(
        store, resource_id="doc-alice-secret",
        owner="user-alice", tags=frozenset({"doc", "secret"}),
    )
    admin_service.create_resource(
        store, resource_id="doc-bob-1", owner="user-bob", tags=frozenset({"doc"})
    )

    # 策略（角色 + 资源属性）
    # owner 可读自己任意资源
    admin_service.upsert_policy(
        store, policy_id="p-owner-read",
        principal_type=PrincipalType.OWNER, principal="*",
        action="read", resource_owner="*", effect_allow=True,
    )
    admin_service.upsert_policy(
        store, policy_id="p-admin-all",
        principal_type=PrincipalType.ROLE, principal="admin",
        action="*", resource_owner="*", effect_allow=True,
    )
    admin_service.upsert_policy(
        store, policy_id="p-member-read-doc",
        principal_type=PrincipalType.ROLE, principal="member",
        action="read", resource_owner="*", resource_tags=frozenset({"doc"}),
        effect_allow=True,
    )
    admin_service.upsert_policy(
        store, policy_id="p-deny-secret",
        principal_type=PrincipalType.ROLE, principal="member",
        action="read", resource_owner="*", resource_tags=frozenset({"secret"}),
        effect_allow=False,
    )

    logger.info("seed 完成: %d 用户, %d 资源, %d 策略",
                len(DEMO_ACCOUNTS), len(store.resources), len(store.policies))
    return {"mfa_secret": SEED_MFA_SECRET}
