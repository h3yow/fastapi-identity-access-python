"""线程安全的本地存储：模拟身份源、凭据、会话与审计日志。"""
from __future__ import annotations

import threading

from app.models import Resource, Role, Session, User


class Store:
    """进程内存储，所有复合操作在单把锁下完成以保证并发一致性。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.users: dict[str, User] = {}
        self.roles: dict[str, Role] = {}
        self.sessions: dict[str, Session] = {}
        self.resources: dict[str, Resource] = {}
        self.audit_log: list[dict] = []
        self.used_refresh_ids: set[str] = set()  # 已消费的 refresh token jti（重放检测）
        # 角色权限集合的全局版本：任何角色的权限被修改即递增，
        # 使按旧权限集合签发的访问凭据立即失效（无论收窄还是放开）。
        self.policy_version: int = 0

    @property
    def lock(self) -> threading.RLock:
        return self._lock
