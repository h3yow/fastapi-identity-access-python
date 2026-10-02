"""线程安全的本地存储：模拟身份源、凭据、会话与审计日志。"""
from __future__ import annotations

import threading

from app.models import AuthzDecision, Resource, Role, Session, User


class Store:
    """进程内存储，所有复合操作在单把锁下完成以保证并发一致性。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.users: dict[str, User] = {}
        self.roles: dict[str, Role] = {}
        self.sessions: dict[str, Session] = {}
        self.resources: dict[str, Resource] = {}
        self.audit_log: list[dict] = []
        # 已消费的 refresh token jti -> 消费时间戳（用于区分并发撞车与重放复用）
        self.used_refresh_ids: dict[str, float] = {}
        # 幂等授权：caller 作用域 + request_id -> 首次判定结论（重试不再重复记账）
        self.completed_authz: dict[str, AuthzDecision] = {}

    @property
    def lock(self) -> threading.RLock:
        return self._lock
