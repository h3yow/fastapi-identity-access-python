"""本地内存存储。

一把全局 RLock 保护字典结构与版本号；另为每个会话维护一把互斥锁，
使“刷新令牌轮换”天然串行化：并发续期请求在同一把锁上排队，
由状态机决定谁赢，绝不产生两个同时有效的会话。
"""

from __future__ import annotations

import threading

from app.models import Decision
from app.models import MfaChallenge
from app.models import Policy
from app.models import RefreshToken
from app.models import Resource
from app.models import Session
from app.models import User
from app.models import AccessTokenRecord


class Store:
    """进程内身份源 / 凭据 / 会话 / 资源 / 审计存储。"""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.users: dict[str, User] = {}
        self.users_by_username: dict[str, str] = {}
        self.policies: dict[str, Policy] = {}
        self.policy_version: int = 0
        self.resources: dict[str, Resource] = {}
        self.sessions: dict[str, Session] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}
        self.access_tokens: dict[str, AccessTokenRecord] = {}
        self.mfa_challenges: dict[str, MfaChallenge] = {}
        # 审计以 request_id 幂等：同一逻辑请求只记一次结论、只计一次费。
        self.decisions_by_request: dict[str, Decision] = {}
        self.bill_counters: dict[str, int] = {}
        self.session_locks: dict[str, threading.Lock] = {}

    def session_lock(self, session_id: str) -> threading.Lock:
        with self.lock:
            lock = self.session_locks.get(session_id)
            if lock is None:
                lock = threading.Lock()
                self.session_locks[session_id] = lock
            return lock
