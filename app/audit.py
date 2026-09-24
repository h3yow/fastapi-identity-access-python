"""审计：判定与记账在 store 锁内原子完成，避免并发下部分授权或重复记账。"""
from __future__ import annotations

import time

from app.store import Store


class AuditLog:
    def __init__(self, store: Store) -> None:
        self._store = store

    def record(self, event: str, **fields: object) -> None:
        """调用方须已持有 store.lock，保证判定与记账原子。"""
        entry = {"event": event, "ts": time.time(), **fields}
        self._store.audit_log.append(entry)
