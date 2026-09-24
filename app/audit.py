"""审计记账。

核心约束：
- 以 request_id 幂等：同一逻辑请求的重复判定（重试 / 并发）返回首次结论，
  绝不重复记账（billed 只在首次落账时为 True 且计数器只增一次）。
- 日志打印关键输入与判定依据，保证结论“可解释、可回放”。
"""

from __future__ import annotations

import logging

from app.models import Decision
from app.storage import Store

logger = logging.getLogger("iac.audit")


def record_decision(store: Store, decision: Decision) -> Decision:
    """幂等记录一次授权判定；返回该 request_id 下的权威结论。"""
    with store.lock:
        existing = store.decisions_by_request.get(decision.request_id)
        if existing is not None:
            logger.info(
                "audit idempotent-hit request_id=%s user=%s action=%s resource=%s "
                "allowed=%s reason=%s billed=False (首次结论已记账)",
                decision.request_id, decision.user_id, decision.action,
                decision.resource_id, existing.allowed, existing.reason,
            )
            return existing

        store.decisions_by_request[decision.request_id] = decision
        if decision.allowed:
            store.bill_counters[decision.resource_id] = (
                store.bill_counters.get(decision.resource_id, 0) + 1
            )
        billed = decision.billed
        logger.info(
            "audit record request_id=%s user=%s action=%s resource=%s "
            "allowed=%s reason=%s billed=%s",
            decision.request_id, decision.user_id, decision.action,
            decision.resource_id, decision.allowed, decision.reason, billed,
        )
        return decision
