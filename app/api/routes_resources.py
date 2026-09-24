"""资源访问与授权判定 HTTP 路由。

对同一逻辑请求以客户端提供的 X-Request-Id（缺省服务端生成）幂等，
并发/重试保证“同一请求的判定结果与审计/计费严格一致、不重复记账”。
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse

from app.api.deps import get_settings, get_store, now
from app.errors import DomainError, ErrorCode
from app.models import Decision
from app.security import new_token
from app.services import authz
from app.settings import Settings
from app.storage import Store

logger = logging.getLogger("iac.api.resources")

router = APIRouter(tags=["resources"])


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    if not authorization.startswith("Bearer "):
        raise DomainError(
            ErrorCode.UNAUTHENTICATED,
            "Authorization 头格式应为 Bearer <token>",
            status_code=401,
        )
    return authorization.removeprefix("Bearer ").strip()


def _http_status(decision: Decision) -> int:
    if decision.allowed:
        return 200
    if decision.reason == "unauthenticated:account_disabled":
        return 403
    if decision.reason.startswith("unauthenticated:"):
        return 401
    if decision.reason.startswith("resource_not_found"):
        return 404
    return 403


@router.get("/resources/{resource_id}")
def read_resource(
    resource_id: str,
    request: Request,
    action: str = "read",
    authorization: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
    now_ts: float = Depends(now),
) -> JSONResponse:
    request_id = x_request_id or new_token()
    token = _bearer(authorization)
    decision = authz.decide(
        store,
        settings,
        request_id=request_id,
        access_token=token,
        action=action,
        resource_id=resource_id,
        now=now_ts,
    )
    status = _http_status(decision)
    body = {
        "request_id": request_id,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "billed": decision.billed,
    }
    logger.info(
        "GET resource=%s action=%s request_id=%s -> %s (%s)",
        resource_id, action, request_id, status, decision.reason,
    )
    return JSONResponse(status_code=status, content=body)
