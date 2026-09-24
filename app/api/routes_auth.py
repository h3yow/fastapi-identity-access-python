"""认证相关 HTTP 路由。"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel

from app.api.deps import get_settings, get_store, now, serialize_tokens
from app.errors import DomainError, ErrorCode
from app.security import totp_code
from app.services import authentication as auth
from app.settings import Settings
from app.storage import Store

logger = logging.getLogger("iac.api.auth")

router = APIRouter(tags=["auth"])


class LoginBeginRequest(BaseModel):
    username: str
    password: str


class LoginCompleteRequest(BaseModel):
    challenge_id: str
    mfa_code: str


class RefreshRequest(BaseModel):
    refresh_token: str


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise DomainError(
            ErrorCode.UNAUTHENTICATED,
            "缺少 Authorization: Bearer <token>",
            status_code=401,
        )
    return authorization.removeprefix("Bearer ").strip()


@router.post("/auth/login/begin")
def login_begin(
    body: LoginBeginRequest,
    request: Request,
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
    now_ts: float = Depends(now),
) -> dict:
    challenge = auth.begin_login(
        store, settings, username=body.username, password=body.password, now=now_ts
    )
    # 本地演示便利：回显当前 TOTP（生产绝不应返回）。
    hint = totp_code(
        store.users[challenge.user_id].mfa_secret,
        now_ts,
        step=settings.mfa_time_step_seconds,
        digits=settings.mfa_digits,
    )
    return {"challenge_id": challenge.challenge_id, "mfa_required": True, "dev_totp_hint": hint}


@router.post("/auth/login/complete")
def login_complete(
    body: LoginCompleteRequest,
    request: Request,
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
    now_ts: float = Depends(now),
) -> dict:
    access, refresh_token = auth.complete_login(
        store,
        settings,
        challenge_id=body.challenge_id,
        mfa_code=body.mfa_code,
        now=now_ts,
    )
    return serialize_tokens(access, refresh_token, settings, now_ts)


@router.post("/auth/refresh")
def refresh(
    body: RefreshRequest,
    request: Request,
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
    now_ts: float = Depends(now),
) -> dict:
    access, refresh_token = auth.rotate_refresh_token(
        store, settings, refresh_token=body.refresh_token, now=now_ts
    )
    return serialize_tokens(access, refresh_token, settings, now_ts)


@router.post("/auth/logout")
def logout(
    request: Request,
    authorization: str | None = Header(default=None),
    store: Store = Depends(get_store),
    now_ts: float = Depends(now),
) -> dict:
    token = _bearer(authorization)
    auth.logout(store, access_token=token, now=now_ts)
    return {"logged_out": True}
