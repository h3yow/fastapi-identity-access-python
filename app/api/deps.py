"""HTTP 层共享辅助：状态访问、时钟与凭据序列化。"""

from __future__ import annotations

from fastapi import Request

from app.models import AccessTokenRecord
from app.settings import Settings
from app.storage import Store


def get_state(request: Request):
    return request.app.state.iac


def get_store(request: Request) -> Store:
    return get_state(request).store


def get_settings(request: Request) -> Settings:
    return get_state(request).settings


def now(request: Request) -> float:
    return get_state(request).time_fn()


def serialize_tokens(
    access: AccessTokenRecord, refresh_token: str, settings: Settings, now_ts: float
) -> dict:
    return {
        "access_token": access.jti,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "access_expires_in": max(0, int(access.expires_at - now_ts)),
        "refresh_expires_in": settings.refresh_token_ttl_seconds,
        "session_id": access.session_id,
    }
