"""管理端 HTTP 路由：账号启用/禁用与角色调整（本地演示无额外鉴权）。"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.api.deps import get_settings, get_store
from app.services import authentication as auth
from app.settings import Settings
from app.storage import Store

logger = logging.getLogger("iac.api.admin")

router = APIRouter(prefix="/admin", tags=["admin"])


class EnabledRequest(BaseModel):
    enabled: bool


class RolesRequest(BaseModel):
    roles: list[str]


@router.post("/users/{username}/enabled")
def set_enabled(
    username: str,
    body: EnabledRequest,
    request: Request,
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict:
    auth.admin_set_user_enabled(
        store, settings, username=username, enabled=body.enabled
    )
    return {"username": username, "enabled": body.enabled}


@router.post("/users/{username}/roles")
def set_roles(
    username: str,
    body: RolesRequest,
    request: Request,
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict:
    auth.admin_set_user_roles(store, settings, username=username, roles=body.roles)
    return {"username": username, "roles": body.roles}
