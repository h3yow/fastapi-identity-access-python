"""FastAPI 入口：组装本地身份与访问控制服务，并预置演示数据。"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.audit import AuditLog
from app.auth import AuthService, LoginError, RefreshError, hash_password
from app.authz import AuthzService
from app.models import RefreshFailureReason, Resource, Role, User
from app.store import Store
from app.tokens import TokenService

store = Store()
tokens = TokenService(secret="local-dev-secret")
auth = AuthService(store, tokens)
authz = AuthzService(store, tokens, AuditLog(store))

# 预置身份源与资源（本地模拟）
store.roles["reader"] = Role("reader", frozenset({"document:read"}))
store.roles["editor"] = Role("editor", frozenset({"document:read", "document:write"}))
store.roles["confidential-reader"] = Role(
    "confidential-reader", frozenset({"document:read", "document:read:confidential"})
)
store.users["u-alice"] = User("u-alice", "alice", hash_password("alice-pw", "u-alice"),
                              "alice-mfa-secret", roles={"reader"})
store.users["u-bob"] = User("u-bob", "bob", hash_password("bob-pw", "u-bob"),
                            "bob-mfa-secret", roles={"editor"})
store.resources["doc-public"] = Resource("doc-public", owner_id="u-bob", attributes=frozenset())
store.resources["doc-secret"] = Resource("doc-secret", owner_id="u-bob",
                                         attributes=frozenset({"confidential"}))

app = FastAPI(title="local-identity-access")


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: str


class RefreshRequest(BaseModel):
    refresh_token: str


class AuthorizeRequest(BaseModel):
    access_token: str | None = None
    permission: str
    resource_id: str


@app.post("/login")
def login(req: LoginRequest) -> dict:
    try:
        return auth.login(req.username, req.password, req.mfa_code)
    except LoginError as exc:
        raise HTTPException(status_code=401, detail=exc.reason.value) from exc


@app.post("/refresh")
def refresh(req: RefreshRequest) -> dict:
    try:
        return auth.refresh(req.refresh_token)
    except RefreshError as exc:
        # 并发撞车落败方：409 表示可安全重试；其余为 401。
        status = 409 if exc.reason is RefreshFailureReason.REFRESH_CONFLICT else 401
        raise HTTPException(status_code=status, detail=exc.reason.value) from exc


@app.post("/logout/{session_id}")
def logout(session_id: str) -> dict:
    auth.logout(session_id)
    return {"status": "logged_out"}


@app.post("/authorize")
def authorize(req: AuthorizeRequest) -> dict:
    return {"decision": authz.authorize(req.access_token, req.permission, req.resource_id).value}


@app.post("/admin/users/{user_id}/disable")
def disable_user(user_id: str) -> dict:
    auth.disable_user(user_id)
    return {"status": "disabled"}


@app.post("/admin/users/{user_id}/roles")
def set_roles(user_id: str, roles: list[str]) -> dict:
    auth.set_roles(user_id, set(roles))
    return {"status": "roles_updated"}


@app.post("/admin/roles/{role_name}/permissions")
def set_role_permissions(role_name: str, permissions: list[str]) -> dict:
    auth.set_role_permissions(role_name, set(permissions))
    return {"status": "role_permissions_updated"}


@app.get("/audit")
def audit() -> list[dict]:
    return list(store.audit_log)
