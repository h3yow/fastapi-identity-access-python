"""HTTP 端到端：登录 -> 授权 -> 角色调整 -> 旧凭据失效 -> 续期恢复。"""
from fastapi.testclient import TestClient

from app.auth import totp_code
from app.main import app

client = TestClient(app)


def test_end_to_end_flow():
    r = client.post("/login", json={
        "username": "alice", "password": "alice-pw",
        "mfa_code": totp_code("alice-mfa-secret"),
    })
    assert r.status_code == 200, r.text
    pair = r.json()

    r = client.post("/authorize", json={
        "access_token": pair["access_token"],
        "permission": "document:read", "resource_id": "doc-public",
    })
    print(f"alice read doc-public -> {r.json()}")
    assert r.json()["decision"] == "allowed"

    r = client.post("/authorize", json={
        "access_token": pair["access_token"],
        "permission": "document:read", "resource_id": "doc-secret",
    })
    print(f"alice read confidential doc-secret -> {r.json()}")
    assert r.json()["decision"] == "forbidden"

    # 提权后旧凭据立即失效，续期后获得新权限
    client.post("/admin/users/u-alice/roles", json=["confidential-reader"])
    r = client.post("/authorize", json={
        "access_token": pair["access_token"],
        "permission": "document:read", "resource_id": "doc-secret",
    })
    assert r.json()["decision"] == "unauthenticated"

    r = client.post("/refresh", json={"refresh_token": pair["refresh_token"]})
    assert r.status_code == 200
    pair2 = r.json()
    r = client.post("/authorize", json={
        "access_token": pair2["access_token"],
        "permission": "document:read", "resource_id": "doc-secret",
    })
    print(f"after refresh, alice read doc-secret -> {r.json()}")
    assert r.json()["decision"] == "allowed"

    # 旧 refresh token 在冲突窗口内被重复提交 -> 409 可重试撞车
    r = client.post("/refresh", json={"refresh_token": pair["refresh_token"]})
    print(f"immediate re-submit of consumed refresh -> {r.status_code} {r.json()}")
    assert r.status_code == 409 and r.json()["detail"] == "concurrent_conflict"


def test_role_permission_change_over_http():
    """改角色本身的权限集合：旧凭据立即失效，续期后按新权限集合判定。"""
    # 共享应用状态：先确保 alice 持有且仅持有 reader 角色
    client.post("/admin/users/u-alice/roles", json=["reader"])
    r = client.post("/login", json={
        "username": "alice", "password": "alice-pw",
        "mfa_code": totp_code("alice-mfa-secret"),
    })
    pair = r.json()

    # 放开 reader 的权限：允许读 confidential 资源
    r = client.post("/admin/roles/reader/permissions",
                    json=["document:read", "document:read:confidential"])
    assert r.status_code == 200
    r = client.post("/authorize", json={
        "access_token": pair["access_token"],
        "permission": "document:read", "resource_id": "doc-secret",
    })
    print(f"old token after role-permission widening -> {r.json()}")
    assert r.json()["decision"] == "unauthenticated", "旧凭据不得静默获得新放开的权限"

    r = client.post("/refresh", json={"refresh_token": pair["refresh_token"]})
    pair2 = r.json()
    r = client.post("/authorize", json={
        "access_token": pair2["access_token"],
        "permission": "document:read", "resource_id": "doc-secret",
    })
    print(f"refreshed token after widening -> {r.json()}")
    assert r.json()["decision"] == "allowed"

    # 收窄回去：续期后的凭据同样立即失效
    client.post("/admin/roles/reader/permissions", json=["document:read"])
    r = client.post("/authorize", json={
        "access_token": pair2["access_token"],
        "permission": "document:read", "resource_id": "doc-secret",
    })
    print(f"token after role-permission narrowing -> {r.json()}")
    assert r.json()["decision"] == "unauthenticated"

    r = client.post("/admin/roles/no-such-role/permissions", json=["document:read"])
    assert r.status_code == 404


def test_authorize_idempotent_over_http():
    r = client.post("/login", json={
        "username": "alice", "password": "alice-pw",
        "mfa_code": totp_code("alice-mfa-secret"),
    })
    at = r.json()["access_token"]
    body = {"access_token": at, "permission": "document:read",
            "resource_id": "doc-public", "request_id": "http-req-1"}
    before = len(client.get("/audit").json())
    decisions = [client.post("/authorize", json=body).json()["decision"]
                 for _ in range(4)]
    entries = [e for e in client.get("/audit").json()[before:]
               if e.get("request_id") == "http-req-1"]
    print(f"4 duplicate deliveries over HTTP -> {decisions}, audit entries={len(entries)}")
    assert decisions == ["allowed"] * 4
    assert len(entries) == 1, "同一请求重复投递只记一次账"
