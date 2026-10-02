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

    # 旧 refresh token 在宽限窗口内再次提交：可重试的并发冲突（409）
    r = client.post("/refresh", json={"refresh_token": pair["refresh_token"]})
    print(f"re-submit old refresh -> {r.status_code} {r.json()}")
    assert r.status_code == 409 and r.json()["detail"] == "refresh_conflict"


def test_api_role_permission_change_and_idempotency():
    """HTTP 链路：角色权限集合变更使旧凭据失效；request_id 重复投递只记一次账。"""
    client.post("/admin/users/u-alice/roles", json=["reader"])
    r = client.post("/login", json={
        "username": "alice", "password": "alice-pw",
        "mfa_code": totp_code("alice-mfa-secret"),
    })
    pair = r.json()

    # 同一 request_id 重复投递：结论一致
    body = {"access_token": pair["access_token"], "permission": "document:read",
            "resource_id": "doc-public", "request_id": "api-req-1"}
    r1 = client.post("/authorize", json=body).json()["decision"]
    r2 = client.post("/authorize", json=body).json()["decision"]
    print(f"same request_id twice -> {r1}, {r2}")
    assert r1 == r2 == "allowed"
    entries = [e for e in client.get("/audit").json()
               if e.get("request_id") == "api-req-1"]
    print(f"audit entries for api-req-1: {len(entries)}")
    assert len(entries) == 1, "重复投递只记一次账"

    # 收窄 reader 角色的权限集合（用户角色未变）：旧凭据立即失效
    client.post("/admin/roles/reader/permissions", json=[])
    r = client.post("/authorize", json={
        "access_token": pair["access_token"], "permission": "document:read",
        "resource_id": "doc-public",
    })
    print(f"old token after role perms narrowed -> {r.json()}")
    assert r.json()["decision"] == "unauthenticated"

    # 续期后按新权限集合判定
    pair2 = client.post("/refresh", json={"refresh_token": pair["refresh_token"]}).json()
    r = client.post("/authorize", json={
        "access_token": pair2["access_token"], "permission": "document:read",
        "resource_id": "doc-public",
    })
    print(f"refreshed token -> {r.json()}")
    assert r.json()["decision"] == "forbidden"

    # 恢复演示数据，避免影响其他用例
    client.post("/admin/roles/reader/permissions", json=["document:read"])
