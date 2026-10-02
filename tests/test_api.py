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
