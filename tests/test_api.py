"""HTTP 端到端：登录、重放、越权、禁用、幂等记账。"""

from __future__ import annotations

import threading

from fastapi.testclient import TestClient

from app.app import create_app


def _client():
    return TestClient(create_app())


def _login(client: TestClient, username: str, password: str) -> dict:
    r = client.post("/auth/login/begin", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    data = r.json()
    r = client.post(
        "/auth/login/complete",
        json={"challenge_id": data["challenge_id"], "mfa_code": data["dev_totp_hint"]},
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_full_flow_and_error_codes():
    c = _client()
    bad = c.post("/auth/login/begin", json={"username": "alice", "password": "wrong"})
    assert bad.status_code == 401 and bad.json()["error"] == "invalid_credentials"

    tok = _login(c, "alice", "alice-pw")
    h = {"Authorization": f"Bearer {tok['access_token']}"}

    assert c.get("/resources/doc-alice-1", headers=h).status_code == 200
    denied = c.get("/resources/doc-alice-secret", headers=h)
    assert denied.status_code == 403  # 越权访问 secret 被显式拒绝
    assert c.get("/resources/does-not-exist", headers=h).status_code == 404
    assert c.get("/resources/doc-alice-1").status_code == 401  # 未认证


def test_refresh_replay_revokes_family():
    c = _client()
    tok = _login(c, "bob", "bob-pw")
    r1 = c.post("/auth/refresh", json={"refresh_token": tok["refresh_token"]})
    assert r1.status_code == 200
    new_rt = r1.json()["refresh_token"]

    # 重放旧令牌：超过并发窗口(默认 1.0s) => reuse_detected
    import time
    time.sleep(1.1)
    replay = c.post("/auth/refresh", json={"refresh_token": tok["refresh_token"]})
    assert replay.status_code == 401
    assert replay.json()["error"] == "refresh_reuse_detected"
    # 新令牌被连带作废
    r2 = c.post("/auth/refresh", json={"refresh_token": new_rt})
    assert r2.status_code == 401
    assert r2.json()["error"] in ("refresh_token_revoked", "session_revoked")


def test_disabled_user_access_token_rejected():
    c = _client()
    tok = _login(c, "alice", "alice-pw")
    h = {"Authorization": f"Bearer {tok['access_token']}"}
    assert c.get("/resources/doc-alice-1", headers=h).status_code == 200

    r = c.post("/admin/users/alice/enabled", json={"enabled": False})
    assert r.status_code == 200
    resp = c.get("/resources/doc-alice-1", headers=h)
    assert resp.status_code == 403
    assert resp.json()["reason"] == "unauthenticated:account_disabled"


def test_same_request_id_concurrent_billed_once():
    c = _client()
    tok = _login(c, "bob", "bob-pw")
    headers = {
        "Authorization": f"Bearer {tok['access_token']}",
        "X-Request-Id": "fixed-rid-123",
    }
    statuses: list[int] = []

    def worker():
        statuses.append(c.get("/resources/doc-bob-1", headers=headers).status_code)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert set(statuses) == {200}
    store = c.app.state.iac.store
    assert store.bill_counters["doc-bob-1"] == 1
    assert "fixed-rid-123" in store.decisions_by_request


def test_logout_then_token_useless():
    c = _client()
    tok = _login(c, "alice", "alice-pw")
    h = {"Authorization": f"Bearer {tok['access_token']}"}
    assert c.post("/auth/logout", headers=h).status_code == 200
    assert c.get("/resources/doc-alice-1", headers=h).status_code == 401
