import pytest

from app.audit import AuditLog
from app.auth import AuthService, hash_password, totp_code
from app.authz import AuthzService
from app.models import Resource, Role, User
from app.store import Store
from app.tokens import TokenService

MFA_SECRET = "alice-mfa-secret"


class FakeClock:
    """可控时钟：驱动续期的撞车窗口判定，测试可精确越过窗口制造复现场景。"""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture()
def fake_clock() -> FakeClock:
    return FakeClock()


@pytest.fixture()
def store() -> Store:
    s = Store()
    s.roles["reader"] = Role("reader", frozenset({"document:read"}))
    s.roles["editor"] = Role("editor", frozenset({"document:read", "document:write"}))
    s.roles["conf-reader"] = Role(
        "conf-reader", frozenset({"document:read", "document:read:confidential"})
    )
    s.users["u1"] = User("u1", "alice", hash_password("pw", "u1"), MFA_SECRET,
                         roles={"reader"})
    s.resources["doc-plain"] = Resource("doc-plain", owner_id="u9", attributes=frozenset())
    s.resources["doc-conf"] = Resource("doc-conf", owner_id="u9",
                                       attributes=frozenset({"confidential"}))
    return s


@pytest.fixture()
def tokens() -> TokenService:
    return TokenService(secret="test-secret")


@pytest.fixture()
def auth(store: Store, tokens: TokenService) -> AuthService:
    return AuthService(store, tokens)


@pytest.fixture()
def authz(store: Store, tokens: TokenService) -> AuthzService:
    return AuthzService(store, tokens, AuditLog(store))


@pytest.fixture()
def logged_in(auth: AuthService) -> dict:
    return auth.login("alice", "pw", totp_code(MFA_SECRET))
