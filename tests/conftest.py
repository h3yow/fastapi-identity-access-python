import pytest

from app.audit import AuditLog
from app.auth import AuthService, hash_password, totp_code
from app.authz import AuthzService
from app.models import Resource, Role, User
from app.store import Store
from app.tokens import TokenService

MFA_SECRET = "alice-mfa-secret"


class FakeClock:
    """可手动推进的时钟，用于确定性地测试撞车宽限窗口。"""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture()
def clock() -> FakeClock:
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
def auth(store: Store, tokens: TokenService, clock: FakeClock) -> AuthService:
    return AuthService(store, tokens, rotation_leeway=2.0, clock=clock)


@pytest.fixture()
def authz(store: Store, tokens: TokenService) -> AuthzService:
    return AuthzService(store, tokens, AuditLog(store))


@pytest.fixture()
def logged_in(auth: AuthService) -> dict:
    return auth.login("alice", "pw", totp_code(MFA_SECRET))
