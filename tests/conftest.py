"""测试夹具：隔离的内存 Store、可推进的虚拟时钟与登录辅助。"""

from __future__ import annotations

import logging

import pytest

from app.security import totp_code
from app.services import authentication as auth
from app.services.seed import seed
from app.settings import Settings
from app.storage import Store

logging.basicConfig(level=logging.INFO)


class Clock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def settings() -> Settings:
    # 压缩窗口，便于在单测里快速触发过期与并发判定。
    return Settings(
        access_token_ttl_seconds=60.0,
        refresh_token_ttl_seconds=300.0,
        mfa_challenge_ttl_seconds=120.0,
        session_absolute_ttl_seconds=3600.0,
        concurrent_refresh_window_seconds=0.5,
    )


@pytest.fixture
def store(settings: Settings) -> Store:
    s = Store()
    seed(s, settings)
    return s


@pytest.fixture
def clock() -> Clock:
    return Clock()


def login(store: Store, settings: Settings, clock: Clock, username: str, password: str):
    """完成两段式 MFA 登录，返回 (access_record, refresh_token)。"""
    challenge = auth.begin_login(
        store, settings, username=username, password=password, now=clock()
    )
    code = totp_code(
        store.users[challenge.user_id].mfa_secret,
        clock(),
        step=settings.mfa_time_step_seconds,
        digits=settings.mfa_digits,
    )
    return auth.complete_login(
        store, settings, challenge_id=challenge.challenge_id, mfa_code=code, now=clock()
    )
