"""本地可调参数。

默认时长偏短，便于本地直接观察过期、续期与撤销链路；
测试中可构造自定义 Settings 进一步压缩时间窗口。
"""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class Settings:
    access_token_ttl_seconds: float = 60.0
    refresh_token_ttl_seconds: float = 600.0
    mfa_challenge_ttl_seconds: float = 120.0
    session_absolute_ttl_seconds: float = 24 * 3600.0
    # 同一刷新令牌在轮换后的此时长窗口内再次出现，判定为并发竞态而非重放攻击。
    concurrent_refresh_window_seconds: float = 1.0
    mfa_time_step_seconds: int = 30
    mfa_digits: int = 6

    @staticmethod
    def default() -> "Settings":
        return Settings()


_SETTINGS = Settings.default()


def get_settings() -> Settings:
    return _SETTINGS
