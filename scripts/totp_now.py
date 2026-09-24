#!/usr/bin/env python3
"""打印当前时间的演示 TOTP 验证码（种子账号共享密钥）。"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.security import totp_code  # noqa: E402
from app.services.seed import SEED_MFA_SECRET  # noqa: E402


def main() -> None:
    secret = sys.argv[1] if len(sys.argv) > 1 else SEED_MFA_SECRET
    print(totp_code(secret, time.time()))


if __name__ == "__main__":
    main()
