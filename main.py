"""兼容入口：`uvicorn main:app` 与 `uvicorn app.main:app` 等价。"""
from app.main import app

__all__ = ["app"]
