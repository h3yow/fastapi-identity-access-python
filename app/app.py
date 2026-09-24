"""FastAPI 应用装配。"""

from __future__ import annotations

import logging
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api import routes_admin, routes_auth, routes_resources
from app.errors import DomainError
from app.services.seed import seed
from app.settings import get_settings
from app.storage import Store

logger = logging.getLogger("iac")


class AppState:
    """进程内共享状态：单一 Store + 可替换时钟（测试可注入虚拟时间）。"""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.store = Store()
        self.time_fn = time.time
        seed(self.store, self.settings)


def create_app() -> FastAPI:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    app = FastAPI(title="本地身份与访问控制服务", version="0.1.0")
    app.state.iac = AppState()

    @app.exception_handler(DomainError)
    async def domain_error_handler(_: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

    @app.get("/health")
    def health() -> dict[str, bool]:
        return {"ok": True}

    app.include_router(routes_auth.router)
    app.include_router(routes_resources.router)
    app.include_router(routes_admin.router)
    return app
