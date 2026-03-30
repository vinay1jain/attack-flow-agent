"""FastAPI application factory and entrypoint for the Attack Flow Agent."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.middleware.auth import HMACAuthMiddleware
from .api.middleware.tenant import TenantMiddleware
from .api.middleware.rate_limit import RateLimitMiddleware
from .api.router import api_router, health_router
from .config import get_settings
from .core.errors import AttackFlowError

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    logger.info(
        "agent.starting",
        host=settings.host,
        port=settings.port,
        llm_model=settings.llm.model,
    )
    yield
    logger.info("agent.shutting_down")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="Attack Flow Agent",
        description="AI-powered attack flow generation from threat intelligence reports",
        version="1.0.0",
        lifespan=lifespan,
    )

    # ── Middleware (order matters: outermost first) ───────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(TenantMiddleware)
    app.add_middleware(HMACAuthMiddleware)

    # ── Routers ──────────────────────────────────────────────────────
    app.include_router(api_router)
    app.include_router(health_router)

    # ── Exception handlers ───────────────────────────────────────────
    @app.exception_handler(AttackFlowError)
    async def attack_flow_error_handler(request: Request, exc: AttackFlowError) -> JSONResponse:
        status_map = {
            "REPORT_NOT_FOUND": 404,
            "JOB_NOT_FOUND": 404,
            "TLP_RESTRICTED": 403,
            "AUTH_FAILED": 401,
            "RATE_LIMITED": 429,
            "REPORT_CONTENT_INSUFFICIENT": 422,
        }
        status_code = status_map.get(exc.code.value, 500)
        return JSONResponse(status_code=status_code, content=exc.to_dict())

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
        log_level=settings.log_level.lower(),
    )
