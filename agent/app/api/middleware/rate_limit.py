"""Per-tenant rate limiting middleware."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from ...config import get_settings
from ...core.jobs import get_job_manager


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforce per-tenant generation rate limits.

    Only applies to the ``POST /api/v1/attack-flow/generate`` endpoint.
    """

    RATE_LIMITED_PATHS = {"/api/v1/attack-flow/generate"}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method != "POST" or request.url.path not in self.RATE_LIMITED_PATHS:
            return await call_next(request)

        tenant_id = getattr(request.state, "tenant_id", None)
        if not tenant_id:
            return await call_next(request)

        settings = get_settings()
        window = timedelta(seconds=settings.rate_limit.window_seconds)
        since = datetime.now(timezone.utc) - window

        job_mgr = get_job_manager()
        count = await job_mgr.get_tenant_job_count(tenant_id, since)

        if count >= settings.rate_limit.per_tenant:
            return JSONResponse(
                status_code=429,
                content={
                    "error_code": "RATE_LIMITED",
                    "message": (
                        f"Rate limit exceeded. Maximum {settings.rate_limit.per_tenant} "
                        f"generations per {settings.rate_limit.window_seconds}s for your tenant."
                    ),
                    "details": {},
                },
            )

        return await call_next(request)
