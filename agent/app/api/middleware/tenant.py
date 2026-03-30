"""Tenant context extraction middleware."""

from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response


class TenantMiddleware(BaseHTTPMiddleware):
    """Extract ``X-Tenant-Id`` header and attach it to request state.

    Skips enforcement for health and documentation endpoints.
    """

    SKIP_PATHS = {"/api/v1/health", "/health", "/docs", "/openapi.json", "/redoc"}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in self.SKIP_PATHS:
            return await call_next(request)

        tenant_id = request.headers.get("X-Tenant-Id", "")
        if not tenant_id:
            return JSONResponse(
                status_code=400,
                content={"error_code": "TENANT_REQUIRED", "message": "X-Tenant-Id header is required", "details": {}},
            )

        request.state.tenant_id = tenant_id
        return await call_next(request)
