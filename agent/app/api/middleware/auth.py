"""HMAC signature validation middleware for incoming requests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from ...config import get_settings


def _error_response(status: int, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error_code": "AUTH_FAILED", "message": detail, "details": {}},
    )


class HMACAuthMiddleware(BaseHTTPMiddleware):
    """Validate HMAC-SHA1 signatures on incoming API requests.

    Expects query parameters: ``AccessID``, ``Expires``, ``Signature``.
    Skips validation for the health endpoint.
    """

    SKIP_PATHS = {"/api/v1/health", "/health", "/docs", "/openapi.json", "/redoc"}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in self.SKIP_PATHS:
            return await call_next(request)

        settings = get_settings()
        if not settings.ctix.access_id:
            return await call_next(request)

        access_id = request.query_params.get("AccessID", "")
        expires_str = request.query_params.get("Expires", "")
        signature = request.query_params.get("Signature", "")

        if not all([access_id, expires_str, signature]):
            return _error_response(401, "Missing authentication parameters")

        try:
            expires = int(expires_str)
        except ValueError:
            return _error_response(401, "Invalid Expires value")

        if expires < int(time.time()):
            return _error_response(401, "Signature expired")

        expected_sig = self._compute_signature(access_id, expires, settings.ctix.secret_key)
        if not hmac.compare_digest(signature, expected_sig):
            return _error_response(401, "Invalid signature")

        return await call_next(request)

    @staticmethod
    def _compute_signature(access_id: str, expires: int, secret_key: str) -> str:
        to_sign = f"{access_id}\n{expires}"
        return base64.b64encode(
            hmac.new(
                secret_key.encode("utf-8"),
                to_sign.encode("utf-8"),
                hashlib.sha1,
            ).digest()
        ).decode()
