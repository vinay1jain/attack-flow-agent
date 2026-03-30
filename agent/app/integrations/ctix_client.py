"""HMAC-authenticated async client for the configured upstream threat-intel API."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Any

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from ..config import get_settings

logger = structlog.get_logger(__name__)


def _generate_hmac_signature(access_id: str, secret_key: str) -> tuple[int, str]:
    """Generate HMAC-SHA1 signature for upstream API authentication.

    Mirrors the Cyware CFTR auth contract: sign ``"{access_id}\\n{expires}"``
    with the secret key and Base64-encode the digest.
    """
    expires = int(time.time() + 30)
    to_sign = f"{access_id}\n{expires}"
    signature = base64.b64encode(
        hmac.new(
            secret_key.encode("utf-8"),
            to_sign.encode("utf-8"),
            hashlib.sha1,
        ).digest()
    ).decode()
    return expires, signature


class CTIXClient:
    """Async HTTP client for threat-data and ingestion APIs (see settings / env)."""

    def __init__(self) -> None:
        settings = get_settings()
        self._base_url = settings.ctix.base_url.rstrip("/")
        self._access_id = settings.ctix.access_id
        self._secret_key = settings.ctix.secret_key
        self._verify_ssl = settings.ctix.verify_ssl
        self._timeout = settings.ctix.request_timeout

    def _auth_params(self) -> dict[str, Any]:
        expires, signature = _generate_hmac_signature(self._access_id, self._secret_key)
        return {
            "AccessID": self._access_id,
            "Expires": str(expires),
            "Signature": signature,
        }

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url,
            verify=self._verify_ssl,
            timeout=self._timeout,
            headers={"Content-Type": "application/json"},
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
    )
    async def _request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        merged_params = {**(params or {}), **self._auth_params()}
        headers: dict[str, str] = {}
        if tenant_id:
            headers["X-Tenant-Id"] = tenant_id

        async with self._client() as client:
            response = await client.request(
                method,
                endpoint,
                params=merged_params,
                json=json_body,
                headers=headers,
            )
            response.raise_for_status()
            return response.json()

    # ── Report endpoints ──────────────────────────────────────────────

    async def get_report(self, report_id: str, *, tenant_id: str | None = None) -> dict[str, Any]:
        """Fetch report details via ``GET /ingestion/threat-data/report/{id}/basic/``."""
        logger.info("ctix.get_report", report_id=report_id, tenant_id=tenant_id)
        return await self._request(
            "GET",
            f"/ingestion/threat-data/report/{report_id}/basic/",
            tenant_id=tenant_id,
        )

    async def get_report_relations(self, report_id: str, *, tenant_id: str | None = None) -> dict[str, Any]:
        """Fetch related SDOs via ``GET /ingestion/threat-data/report/{id}/relations/``."""
        logger.info("ctix.get_report_relations", report_id=report_id, tenant_id=tenant_id)
        return await self._request(
            "GET",
            f"/ingestion/threat-data/report/{report_id}/relations/",
            tenant_id=tenant_id,
        )

    # ── Ingestion endpoints ───────────────────────────────────────────

    async def ingest_bundle(
        self,
        stix_bundle: dict[str, Any],
        *,
        source: str = "attack-flow-agent",
        collection: str = "attack-flows",
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Store generated STIX objects via ``POST /ingestion/ingestion-api/ingest_bundle/``."""
        logger.info("ctix.ingest_bundle", object_count=len(stix_bundle.get("objects", [])), tenant_id=tenant_id)
        return await self._request(
            "POST",
            "/ingestion/ingestion-api/ingest_bundle/",
            json_body={
                "bundle": stix_bundle,
                "source": source,
                "collection": collection,
            },
            tenant_id=tenant_id,
        )

    async def notify_completion(
        self,
        report_id: str,
        react_flow_data: dict[str, Any],
        *,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Notify the upstream platform that attack flow generation is complete."""
        logger.info("ctix.notify_completion", report_id=report_id, tenant_id=tenant_id)
        return await self._request(
            "POST",
            f"/ingestion/threat-data/report/{report_id}/attack-flow/callback/",
            json_body={"react_flow_data": react_flow_data},
            tenant_id=tenant_id,
        )

    # ── Health check ──────────────────────────────────────────────────

    async def health_check(self) -> bool:
        """Return True if the upstream API is reachable."""
        try:
            async with self._client() as client:
                resp = await client.get("/health/", params=self._auth_params())
                return resp.is_success
        except Exception:
            return False
