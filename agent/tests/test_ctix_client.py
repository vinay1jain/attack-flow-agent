"""Tests for upstream API client (unit tests with mocked HTTP)."""
import os
import pytest
import httpx
from unittest.mock import AsyncMock, patch

os.environ.setdefault("CTIX_BASE_URL", "http://test-platform.local")
os.environ.setdefault("CTIX_ACCESS_ID", "test-access-id")
os.environ.setdefault("CTIX_SECRET_KEY", "test-secret-key")

from app.integrations.ctix_client import CTIXClient, _generate_hmac_signature


def test_hmac_signature_generation():
    expires, signature = _generate_hmac_signature("test-id", "test-secret")
    assert isinstance(expires, int)
    assert isinstance(signature, str)
    assert len(signature) > 0


def test_hmac_signature_deterministic():
    """Same inputs at same time produce same signature."""
    from unittest.mock import patch as sync_patch

    fixed_time = 1711500000
    with sync_patch("app.integrations.ctix_client.time") as mock_time:
        mock_time.time.return_value = fixed_time
        _, sig1 = _generate_hmac_signature("id", "secret")
        _, sig2 = _generate_hmac_signature("id", "secret")
    assert sig1 == sig2


@pytest.mark.asyncio
async def test_get_report():
    client = CTIXClient()
    mock_response = httpx.Response(
        200,
        json={"id": "report--1", "name": "Test Report"},
        request=httpx.Request("GET", "http://test"),
    )
    with patch.object(httpx.AsyncClient, "request", new_callable=AsyncMock, return_value=mock_response):
        result = await client.get_report("report--1", tenant_id="tenant-1")
    assert result["id"] == "report--1"


@pytest.mark.asyncio
async def test_health_check_success():
    client = CTIXClient()
    mock_response = httpx.Response(200, request=httpx.Request("GET", "http://test"))
    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock, return_value=mock_response):
        assert await client.health_check() is True


@pytest.mark.asyncio
async def test_health_check_failure():
    client = CTIXClient()
    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock, side_effect=httpx.ConnectError("refused")):
        assert await client.health_check() is False
