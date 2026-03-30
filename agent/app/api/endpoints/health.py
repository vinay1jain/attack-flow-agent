"""GET /api/v1/health — service health check."""

from __future__ import annotations

from fastapi import APIRouter

from ..schemas.responses import HealthResponse
from ...core.jobs import get_job_manager
from ...integrations.ctix_client import CTIXClient

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service health check",
)
async def health_check() -> HealthResponse:
    job_mgr = get_job_manager()
    active_jobs = await job_mgr.get_active_job_count()

    deps: dict[str, str] = {}
    try:
        client = CTIXClient()
        upstream_ok = await client.health_check()
        deps["upstream_api"] = "healthy" if upstream_ok else "unreachable"
    except Exception:
        deps["upstream_api"] = "unreachable"

    deps["llm_provider"] = "configured"

    overall = "healthy" if deps.get("upstream_api") == "healthy" else "degraded"

    return HealthResponse(
        status=overall,
        version="1.0.0",
        active_jobs=active_jobs,
        dependencies=deps,
    )
