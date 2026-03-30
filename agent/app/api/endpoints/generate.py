"""POST /api/v1/attack-flow/generate — trigger attack flow generation."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..schemas.requests import GenerateFlowRequest
from ..schemas.responses import GenerateFlowResponse
from ...core.jobs import get_job_manager
from ...core.pipeline import run_attack_flow_pipeline
from ...models.job import JobStatus

router = APIRouter()


@router.post(
    "/generate",
    response_model=GenerateFlowResponse,
    status_code=202,
    summary="Generate an attack flow from a CTIX report",
)
async def generate_attack_flow(body: GenerateFlowRequest, request: Request) -> GenerateFlowResponse:
    tenant_id: str = request.state.tenant_id
    user_id: str | None = request.headers.get("X-User-Id")

    job_mgr = get_job_manager()

    if not body.force_regenerate:
        existing = await job_mgr.get_latest_flow_for_report(body.report_id)
        if existing:
            return GenerateFlowResponse(
                job_id=existing.id,
                status=existing.status,
                message="Cached attack flow returned (use force_regenerate=true to rebuild)",
            )

    job = await job_mgr.create_job(
        report_id=body.report_id,
        tenant_id=tenant_id,
        user_id=user_id,
    )

    asyncio.create_task(
        run_attack_flow_pipeline(job.id, body.report_id, tenant_id)
    )

    return GenerateFlowResponse(
        job_id=job.id,
        status=JobStatus.QUEUED,
        message="Attack flow generation started",
    )
