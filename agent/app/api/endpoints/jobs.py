"""GET /api/v1/attack-flow/jobs/{job_id} — query job status."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..schemas.responses import JobStatusResponse
from ...core.jobs import get_job_manager

router = APIRouter()


@router.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    summary="Get attack flow generation job status",
)
async def get_job_status(job_id: str) -> JobStatusResponse:
    job_mgr = get_job_manager()
    job = await job_mgr.get_job(job_id)

    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    return JobStatusResponse(
        job_id=job.id,
        report_id=job.report_id,
        tenant_id=job.tenant_id,
        status=job.status,
        stage=job.stage,
        progress_message=job.progress_message,
        created_at=job.created_at.isoformat(),
        started_at=job.started_at.isoformat() if job.started_at else None,
        completed_at=job.completed_at.isoformat() if job.completed_at else None,
        metadata=job.metadata,
        result=job.result,
    )
