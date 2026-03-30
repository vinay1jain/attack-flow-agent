"""Flow retrieval and export endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from ...core.jobs import get_job_manager

router = APIRouter()


@router.get(
    "/report/{report_id}",
    summary="Get the latest attack flow for a report",
)
async def get_flow_for_report(report_id: str, request: Request) -> JSONResponse:
    job_mgr = get_job_manager()
    job = await job_mgr.get_latest_flow_for_report(report_id)

    if not job or not job.result:
        raise HTTPException(
            status_code=404,
            detail=f"No attack flow found for report {report_id}",
        )

    return JSONResponse(content=job.result)


@router.get(
    "/{flow_id}/export/{fmt}",
    summary="Export an attack flow in the specified format",
)
async def export_flow(flow_id: str, fmt: str) -> JSONResponse:
    job_mgr = get_job_manager()

    target_job = None
    for job in (await job_mgr.list_jobs(limit=500)):
        if job.result and job.result.get("flow_id") == flow_id:
            target_job = job
            break

    if not target_job or not target_job.result:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found")

    result = target_job.result

    if fmt == "stix":
        bundle = result.get("stix_bundle")
        if not bundle:
            raise HTTPException(status_code=404, detail="STIX bundle not available")
        return JSONResponse(
            content=bundle,
            headers={"Content-Disposition": f'attachment; filename="{flow_id}-stix.json"'},
        )

    if fmt == "afb":
        afb = result.get("afb_data")
        if not afb:
            raise HTTPException(status_code=404, detail="AFB data not available")
        return JSONResponse(
            content=afb,
            headers={"Content-Disposition": f'attachment; filename="{flow_id}.afb"'},
        )

    if fmt == "flowviz":
        return JSONResponse(
            content={
                "nodes": result.get("nodes", []),
                "edges": result.get("edges", []),
                "metadata": {
                    "flow_id": flow_id,
                    "report_id": result.get("report_id"),
                    "generated_at": result.get("generated_at"),
                },
            },
            headers={"Content-Disposition": f'attachment; filename="{flow_id}-flowviz.json"'},
        )

    raise HTTPException(status_code=400, detail=f"Unsupported export format: {fmt}. Use stix, afb, or flowviz.")
