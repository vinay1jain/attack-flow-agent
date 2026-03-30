from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ...models.job import JobMetadata, JobStage, JobStatus


class GenerateFlowResponse(BaseModel):
    job_id: str
    status: JobStatus
    message: str = "Attack flow generation started"


class JobStatusResponse(BaseModel):
    job_id: str
    report_id: str
    tenant_id: str
    status: JobStatus
    stage: JobStage | None = None
    progress_message: str | None = None
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    metadata: JobMetadata
    result: dict[str, Any] | None = None


class FlowResponse(BaseModel):
    flow_id: str
    report_id: str
    tenant_id: str
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    generated_at: str
    llm_model: str | None = None
    total_tokens: int = 0
    tlp_marking: str | None = None


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    active_jobs: int = 0
    dependencies: dict[str, str] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error_code: str
    message: str
    details: dict[str, str] = Field(default_factory=dict)
