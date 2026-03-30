from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class JobStage(str, Enum):
    FETCHING_REPORT = "fetching_report"
    CHECKING_TLP = "checking_tlp"
    FETCHING_RELATIONS = "fetching_relations"
    ASSEMBLING_NARRATIVE = "assembling_narrative"
    ANALYZING_TECHNIQUES = "analyzing_techniques"
    BUILDING_GRAPH = "building_graph"
    CONVERTING_OUTPUT = "converting_output"
    STORING_RESULTS = "storing_results"
    COMPLETE = "complete"


class JobMetadata(BaseModel):
    llm_model: str | None = None
    total_tokens: int = 0
    node_count: int = 0
    edge_count: int = 0
    error_code: str | None = None
    error_message: str | None = None


class Job(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    report_id: str
    tenant_id: str
    user_id: str | None = None
    status: JobStatus = JobStatus.QUEUED
    stage: JobStage | None = None
    progress_message: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    metadata: JobMetadata = Field(default_factory=JobMetadata)
    result: dict[str, Any] | None = None
