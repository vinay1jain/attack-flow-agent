"""In-memory async job manager for attack flow generation.

Story 1.5 — Every generation is tracked as a job with full metadata.
The in-memory store is sufficient for Phase 1; the interface is designed
so it can be swapped for Redis or PostgreSQL in Phase 3.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import structlog

from ..models.job import Job, JobMetadata, JobStage, JobStatus

logger = structlog.get_logger(__name__)


class JobManager:
    """Thread-safe in-memory job store with async execution support."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = asyncio.Lock()
        self._flow_cache: dict[str, str] = {}

    async def create_job(
        self,
        report_id: str,
        tenant_id: str,
        user_id: str | None = None,
    ) -> Job:
        """Create a new job and return it."""
        job = Job(
            report_id=report_id,
            tenant_id=tenant_id,
            user_id=user_id,
        )
        async with self._lock:
            self._jobs[job.id] = job
        logger.info("job.created", job_id=job.id, report_id=report_id, tenant_id=tenant_id)
        return job

    async def get_job(self, job_id: str) -> Job | None:
        async with self._lock:
            return self._jobs.get(job_id)

    async def update_status(
        self,
        job_id: str,
        status: JobStatus,
        *,
        stage: JobStage | None = None,
        progress_message: str | None = None,
    ) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.status = status
            if stage is not None:
                job.stage = stage
            if progress_message is not None:
                job.progress_message = progress_message
            if status == JobStatus.PROCESSING and job.started_at is None:
                job.started_at = datetime.now(timezone.utc)
            if status in (JobStatus.COMPLETED, JobStatus.FAILED):
                job.completed_at = datetime.now(timezone.utc)

        logger.info(
            "job.status_updated",
            job_id=job_id,
            status=status.value,
            stage=stage.value if stage else None,
        )

    async def set_result(
        self,
        job_id: str,
        result: dict[str, Any],
        metadata: JobMetadata | None = None,
    ) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.result = result
            if metadata:
                job.metadata = metadata
            self._flow_cache[job.report_id] = job_id

    async def set_error(
        self,
        job_id: str,
        error_code: str,
        error_message: str,
    ) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.status = JobStatus.FAILED
            job.completed_at = datetime.now(timezone.utc)
            job.metadata.error_code = error_code
            job.metadata.error_message = error_message

        logger.error(
            "job.failed",
            job_id=job_id,
            error_code=error_code,
            error_message=error_message,
        )

    async def get_latest_flow_for_report(self, report_id: str) -> Job | None:
        """Return the most recent completed job for a given report."""
        async with self._lock:
            job_id = self._flow_cache.get(report_id)
            if job_id:
                job = self._jobs.get(job_id)
                if job and job.status == JobStatus.COMPLETED:
                    return job
        return None

    async def get_active_job_count(self) -> int:
        async with self._lock:
            return sum(
                1
                for j in self._jobs.values()
                if j.status in (JobStatus.QUEUED, JobStatus.PROCESSING)
            )

    async def get_tenant_job_count(self, tenant_id: str, since: datetime) -> int:
        """Count jobs for a tenant created since the given timestamp."""
        async with self._lock:
            return sum(
                1
                for j in self._jobs.values()
                if j.tenant_id == tenant_id and j.created_at >= since
            )

    async def list_jobs(
        self,
        tenant_id: str | None = None,
        limit: int = 50,
    ) -> list[Job]:
        async with self._lock:
            jobs = list(self._jobs.values())
        if tenant_id:
            jobs = [j for j in jobs if j.tenant_id == tenant_id]
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]


_job_manager: JobManager | None = None


def get_job_manager() -> JobManager:
    global _job_manager
    if _job_manager is None:
        _job_manager = JobManager()
    return _job_manager
