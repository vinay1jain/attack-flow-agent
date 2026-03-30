"""Main API router aggregating all endpoint modules."""

from __future__ import annotations

from fastapi import APIRouter

from .endpoints import generate, jobs, flows, health

api_router = APIRouter(prefix="/api/v1/attack-flow")

api_router.include_router(generate.router, tags=["generation"])
api_router.include_router(jobs.router, tags=["jobs"])
api_router.include_router(flows.router, tags=["flows"])

health_router = APIRouter()
health_router.include_router(health.router, prefix="/api/v1", tags=["health"])
