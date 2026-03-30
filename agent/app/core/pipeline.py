"""LangGraph-orchestrated attack flow generation pipeline.

Story 1.1 — Orchestrates the full flow: fetch report -> check TLP ->
fetch relations -> assemble narrative -> run ttp_chainer -> convert output ->
store results.  Each step updates the job stage for progress tracking.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, TypedDict

import structlog
from langgraph.graph import END, StateGraph

from ..config import get_settings
from ..core.errors import AttackFlowError, ErrorCode
from ..core.jobs import JobManager, get_job_manager
from ..core.narrative import assemble_narrative
from ..core.tlp import TLPEnforcer
from ..integrations.ctix_client import CTIXClient
from ..integrations.ttp_chainer.adapter import TTPChainerAdapter
from ..integrations.ttp_chainer.converter import stix_bundle_to_react_flow
from ..models.job import JobMetadata, JobStage, JobStatus

logger = structlog.get_logger(__name__)


class PipelineState(TypedDict, total=False):
    """State flowing through the LangGraph pipeline."""
    job_id: str
    report_id: str
    tenant_id: str
    report: dict[str, Any]
    related_sdos: list[dict[str, Any]]
    tlp_model: str
    tlp_level: str | None
    narrative: str
    extracted_data: dict[str, Any]
    stix_bundle: dict[str, Any]
    afb_data: dict[str, Any]
    react_flow_data: dict[str, Any]
    error: str | None
    error_code: str | None


# ── Pipeline node functions ──────────────────────────────────────────


async def fetch_report(state: PipelineState) -> PipelineState:
    """Fetch the report from the upstream platform."""
    job_mgr = get_job_manager()
    await job_mgr.update_status(
        state["job_id"],
        JobStatus.PROCESSING,
        stage=JobStage.FETCHING_REPORT,
        progress_message="Fetching report data from upstream API",
    )

    try:
        client = CTIXClient()
        report = await client.get_report(
            state["report_id"],
            tenant_id=state["tenant_id"],
        )
        return {**state, "report": report}
    except Exception as exc:
        logger.error("pipeline.fetch_report_failed", error=str(exc))
        return {
            **state,
            "error": str(exc),
            "error_code": ErrorCode.REPORT_NOT_FOUND.value,
        }


async def check_tlp(state: PipelineState) -> PipelineState:
    """Check TLP markings and determine which LLM model to use."""
    job_mgr = get_job_manager()
    await job_mgr.update_status(
        state["job_id"],
        JobStatus.PROCESSING,
        stage=JobStage.CHECKING_TLP,
        progress_message="Checking TLP markings",
    )

    try:
        enforcer = TLPEnforcer()
        decision = enforcer.check(state["report"])
        return {
            **state,
            "tlp_model": decision.model,
            "tlp_level": decision.tlp_level,
        }
    except AttackFlowError as exc:
        return {
            **state,
            "error": exc.message,
            "error_code": exc.code.value,
        }


async def fetch_relations(state: PipelineState) -> PipelineState:
    """Fetch related SDOs for the report."""
    job_mgr = get_job_manager()
    await job_mgr.update_status(
        state["job_id"],
        JobStatus.PROCESSING,
        stage=JobStage.FETCHING_RELATIONS,
        progress_message="Fetching related intelligence objects",
    )

    try:
        client = CTIXClient()
        relations_response = await client.get_report_relations(
            state["report_id"],
            tenant_id=state["tenant_id"],
        )
        sdos = relations_response.get("objects", relations_response.get("results", []))
        if isinstance(sdos, dict):
            sdos = list(sdos.values()) if sdos else []
        return {**state, "related_sdos": sdos}
    except Exception as exc:
        logger.warning("pipeline.fetch_relations_failed", error=str(exc))
        return {**state, "related_sdos": []}


async def build_narrative(state: PipelineState) -> PipelineState:
    """Assemble the narrative from report data and SDOs."""
    job_mgr = get_job_manager()
    await job_mgr.update_status(
        state["job_id"],
        JobStatus.PROCESSING,
        stage=JobStage.ASSEMBLING_NARRATIVE,
        progress_message="Assembling narrative from report data",
    )

    try:
        narrative = assemble_narrative(state["report"], state.get("related_sdos", []))
        return {**state, "narrative": narrative}
    except AttackFlowError as exc:
        return {
            **state,
            "error": exc.message,
            "error_code": exc.code.value,
        }


async def run_ttp_chainer(state: PipelineState) -> PipelineState:
    """Run the ttp_chainer AI pipeline."""
    job_mgr = get_job_manager()
    await job_mgr.update_status(
        state["job_id"],
        JobStatus.PROCESSING,
        stage=JobStage.ANALYZING_TECHNIQUES,
        progress_message="Analyzing techniques and building attack graph (this may take 1-3 minutes)",
    )

    try:
        adapter = TTPChainerAdapter(model=state.get("tlp_model"))
        import asyncio
        result = await asyncio.get_event_loop().run_in_executor(
            None, adapter.run, state["narrative"]
        )
        return {
            **state,
            "extracted_data": result.extracted_data,
            "stix_bundle": result.stix_bundle,
            "afb_data": result.afb_data,
        }
    except Exception as exc:
        logger.exception("pipeline.ttp_chainer_failed")
        error_code = ErrorCode.LLM_TIMEOUT.value if "timeout" in str(exc).lower() else ErrorCode.INTERNAL_ERROR.value
        return {
            **state,
            "error": str(exc),
            "error_code": error_code,
        }


async def convert_output(state: PipelineState) -> PipelineState:
    """Convert STIX bundle to React Flow JSON."""
    job_mgr = get_job_manager()
    await job_mgr.update_status(
        state["job_id"],
        JobStatus.PROCESSING,
        stage=JobStage.CONVERTING_OUTPUT,
        progress_message="Converting to interactive graph format",
    )

    react_flow_data = stix_bundle_to_react_flow(
        state["stix_bundle"],
        state.get("extracted_data"),
    )

    enforcer = TLPEnforcer()
    stix_bundle = enforcer.propagate_markings(state["report"], state["stix_bundle"])

    return {
        **state,
        "react_flow_data": react_flow_data,
        "stix_bundle": stix_bundle,
    }


async def store_results(state: PipelineState) -> PipelineState:
    """Store results in the upstream platform and update the job."""
    job_mgr = get_job_manager()
    await job_mgr.update_status(
        state["job_id"],
        JobStatus.PROCESSING,
        stage=JobStage.STORING_RESULTS,
        progress_message="Storing results",
    )

    try:
        client = CTIXClient()
        await client.ingest_bundle(
            state["stix_bundle"],
            tenant_id=state["tenant_id"],
        )
    except Exception as exc:
        logger.warning("pipeline.store_stix_failed", error=str(exc))

    try:
        client = CTIXClient()
        await client.notify_completion(
            state["report_id"],
            state["react_flow_data"],
            tenant_id=state["tenant_id"],
        )
    except Exception as exc:
        logger.warning("pipeline.notify_failed", error=str(exc))

    flow_id = f"flow-{uuid.uuid4().hex[:12]}"
    result = {
        "flow_id": flow_id,
        "report_id": state["report_id"],
        "tenant_id": state["tenant_id"],
        "nodes": state["react_flow_data"]["nodes"],
        "edges": state["react_flow_data"]["edges"],
        "stix_bundle": state["stix_bundle"],
        "afb_data": state.get("afb_data"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "llm_model": state.get("tlp_model"),
        "tlp_marking": state.get("tlp_level"),
    }

    node_count = len(result["nodes"])
    edge_count = len(result["edges"])

    await job_mgr.set_result(
        state["job_id"],
        result,
        metadata=JobMetadata(
            llm_model=state.get("tlp_model"),
            node_count=node_count,
            edge_count=edge_count,
        ),
    )
    await job_mgr.update_status(
        state["job_id"],
        JobStatus.COMPLETED,
        stage=JobStage.COMPLETE,
        progress_message=f"Complete — {node_count} nodes, {edge_count} edges",
    )

    return state


async def handle_error(state: PipelineState) -> PipelineState:
    """Record the error on the job."""
    job_mgr = get_job_manager()
    await job_mgr.set_error(
        state["job_id"],
        state.get("error_code", ErrorCode.INTERNAL_ERROR.value),
        state.get("error", "Unknown error"),
    )
    return state


# ── Conditional routing ──────────────────────────────────────────────


def _has_error(state: PipelineState) -> str:
    if state.get("error"):
        return "handle_error"
    return "continue"


# ── Graph construction ───────────────────────────────────────────────


def build_pipeline() -> Any:
    """Build and compile the LangGraph attack flow pipeline."""
    workflow = StateGraph(PipelineState)

    workflow.add_node("fetch_report", fetch_report)
    workflow.add_node("check_tlp", check_tlp)
    workflow.add_node("fetch_relations", fetch_relations)
    workflow.add_node("build_narrative", build_narrative)
    workflow.add_node("run_ttp_chainer", run_ttp_chainer)
    workflow.add_node("convert_output", convert_output)
    workflow.add_node("store_results", store_results)
    workflow.add_node("handle_error", handle_error)

    workflow.set_entry_point("fetch_report")

    workflow.add_conditional_edges(
        "fetch_report",
        _has_error,
        {"handle_error": "handle_error", "continue": "check_tlp"},
    )
    workflow.add_conditional_edges(
        "check_tlp",
        _has_error,
        {"handle_error": "handle_error", "continue": "fetch_relations"},
    )
    workflow.add_edge("fetch_relations", "build_narrative")
    workflow.add_conditional_edges(
        "build_narrative",
        _has_error,
        {"handle_error": "handle_error", "continue": "run_ttp_chainer"},
    )
    workflow.add_conditional_edges(
        "run_ttp_chainer",
        _has_error,
        {"handle_error": "handle_error", "continue": "convert_output"},
    )
    workflow.add_edge("convert_output", "store_results")
    workflow.add_edge("store_results", END)
    workflow.add_edge("handle_error", END)

    return workflow.compile()


_pipeline = None


def get_pipeline():
    global _pipeline
    if _pipeline is None:
        _pipeline = build_pipeline()
    return _pipeline


async def run_attack_flow_pipeline(
    job_id: str,
    report_id: str,
    tenant_id: str,
) -> None:
    """Execute the full pipeline for a given job. Called as a background task."""
    pipeline = get_pipeline()
    initial_state: PipelineState = {
        "job_id": job_id,
        "report_id": report_id,
        "tenant_id": tenant_id,
        "report": {},
        "related_sdos": [],
        "tlp_model": "",
        "tlp_level": None,
        "narrative": "",
        "extracted_data": {},
        "stix_bundle": {},
        "afb_data": {},
        "react_flow_data": {},
        "error": None,
        "error_code": None,
    }

    try:
        await pipeline.ainvoke(initial_state)
    except Exception as exc:
        logger.exception("pipeline.unhandled_error", job_id=job_id)
        job_mgr = get_job_manager()
        await job_mgr.set_error(job_id, ErrorCode.INTERNAL_ERROR.value, str(exc))
