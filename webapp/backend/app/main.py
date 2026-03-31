"""Standalone Attack Flow Web App — Backend API."""
from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from .analyze import run_analysis
from .graph_connectivity import validate_attack_flow_connectivity
from .config import get_settings
from .rules import generate_bulk_rules, generate_rules, package_rules_zip_with_mode
from .schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    BulkRuleRequest,
    DetectionRule,
    HealthResponse,
    RuleRequest,
    UploadResponse,
)
from .upload import detect_file_type, parse_pdf, parse_stix_bundle, parse_text_file

load_dotenv()
logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    logger.info("webapp.starting", port=settings.port, model=settings.llm_model)
    yield
    logger.info("webapp.shutting_down")


app = FastAPI(
    title="Attack Flow Analyzer",
    description="Upload threat reports, visualize attack flows, generate detection rules",
    version="1.0.0",
    lifespan=lifespan,
)

settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        settings.frontend_url,
        "http://localhost:5173",
        "http://localhost:3000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", response_model=HealthResponse)
async def health():
    s = get_settings()
    key_ok = bool((s.openai_api_key or "").strip())
    return HealthResponse(
        status="healthy",
        llm_ready=key_ok,
        llm_model=s.llm_model or "",
        extraction_model=s.extraction_model or "",
    )


@app.post("/api/upload", response_model=UploadResponse)
async def upload_file(file: UploadFile = File(...)):
    """Upload a STIX JSON bundle or PDF report."""
    settings = get_settings()
    content = await file.read()

    if len(content) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(413, f"File too large. Maximum {settings.max_upload_mb}MB.")

    filename = file.filename or "unknown"
    try:
        file_type = detect_file_type(filename, content)
    except ValueError as e:
        raise HTTPException(400, str(e))

    stix_bundle = None
    if file_type == "pdf":
        text_content = parse_pdf(content)
    elif file_type == "text":
        text_content = parse_text_file(content)
    else:
        text_content, stix_bundle = parse_stix_bundle(content)

    if not text_content.strip():
        raise HTTPException(
            422, "Could not extract meaningful text from the uploaded file."
        )

    return UploadResponse(
        filename=filename,
        file_type=file_type,
        text_content=text_content,
        stix_bundle=stix_bundle,
        char_count=len(text_content),
    )


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    """Analyze a report and return attack flow graph.

    Always runs the LLM-powered ttp_chainer pipeline to extract techniques,
    build causal relationships, and generate a proper attack flow — regardless
    of whether the input was a STIX bundle or plain text.
    """
    if not request.text_content.strip():
        raise HTTPException(400, "No text content provided.")

    start = time.time()
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, run_analysis, request.text_content
        )
        elapsed = time.time() - start
        result["stats"]["elapsed_seconds"] = round(elapsed, 2)

        nodes = result.get("nodes") or []
        edges = result.get("edges") or []
        ok, connectivity_msg = validate_attack_flow_connectivity(nodes, edges)
        if not ok:
            raise HTTPException(422, connectivity_msg)

        return AnalyzeResponse(**result)
    except Exception as exc:
        logger.exception("analyze.failed")
        raise HTTPException(500, f"Analysis failed: {str(exc)}")


@app.post("/api/rules/generate", response_model=DetectionRule, response_model_exclude_none=True)
async def generate_detection_rules(request: RuleRequest):
    """Behavioral detection pack: MITRE mapping, data sources, tuning, implementation guide, and native queries per selected platform."""
    rules = await generate_rules(
        technique_name=request.technique_name,
        technique_id=request.technique_id,
        tactic_name=request.tactic_name,
        description=request.description,
        source_excerpt=request.source_excerpt,
        focus=request.focus,
        output_formats=request.output_formats,
        additional_context=request.additional_context,
    )
    return DetectionRule(
        technique_id=request.technique_id or "",
        technique_name=request.technique_name,
        **rules,
    )


@app.post("/api/rules/bulk")
async def bulk_generate_rules(request: BulkRuleRequest):
    """Generate rules for all techniques and return as ZIP."""
    techniques = [t.model_dump() for t in request.techniques]
    rules = await generate_bulk_rules(techniques)
    zip_bytes = package_rules_zip_with_mode(rules, request.rule_output_mode)

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=detection-rules-analysis-{request.rule_output_mode}.zip"},
    )


@app.get("/api/test-result")
async def test_result():
    """Serve cached analysis result for UI testing (dev only)."""
    import json as _json
    from pathlib import Path

    cached = Path("/tmp/analyze_result.json")
    if cached.exists():
        return _json.loads(cached.read_text())
    raise HTTPException(404, "No cached result")


if __name__ == "__main__":
    import uvicorn

    s = get_settings()
    uvicorn.run("app.main:app", host="0.0.0.0", port=s.port, reload=True)
