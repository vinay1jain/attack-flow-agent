from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class FlowNodeData(BaseModel):
    """Data payload for a React Flow node, matching FlowViz's expected format."""

    id: str
    type: str
    name: str
    description: str | None = None
    technique_id: str | None = None
    tactic_id: str | None = None
    tactic_name: str | None = None
    source_excerpt: str | None = None
    confidence: Literal["low", "medium", "high"] | None = None
    command_line: str | None = None
    # Tool/malware specific
    tool_types: list[str] | None = None
    # Vulnerability specific
    cve_id: str | None = None
    cvss_score: float | None = None
    # Asset specific
    indicator_type: str | None = None
    indicator_value: str | None = None
    # Operator specific
    operator: Literal["AND", "OR"] | None = None


class FlowNodePosition(BaseModel):
    x: float = 0.0
    y: float = 0.0


class FlowNode(BaseModel):
    """React Flow node structure."""

    id: str
    type: str
    data: FlowNodeData
    position: FlowNodePosition = Field(default_factory=FlowNodePosition)


class FlowEdge(BaseModel):
    """React Flow edge structure."""

    id: str
    source: str
    target: str
    label: str | None = None


class AttackFlowResult(BaseModel):
    """Complete attack flow result returned to the frontend."""

    flow_id: str
    report_id: str
    tenant_id: str
    nodes: list[FlowNode]
    edges: list[FlowEdge]
    stix_bundle: dict[str, Any] | None = None
    afb_data: dict[str, Any] | None = None
    generated_at: str
    llm_model: str | None = None
    total_tokens: int = 0
    tlp_marking: str | None = None
