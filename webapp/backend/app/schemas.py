from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class UploadResponse(BaseModel):
    filename: str
    file_type: str
    text_content: str
    stix_bundle: dict[str, Any] | None = None
    char_count: int


class FlowNodeData(BaseModel):
    id: str
    type: str
    name: str
    description: str | None = None
    technique_id: str | None = None
    tactic_id: str | None = None
    tactic_name: str | None = None
    source_excerpt: str | None = None
    confidence: str | None = None
    command_line: str | None = None
    tool_types: list[str] | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    operator: str | None = None


class FlowNode(BaseModel):
    id: str
    type: str
    data: FlowNodeData
    position: dict[str, float] = {"x": 0, "y": 0}


class FlowEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str | None = None


class AnalyzeRequest(BaseModel):
    text_content: str
    filename: str | None = None
    stix_bundle: dict[str, Any] | None = None


class AnalyzeResponse(BaseModel):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    stix_bundle: dict[str, Any] | None = None
    afb_data: dict[str, Any] | None = None
    stats: dict[str, Any] = {}


RuleFocus = Literal[
    "technique",
    "tool",
    "malware",
    "vulnerability",
    "asset",
    "infrastructure",
    "other",
]

RuleOutputFormat = Literal[
    "sigma",
    "splunk_spl",
    "elastic_eql",
    "elastic_kql",
    "microsoft_sentinel_kql",
    "crowdstrike_fql",
    "chronicle_yaral",
    "qradar_aql",
    "yara",
    "suricata",
]

RuleOutputMode = Literal[
    "per_node_zip",
    "combined_per_technology",
    "merged_per_technology_file",
]


class RuleRequest(BaseModel):
    technique_name: str
    technique_id: str | None = None
    tactic_name: str | None = None
    description: str | None = None
    source_excerpt: str | None = None
    focus: RuleFocus = Field(
        default="technique",
        description="What to write detections for (tools/assets need focus≠technique when no MITRE ID).",
    )
    output_formats: list[RuleOutputFormat] | None = Field(
        default=None,
        description="Which rule technologies to generate. Omitted = sigma, yara, suricata (legacy).",
    )
    additional_context: str | None = Field(
        default=None,
        description="Optional analyst text (e.g. pasted report excerpt) to ground rules beyond node fields.",
    )


class DetectionRule(BaseModel):
    technique_id: str = ""
    technique_name: str
    mitre_tactic: str | None = None
    mitre_technique_id: str | None = None
    mitre_technique_name: str | None = None
    behavioral_summary: str | None = None
    data_sources: str | None = None
    false_positives: str | None = None
    implementation_guide: str | None = None
    sigma: str | None = None
    splunk_spl: str | None = None
    elastic_eql: str | None = None
    elastic_kql: str | None = None
    microsoft_sentinel_kql: str | None = None
    crowdstrike_fql: str | None = None
    chronicle_yaral: str | None = None
    qradar_aql: str | None = None
    yara: str | None = None
    suricata: str | None = None

    model_config = {"extra": "forbid"}


class BulkRuleRequest(BaseModel):
    techniques: list[RuleRequest]
    rule_output_mode: RuleOutputMode = Field(
        default="per_node_zip",
        description=(
            "Bulk packaging mode: per_node_zip (legacy), combined_per_technology "
            "(single synthesized output per technology), or merged_per_technology_file "
            "(one file per technology with per-node sections)."
        ),
    )


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    # Non-secret runtime hints for operators (never expose OPENAI_API_KEY).
    llm_ready: bool = Field(
        default=False,
        description="True if OPENAI_API_KEY is set on the server (non-empty).",
    )
    llm_model: str = Field(default="", description="Primary LLM id (e.g. openai/gpt-4o).")
    extraction_model: str = Field(default="", description="Extraction / mini model id.")
