from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class GenerateFlowRequest(BaseModel):
    report_id: str = Field(..., description="CTIX report ID")
    force_regenerate: bool = Field(False, description="Force regeneration even if cached")


class ExportFormat(str, Enum):
    STIX = "stix"
    AFB = "afb"
    FLOWVIZ = "flowviz"
    PNG = "png"
