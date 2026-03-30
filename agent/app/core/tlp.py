"""TLP / Marking enforcement for attack flow generation.

Story 1.3 — TLP:RED and TLP:AMBER+STRICT reports must never be sent to
external LLM providers.  If a local model is configured, we transparently
switch to it; otherwise we block and return a clear error.
"""

from __future__ import annotations

from typing import Any

import structlog

from ..config import get_settings
from ..core.errors import AttackFlowError, ErrorCode
from ..models.stix import (
    TLP_MARKINGS,
    RESTRICTED_TLP_LEVELS,
    get_tlp_level,
)

logger = structlog.get_logger(__name__)


class TLPEnforcer:
    """Evaluate a report's TLP markings and determine the allowed LLM model."""

    def check(self, report: dict[str, Any]) -> TLPDecision:
        """Inspect the report and return a decision about which model to use.

        Raises ``AttackFlowError(TLP_RESTRICTED)`` when external processing is
        blocked *and* no local model is available.
        """
        marking_refs: list[str] = report.get("object_marking_refs", [])
        tlp_level = get_tlp_level(marking_refs)

        settings = get_settings()
        primary_model = settings.llm.model
        local_model = settings.llm.local_model

        if tlp_level and tlp_level in RESTRICTED_TLP_LEVELS:
            logger.warning(
                "tlp.restricted",
                tlp_level=tlp_level,
                has_local_model=bool(local_model),
            )
            if local_model:
                return TLPDecision(
                    allowed=True,
                    model=local_model,
                    tlp_level=tlp_level,
                    reason=f"Using local model due to {tlp_level} marking",
                )
            raise AttackFlowError(
                ErrorCode.TLP_RESTRICTED,
                {"tlp_level": tlp_level},
            )

        return TLPDecision(
            allowed=True,
            model=primary_model,
            tlp_level=tlp_level,
            reason="No TLP restriction",
        )

    @staticmethod
    def propagate_markings(
        report: dict[str, Any],
        artifacts: dict[str, Any],
    ) -> dict[str, Any]:
        """Copy the source report's TLP markings onto generated artifacts."""
        marking_refs = report.get("object_marking_refs", [])
        if not marking_refs:
            return artifacts

        if isinstance(artifacts, dict):
            for obj in artifacts.get("objects", []):
                if isinstance(obj, dict) and "object_marking_refs" not in obj:
                    obj["object_marking_refs"] = marking_refs
        return artifacts


class TLPDecision:
    """Outcome of a TLP enforcement check."""

    __slots__ = ("allowed", "model", "tlp_level", "reason")

    def __init__(
        self,
        *,
        allowed: bool,
        model: str,
        tlp_level: str | None,
        reason: str,
    ) -> None:
        self.allowed = allowed
        self.model = model
        self.tlp_level = tlp_level
        self.reason = reason

    def __repr__(self) -> str:
        return (
            f"TLPDecision(allowed={self.allowed}, model={self.model!r}, "
            f"tlp={self.tlp_level!r})"
        )
