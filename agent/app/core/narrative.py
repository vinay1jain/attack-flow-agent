"""Narrative assembly: synthesize a coherent text narrative from CTIX report data.

Story 1.2 — When a report lacks a prose ``description``, we assemble one from
the report's structured data (name, type, publication date, related SDOs) so
the ``ttp_chainer`` pipeline receives quality input.
"""

from __future__ import annotations

from typing import Any

import structlog

from ..config import get_settings
from ..core.errors import AttackFlowError, ErrorCode

logger = structlog.get_logger(__name__)

SDO_TYPE_ORDER = [
    "threat-actor",
    "intrusion-set",
    "campaign",
    "malware",
    "tool",
    "attack-pattern",
    "vulnerability",
    "indicator",
    "infrastructure",
    "observed-data",
    "identity",
    "location",
]


def _sdo_sort_key(sdo: dict[str, Any]) -> tuple[int, str]:
    sdo_type = sdo.get("type", "")
    try:
        type_rank = SDO_TYPE_ORDER.index(sdo_type)
    except ValueError:
        type_rank = len(SDO_TYPE_ORDER)
    return (type_rank, sdo.get("name", sdo.get("id", "")))


def _summarise_sdo(sdo: dict[str, Any]) -> str:
    """Produce a one-line summary of a STIX domain object."""
    sdo_type = sdo.get("type", "unknown")
    name = sdo.get("name", sdo.get("value", "unnamed"))
    desc = sdo.get("description", "")
    parts = [f"[{sdo_type.upper()}] {name}"]

    if sdo_type == "attack-pattern":
        ext_refs = sdo.get("external_references", [])
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                parts.append(f"(MITRE {ref.get('external_id', '')})")
                break

    if desc:
        truncated = desc[:300].rstrip()
        if len(desc) > 300:
            truncated += "..."
        parts.append(f"— {truncated}")

    return " ".join(parts)


def _extract_technique_hints(sdos: list[dict[str, Any]]) -> list[str]:
    """Pull ATT&CK technique IDs from existing attack-pattern objects."""
    hints: list[str] = []
    for sdo in sdos:
        if sdo.get("type") != "attack-pattern":
            continue
        for ref in sdo.get("external_references", []):
            ext_id = ref.get("external_id", "")
            if ext_id.startswith("T") and ref.get("source_name") == "mitre-attack":
                hints.append(ext_id)
    return hints


def assemble_narrative(
    report: dict[str, Any],
    related_sdos: list[dict[str, Any]],
) -> str:
    """Build the text narrative that feeds ``ttp_chainer``.

    Returns the assembled narrative string.
    Raises ``AttackFlowError`` with ``REPORT_CONTENT_INSUFFICIENT`` if the
    report is too thin.
    """
    settings = get_settings()
    min_sdos = settings.narrative.min_sdos
    max_chars = settings.narrative.max_chars

    description = (report.get("description") or "").strip()

    if description:
        narrative = _narrative_from_description(report, description, related_sdos)
    else:
        narrative = _narrative_from_sdos(report, related_sdos)

    sdo_count = len(related_sdos)
    if sdo_count < min_sdos and not description:
        raise AttackFlowError(
            ErrorCode.REPORT_CONTENT_INSUFFICIENT,
            {"min_sdos": str(min_sdos)},
        )

    if len(narrative) > max_chars:
        narrative = narrative[:max_chars] + "\n\n[Narrative truncated to fit token budget]"

    logger.info(
        "narrative.assembled",
        has_description=bool(description),
        sdo_count=sdo_count,
        narrative_chars=len(narrative),
    )
    return narrative


def _narrative_from_description(
    report: dict[str, Any],
    description: str,
    sdos: list[dict[str, Any]],
) -> str:
    """Use the report's own prose description, enriched with SDO context."""
    parts: list[str] = []
    parts.append(f"# {report.get('name', 'Threat Intelligence Report')}\n")

    pub_date = report.get("published") or report.get("created")
    if pub_date:
        parts.append(f"Published: {pub_date}\n")

    parts.append(description)

    technique_hints = _extract_technique_hints(sdos)
    if technique_hints:
        parts.append(
            f"\n\n## Referenced ATT&CK Techniques\n{', '.join(technique_hints)}"
        )

    sorted_sdos = sorted(sdos, key=_sdo_sort_key)
    supplementary = [s for s in sorted_sdos if s.get("type") not in ("report", "identity")]
    if supplementary:
        parts.append("\n\n## Related Intelligence Objects\n")
        for sdo in supplementary:
            parts.append(f"- {_summarise_sdo(sdo)}")

    return "\n".join(parts)


def _narrative_from_sdos(
    report: dict[str, Any],
    sdos: list[dict[str, Any]],
) -> str:
    """Synthesise a narrative entirely from structured SDO data."""
    parts: list[str] = []
    report_name = report.get("name", "Threat Intelligence Report")
    parts.append(f"# {report_name}\n")

    report_type = report.get("report_types", [])
    if report_type:
        parts.append(f"Report type: {', '.join(report_type)}\n")

    pub_date = report.get("published") or report.get("created")
    if pub_date:
        parts.append(f"Published: {pub_date}\n")

    parts.append(
        "The following intelligence objects are associated with this report "
        "and together describe the threat campaign:\n"
    )

    sorted_sdos = sorted(sdos, key=_sdo_sort_key)

    current_type = ""
    for sdo in sorted_sdos:
        sdo_type = sdo.get("type", "unknown")
        if sdo_type in ("report", "identity", "marking-definition"):
            continue
        if sdo_type != current_type:
            current_type = sdo_type
            parts.append(f"\n## {current_type.replace('-', ' ').title()}\n")
        parts.append(f"- {_summarise_sdo(sdo)}")

    technique_hints = _extract_technique_hints(sdos)
    if technique_hints:
        parts.append(
            f"\n\n## ATT&CK Technique Extraction Hints\n"
            f"The following technique IDs were found in existing attack-pattern objects "
            f"and should be included in the attack flow: {', '.join(technique_hints)}"
        )

    return "\n".join(parts)
