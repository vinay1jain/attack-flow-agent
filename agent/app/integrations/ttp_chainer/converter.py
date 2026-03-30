"""Convert STIX bundle + ttp_chainer extracted data into React Flow JSON.

The output format matches what FlowViz (and the CTIX frontend) expects:
``{ nodes: [{ id, type, data, position }], edges: [{ id, source, target, label }] }``
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from ...models.stix import STIX_TO_FLOW_TYPE, TACTIC_NAMES

logger = structlog.get_logger(__name__)

# STIX object types we want to represent as nodes
_RENDERABLE_TYPES = set(STIX_TO_FLOW_TYPE.keys())

# Relationship types that map to graph edges
_EDGE_RELATIONSHIP_TYPES = {
    "uses",
    "delivers",
    "targets",
    "exploits",
    "indicates",
    "attributed-to",
    "communicates-with",
    "consists-of",
    "derived-from",
    "drops",
    "downloads",
    "controls",
    "has",
    "located-at",
    "variant-of",
}


def stix_bundle_to_react_flow(
    stix_bundle: dict[str, Any],
    extracted_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Transform a STIX 2.1 bundle into React Flow nodes and edges.

    Parameters
    ----------
    stix_bundle:
        A standard STIX 2.1 bundle dict with ``objects`` list.
    extracted_data:
        Optional ttp_chainer output with ``attack_report_graph`` for edge
        ordering and ``node_layout`` for positions.

    Returns
    -------
    Dict with ``nodes`` and ``edges`` lists ready for React Flow.
    """
    objects = stix_bundle.get("objects", [])
    objects_by_id: dict[str, dict[str, Any]] = {obj["id"]: obj for obj in objects if "id" in obj}

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_node_ids: set[str] = set()

    for obj in objects:
        obj_type = obj.get("type", "")

        if obj_type == "relationship":
            edge = _relationship_to_edge(obj, objects_by_id)
            if edge:
                edges.append(edge)
            continue

        if obj_type in _RENDERABLE_TYPES:
            node = _stix_object_to_node(obj)
            if node and node["id"] not in seen_node_ids:
                nodes.append(node)
                seen_node_ids.add(node["id"])

    if extracted_data:
        graph_data = extracted_data.get("attack_report_graph", {})
        graph_edges = graph_data.get("edges", [])
        if graph_edges:
            extra_edges = _extracted_graph_edges(graph_edges, seen_node_ids)
            edges.extend(extra_edges)

    edges = _deduplicate_edges(edges)

    logger.info(
        "converter.stix_to_react_flow",
        node_count=len(nodes),
        edge_count=len(edges),
    )
    return {"nodes": nodes, "edges": edges}


def _stix_object_to_node(obj: dict[str, Any]) -> dict[str, Any] | None:
    """Map a single STIX object to a React Flow node."""
    obj_type = obj.get("type", "")
    flow_type = STIX_TO_FLOW_TYPE.get(obj_type)
    if not flow_type:
        return None

    if obj_type == "attack-operator":
        op_val = obj.get("operator", "AND")
        flow_type = f"{op_val}_operator"

    data: dict[str, Any] = {
        "id": obj["id"],
        "type": flow_type,
        "name": obj.get("name", obj.get("value", obj_type)),
        "description": obj.get("description"),
    }

    if obj_type in ("attack-action", "attack-pattern"):
        data["technique_id"] = obj.get("technique_id")
        tactic_id = obj.get("tactic_id")
        data["tactic_id"] = tactic_id
        data["tactic_name"] = TACTIC_NAMES.get(tactic_id, "") if tactic_id else None

        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                data["technique_id"] = data["technique_id"] or ref.get("external_id")

        data["source_excerpt"] = obj.get("x_source_excerpt")
        data["confidence"] = _map_confidence(obj.get("confidence"))

    if obj_type == "tool":
        data["tool_types"] = obj.get("tool_types", [])
        data["command_line"] = obj.get("x_command_line")

    if obj_type == "malware":
        data["malware_types"] = obj.get("malware_types", [])

    if obj_type == "vulnerability":
        data["cve_id"] = obj.get("name")
        data["cvss_score"] = obj.get("x_cvss_score")

    return {
        "id": obj["id"],
        "type": flow_type,
        "data": data,
        "position": {"x": 0, "y": 0},
    }


def _relationship_to_edge(
    rel: dict[str, Any],
    objects_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Map a STIX relationship to a React Flow edge."""
    source_id = rel.get("source_ref", "")
    target_id = rel.get("target_ref", "")
    rel_type = rel.get("relationship_type", "")

    source_obj = objects_by_id.get(source_id)
    target_obj = objects_by_id.get(target_id)
    if not source_obj or not target_obj:
        return None

    source_type = source_obj.get("type", "")
    target_type = target_obj.get("type", "")
    if source_type not in _RENDERABLE_TYPES or target_type not in _RENDERABLE_TYPES:
        return None

    return {
        "id": rel.get("id", f"edge-{uuid.uuid4().hex[:8]}"),
        "source": source_id,
        "target": target_id,
        "label": rel_type.replace("-", " ").replace("_", " "),
    }


def _extracted_graph_edges(
    graph_edges: list[dict[str, Any]],
    valid_node_ids: set[str],
) -> list[dict[str, Any]]:
    """Convert edges from ttp_chainer's extracted graph into React Flow edges."""
    result: list[dict[str, Any]] = []
    for edge in graph_edges:
        source = edge.get("source", "")
        target = edge.get("target", "")
        if source in valid_node_ids and target in valid_node_ids:
            result.append({
                "id": f"edge-{uuid.uuid4().hex[:8]}",
                "source": source,
                "target": target,
                "label": edge.get("label", "leads to"),
            })
    return result


def _deduplicate_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate edges (same source→target pair)."""
    seen: set[tuple[str, str]] = set()
    result: list[dict[str, Any]] = []
    for edge in edges:
        key = (edge["source"], edge["target"])
        if key not in seen:
            seen.add(key)
            result.append(edge)
    return result


def _map_confidence(value: Any) -> str | None:
    """Map a STIX confidence integer (0-100) to low/medium/high."""
    if value is None:
        return None
    if isinstance(value, str):
        return value if value in ("low", "medium", "high") else None
    if isinstance(value, (int, float)):
        if value < 33:
            return "low"
        if value < 66:
            return "medium"
        return "high"
    return None
