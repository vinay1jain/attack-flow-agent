"""Attack flow analysis engine.

Wraps the ttp_chainer pipeline and converts output to React Flow JSON.
All STIX-to-React-Flow conversion logic is self-contained here (no imports
from the agent package).
"""
from __future__ import annotations

import json
import re
import sys
import uuid
from typing import Any

import structlog

from .config import get_settings

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# STIX → React Flow type mapping (from agent/app/models/stix.py)
# ---------------------------------------------------------------------------

STIX_TO_FLOW_TYPE: dict[str, str] = {
    "attack-action": "action",
    "attack-pattern": "action",
    "tool": "tool",
    "malware": "malware",
    "attack-asset": "asset",
    "infrastructure": "infrastructure",
    "vulnerability": "vulnerability",
    "attack-condition": "asset",
    "attack-operator": "AND_operator",
    "process": "asset",
    "file": "asset",
    "url": "url",
    "ipv4-addr": "infrastructure",
    "ipv6-addr": "infrastructure",
    "domain-name": "infrastructure",
}

TACTIC_NAMES: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
    "TA0100": "Collection",
    "TA0101": "Command and Control",
    "TA0104": "Execution",
    "TA0106": "Impair Process Control",
    "TA0108": "Initial Access",
    "TA0109": "Lateral Movement",
    "TA0110": "Persistence",
    "TA0111": "Privilege Escalation",
}

TACTIC_PHASE_ORDER: list[str] = [
    "TA0043", "TA0042",
    "TA0001", "TA0108",
    "TA0002", "TA0104",
    "TA0003", "TA0110",
    "TA0004", "TA0111",
    "TA0005",
    "TA0006",
    "TA0007",
    "TA0008", "TA0109",
    "TA0009", "TA0100",
    "TA0011", "TA0101",
    "TA0010",
    "TA0040", "TA0106",
]

TACTIC_PHASE_RANK = {tid: i for i, tid in enumerate(TACTIC_PHASE_ORDER)}

_RENDERABLE_TYPES = set(STIX_TO_FLOW_TYPE.keys())

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

# ---------------------------------------------------------------------------
# STIX bundle → React Flow JSON converter
# ---------------------------------------------------------------------------


def stix_bundle_to_react_flow(
    stix_bundle: dict[str, Any],
    extracted_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Transform a STIX 2.1 bundle into React Flow nodes and edges."""
    objects = stix_bundle.get("objects", [])
    objects_by_id: dict[str, dict[str, Any]] = {
        obj["id"]: obj for obj in objects if "id" in obj
    }

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
        "analyze.stix_to_react_flow",
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


# ---------------------------------------------------------------------------
# Direct STIX conversion (no ttp_chainer needed)
# ---------------------------------------------------------------------------


def convert_stix_direct(stix_bundle: dict[str, Any]) -> dict[str, Any]:
    """Convert an already-parsed STIX bundle to React Flow graph.

    Used when the user uploads a STIX JSON file — no LLM extraction needed.
    """
    flow = stix_bundle_to_react_flow(stix_bundle)

    type_counts: dict[str, int] = {}
    for obj in stix_bundle.get("objects", []):
        t = obj.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    technique_count = sum(
        1 for n in flow["nodes"] if n.get("data", {}).get("technique_id")
    )

    return {
        "nodes": flow["nodes"],
        "edges": flow["edges"],
        "stix_bundle": stix_bundle,
        "afb_data": None,
        "stats": {
            "total_stix_objects": len(stix_bundle.get("objects", [])),
            "node_count": len(flow["nodes"]),
            "edge_count": len(flow["edges"]),
            "technique_count": technique_count,
            "type_breakdown": type_counts,
            "mode": "direct_stix",
        },
    }


# ---------------------------------------------------------------------------
# ttp_chainer pipeline wrapper
# ---------------------------------------------------------------------------


def _patch_pydantic_get() -> None:
    """Monkey-patch Pydantic BaseModel to support .get() like a dict.

    The ttp_chainer codebase calls .get() on objects that newer dspy versions
    return as Pydantic models instead of plain dicts.
    """
    from pydantic import BaseModel

    if hasattr(BaseModel, "_get_patched"):
        return

    def _get(self: Any, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def _getitem(self: Any, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    BaseModel.get = _get  # type: ignore[attr-defined]
    if not hasattr(BaseModel, "__getitem__"):
        BaseModel.__getitem__ = _getitem  # type: ignore[attr-defined]
    BaseModel._get_patched = True  # type: ignore[attr-defined]
    logger.info("analyze.pydantic_get_patched")


def _ensure_ttp_chainer_on_path() -> None:
    """Add the ttp_chainer directory to sys.path if not already present."""
    settings = get_settings()
    path = settings.ttp_chainer_path
    if not path:
        raise RuntimeError(
            "TTP_CHAINER_PATH is not configured. "
            "Set it in .env or as an environment variable."
        )
    if path not in sys.path:
        sys.path.insert(0, path)
        logger.info("analyze.ttp_chainer_path_added", path=path)


def _setup_dspy() -> None:
    """Configure DSPy with the LLM model from settings."""
    import dspy

    settings = get_settings()
    lm = dspy.LM(model=settings.extraction_model)
    dspy.configure(lm=lm)
    logger.info("analyze.dspy_configured", model=settings.extraction_model)


def _to_plain_dict(obj: Any) -> Any:
    """Recursively convert any object (stix2, Pydantic, dataclass) to plain dicts/lists."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: _to_plain_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_plain_dict(item) for item in obj]
    if hasattr(obj, "serialize"):
        try:
            return json.loads(obj.serialize())
        except Exception:
            pass
    if hasattr(obj, "model_dump"):
        return _to_plain_dict(obj.model_dump())
    if hasattr(obj, "dict"):
        return _to_plain_dict(obj.dict())
    if hasattr(obj, "__dict__"):
        return _to_plain_dict(
            {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
        )
    return str(obj)


def _serialize_stix_bundle(bundle: Any) -> dict[str, Any]:
    """Convert a stix2 Bundle object (with any nested Pydantic/custom objects) to plain dicts."""
    if hasattr(bundle, "serialize"):
        try:
            result = json.loads(bundle.serialize())
            if isinstance(result, dict):
                return result
        except Exception:
            pass
    return _to_plain_dict(bundle)


def _extracted_data_to_react_flow(extracted_data: dict[str, Any]) -> dict[str, Any]:
    """Build a connected attack flow graph from ttp_chainer extracted_data.

    Strategy (inspired by FlowViz):
      1. Attack actions are the main chain, ordered by MITRE tactic phase.
      2. Sequential "leads to" edges connect actions in adjacent phases.
      3. STIX objects, assets, conditions branch off via relation edges.
      4. The generic ttp_flow is NOT used for node creation — only
         report-specific extracted data is used.
      5. All relation edges from attack_report_graph are wired up,
         auto-creating any nodes referenced but not yet present.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    name_to_id: dict[str, str] = {}
    seen_ids: set[str] = set()
    edge_idx = 0

    def _get(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    def _add_node(node_id: str, flow_type: str, data: dict[str, Any]) -> None:
        if node_id in seen_ids:
            return
        seen_ids.add(node_id)
        nodes.append({
            "id": node_id,
            "type": flow_type,
            "data": {**data, "id": node_id, "type": flow_type},
            "position": {"x": 0, "y": 0},
        })

    def _register(name: str, node_id: str) -> None:
        if not name:
            return
        name_to_id[name] = node_id
        name_to_id[name.lower().strip()] = node_id
        if ":" in name:
            short = name.split(":", 1)[1].strip()
            name_to_id[short] = node_id
            name_to_id[short.lower()] = node_id

    # ── 1) Attack actions → "action" nodes, sorted by tactic phase ──
    raw_actions = extracted_data.get("attack_actions", [])
    actions_with_rank: list[tuple[int, int, Any]] = []
    for i, action in enumerate(raw_actions):
        tactic_id = _get(action, "tactic_id") or ""
        rank = TACTIC_PHASE_RANK.get(tactic_id, 50)
        actions_with_rank.append((rank, i, action))
    actions_with_rank.sort(key=lambda x: (x[0], x[1]))

    action_node_ids: list[str] = []
    for seq, (_, orig_idx, action) in enumerate(actions_with_rank):
        name = _get(action, "action_name") or _get(action, "name") or f"Action {orig_idx+1}"
        technique_id = _get(action, "technique_id")
        tactic_id = _get(action, "tactic_id")
        tactic_name = _get(action, "tactic_name") or TACTIC_NAMES.get(tactic_id or "", "")
        node_id = f"action-{seq+1}"
        _register(name, node_id)
        technique_name = _get(action, "technique_name")
        if technique_name:
            _register(technique_name, node_id)

        _add_node(node_id, "action", {
            "name": name,
            "description": _get(action, "action_description") or _get(action, "description"),
            "technique_id": technique_id,
            "tactic_id": tactic_id,
            "tactic_name": tactic_name,
            "source_excerpt": _get(action, "associated_source_evidence"),
            "confidence": _get(action, "confidence"),
        })
        action_node_ids.append(node_id)

    # ── 2) Sequential edges between adjacent attack actions ──
    for i in range(len(action_node_ids) - 1):
        edge_idx += 1
        edges.append({
            "id": f"edge-{edge_idx}",
            "source": action_node_ids[i],
            "target": action_node_ids[i + 1],
            "label": "leads to",
        })

    # ── 3) STIX objects → tool / infrastructure nodes ──
    for i, obj in enumerate(extracted_data.get("stix_objects", [])):
        name = (
            _get(obj, "object_name")
            or _get(obj, "name")
            or _get(obj, "stix_object_name")
            or ""
        )
        if not name or name == "{}":
            continue
        obj_type = (
            _get(obj, "object_type")
            or _get(obj, "type")
            or _get(obj, "stix_object_type")
            or "tool"
        )
        flow_type = STIX_TO_FLOW_TYPE.get(obj_type, "tool")
        node_id = f"obj-{i+1}"
        _register(name, node_id)
        _add_node(node_id, flow_type, {
            "name": name,
            "description": (
                _get(obj, "object_description")
                or _get(obj, "description")
                or _get(obj, "stix_object_description")
            ),
        })

    # ── 4) Attack assets → "asset" nodes ──
    for i, asset in enumerate(extracted_data.get("attack_assets", [])):
        name = _get(asset, "asset_name") or _get(asset, "name") or ""
        if not name:
            continue
        node_id = f"asset-{i+1}"
        _register(name, node_id)
        _add_node(node_id, "asset", {
            "name": name,
            "description": _get(asset, "asset_description") or _get(asset, "description"),
        })

    # ── 5) Attack conditions → "condition" nodes (rendered as asset) ──
    for i, cond in enumerate(extracted_data.get("attack_conditions", [])):
        name = _get(cond, "condition_name") or _get(cond, "name") or ""
        if not name:
            continue
        node_id = f"cond-{i+1}"
        _register(name, node_id)
        _add_node(node_id, "asset", {
            "name": name,
            "description": _get(cond, "condition_description") or _get(cond, "description"),
        })

    # ── 6) Relation edges from attack_report_graph ──
    graph_data = extracted_data.get("attack_report_graph", {})
    if isinstance(graph_data, dict):
        graph_edges = graph_data.get("attack_graph", [])
    else:
        graph_edges = getattr(graph_data, "attack_graph", [])

    auto_idx = 0

    def _ensure_node(name: str, type_hint: str) -> str | None:
        nonlocal auto_idx
        if not name:
            return None
        nid = _resolve_node_id(name, name_to_id)
        if nid:
            return nid
        auto_idx += 1
        nid = f"auto-{auto_idx}"
        _register(name, nid)
        ft_map = {
            "attack_action": "action",
            "stix_object": "tool",
            "attack_asset": "asset",
            "attack_condition": "asset",
        }
        _add_node(nid, ft_map.get(type_hint, "tool"), {"name": name, "description": None})
        return nid

    for ge in graph_edges:
        src_name = _get(ge, "source_node") or ""
        tgt_name = _get(ge, "target_node") or ""
        src_type = _get(ge, "source_node_type") or "attack_action"
        tgt_type = _get(ge, "target_node_type") or "attack_action"
        evidence = _get(ge, "associated_source_evidence") or ""

        # Skip the generic sequential TTP chain edges injected by ttp_flow orderer
        if "sequential ttp flow" in evidence.lower():
            continue

        src_id = _ensure_node(src_name, src_type)
        tgt_id = _ensure_node(tgt_name, tgt_type)
        if src_id and tgt_id and src_id != tgt_id:
            edge_idx += 1
            label = _get(ge, "relationship_type") or "related to"
            edges.append({
                "id": f"edge-{edge_idx}",
                "source": src_id,
                "target": tgt_id,
                "label": label.replace("_", " "),
            })

    edges = _deduplicate_edges(edges)

    logger.info(
        "analyze.extracted_to_react_flow",
        node_count=len(nodes),
        edge_count=len(edges),
        action_count=len(action_node_ids),
    )
    return {"nodes": nodes, "edges": edges}


def _resolve_node_id(name: str, name_to_id: dict[str, str]) -> str | None:
    """Find a node ID by name, using exact then fuzzy matching."""
    if not name:
        return None
    if name in name_to_id:
        return name_to_id[name]
    low = name.lower().strip()
    if low in name_to_id:
        return name_to_id[low]
    for key, nid in name_to_id.items():
        if key.lower().strip() == low:
            return nid
    for key, nid in name_to_id.items():
        kl = key.lower().strip()
        if low in kl or kl in low:
            return nid
    return None


def _fallback_graph_from_ttp_flow(extracted_data: dict[str, Any]) -> dict[str, Any]:
    """When primary conversion yields no nodes but ttp_chainer ordered a TTP chain, use it."""
    ttp_flow = extracted_data.get("ttp_flow") or []
    if not isinstance(ttp_flow, list) or not ttp_flow:
        return {"nodes": [], "edges": []}

    ttp_id_re = re.compile(r"^(.+?)\s*\[([A-Z0-9.]+)\]$")
    nodes: list[dict[str, Any]] = []
    for i, ttp_str in enumerate(ttp_flow):
        raw = (ttp_str or "").strip()
        if not raw:
            continue
        m = ttp_id_re.match(raw)
        if m:
            name, tid = m.group(1).strip(), m.group(2)
        else:
            name, tid = raw, None
        nid = f"ttp-{i+1}"
        nodes.append({
            "id": nid,
            "type": "action",
            "data": {
                "id": nid,
                "type": "action",
                "name": name,
                "technique_id": tid,
                "tactic_id": None,
                "tactic_name": None,
                "description": f"Ordered TTP chain (fallback): {raw}",
            },
            "position": {"x": 0, "y": 0},
        })
    edges: list[dict[str, Any]] = []
    for i in range(len(nodes) - 1):
        edges.append({
            "id": f"edge-ttp-{i+1}",
            "source": nodes[i]["id"],
            "target": nodes[i + 1]["id"],
            "label": "leads to",
        })
    logger.info("analyze.fallback_ttp_flow", nodes=len(nodes), edges=len(edges))
    return {"nodes": nodes, "edges": edges}


def _fallback_graph_from_llm(text: str) -> dict[str, Any]:
    """Last resort: ask the configured LLM to emit a small connected graph as JSON."""
    settings = get_settings()
    if not (settings.openai_api_key or "").strip():
        logger.warning("analyze.fallback_llm_skipped_no_api_key")
        return {"nodes": [], "edges": []}

    import litellm

    snippet = text.strip()[:14000]
    prompt = f"""You are a cyber threat analyst. Read the security text and build a small attack/vulnerability flow graph.

Return ONLY valid JSON (no markdown) with this exact shape:
{{
  "nodes": [
    {{"name": "short label", "node_type": "action|tool|asset|vulnerability", "technique_id": "T1068 or null", "tactic_name": "Privilege Escalation or null", "description": "one sentence"}}
  ],
  "edges": [
    {{"source": 0, "target": 1, "label": "leads to"}}
  ]
}}

Rules:
- 3 to 12 nodes. Indices in edges are 0-based positions in the nodes array.
- Use real MITRE technique IDs only when clearly justified by the text.
- For CVE advisories, include a vulnerability-type node for the CVE if mentioned.
- Every node should appear in at least one edge, or be connected via a chain.

TEXT:
{snippet}"""

    try:
        response = litellm.completion(
            model=settings.llm_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
        if not content:
            return {"nodes": [], "edges": []}
        payload = json.loads(content)
        raw_nodes = payload.get("nodes") or []
        raw_edges = payload.get("edges") or []
        if not raw_nodes:
            return {"nodes": [], "edges": []}

        flow_types = {
            "action": "action",
            "tool": "tool",
            "asset": "asset",
            "vulnerability": "vulnerability",
            "malware": "malware",
            "infrastructure": "infrastructure",
        }
        nodes: list[dict[str, Any]] = []
        for i, n in enumerate(raw_nodes):
            if not isinstance(n, dict):
                continue
            name = (n.get("name") or f"Step {i+1}").strip()
            nt = flow_types.get((n.get("node_type") or "action").lower(), "action")
            nid = f"llm-{i+1}"
            nodes.append({
                "id": nid,
                "type": nt,
                "data": {
                    "id": nid,
                    "type": nt,
                    "name": name,
                    "technique_id": n.get("technique_id"),
                    "tactic_id": None,
                    "tactic_name": n.get("tactic_name"),
                    "description": n.get("description"),
                },
                "position": {"x": 0, "y": 0},
            })

        edges: list[dict[str, Any]] = []
        for ei, e in enumerate(raw_edges):
            if not isinstance(e, dict):
                continue
            try:
                s = int(e.get("source", -1))
                t = int(e.get("target", -1))
            except (TypeError, ValueError):
                continue
            if s < 0 or t < 0 or s >= len(nodes) or t >= len(nodes) or s == t:
                continue
            edges.append({
                "id": f"edge-llm-{ei+1}",
                "source": nodes[s]["id"],
                "target": nodes[t]["id"],
                "label": (e.get("label") or "related to").replace("_", " "),
            })

        logger.info("analyze.fallback_llm", nodes=len(nodes), edges=len(edges))
        return {"nodes": nodes, "edges": edges}
    except Exception as exc:
        logger.warning("analyze.fallback_llm_failed", error=str(exc))
        return {"nodes": [], "edges": []}


def run_analysis(text: str) -> dict[str, Any]:
    """Run the full ttp_chainer pipeline and return React Flow graph + artifacts.

    Returns a dict with keys: nodes, edges, stix_bundle, afb_data, stats.
    """
    _patch_pydantic_get()
    _ensure_ttp_chainer_on_path()
    _setup_dspy()

    import aaftre
    import stix_object_creator
    from stix_2_afb import StixToAfbConverter

    logger.info("analyze.pipeline_start", text_chars=len(text))

    # Step 1: Extract TTPs from the report text
    extracted_data = aaftre.main(text)
    logger.info(
        "analyze.extraction_complete",
        keys=list(extracted_data.keys()) if isinstance(extracted_data, dict) else "non-dict",
    )

    # Step 2: Build React Flow graph directly from extracted data
    flow = _extracted_data_to_react_flow(extracted_data)
    fallback_used: str | None = None

    if not flow["nodes"]:
        flow = _fallback_graph_from_ttp_flow(extracted_data)
        if flow["nodes"]:
            fallback_used = "ttp_flow_chain"

    if not flow["nodes"]:
        flow = _fallback_graph_from_llm(text)
        if flow["nodes"]:
            fallback_used = "llm_minigraph"

    # Step 3: Try to create STIX bundle (best-effort, for export only)
    stix_bundle: dict[str, Any] | None = None
    try:
        stix_bundle_obj = stix_object_creator.create_stix_bundle(extracted_data)
        stix_bundle = _serialize_stix_bundle(stix_bundle_obj)
        logger.info("analyze.stix_bundle_created", objects=len(stix_bundle.get("objects", [])))
    except Exception as exc:
        logger.warning("analyze.stix_bundle_failed", error=str(exc))

    # Step 4: Try to create AFB format (best-effort, for export only)
    afb_data: dict[str, Any] | None = None
    try:
        if stix_bundle:
            layout_data = extracted_data.get("node_layout", {}) if isinstance(extracted_data, dict) else {}
            converter = StixToAfbConverter()
            afb_result = converter.convert_stix_to_afb(stix_bundle_obj, layout_data)
            afb_data = _to_plain_dict(afb_result)
            logger.info("analyze.afb_created")
    except Exception as exc:
        logger.warning("analyze.afb_failed", error=str(exc))

    technique_count = sum(
        1 for n in flow["nodes"] if n.get("data", {}).get("technique_id")
    )

    stats = {
        "node_count": len(flow["nodes"]),
        "edge_count": len(flow["edges"]),
        "technique_count": technique_count,
    }
    if fallback_used:
        stats["fallback"] = fallback_used

    logger.info("analyze.pipeline_complete", **stats)

    return {
        "nodes": flow["nodes"],
        "edges": flow["edges"],
        "stix_bundle": stix_bundle,
        "afb_data": afb_data,
        "stats": stats,
    }
