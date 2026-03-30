"""Validate that an attack-flow graph is one connected piece (when multiple nodes exist)."""

from __future__ import annotations

from typing import Any


def validate_attack_flow_connectivity(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> tuple[bool, str]:
    """Return (True, "") if the flow may be shown; (False, user_message) if disconnected.

    Rules:
    - 0 or 1 node: always OK (nothing to connect).
    - 2+ nodes with no edges: not OK.
    - 2+ nodes with edges but more than one undirected connected component: not OK.
    """
    ids = {str(n["id"]) for n in nodes if n.get("id") not in (None, "")}
    if len(ids) <= 1:
        return True, ""

    if not edges:
        return False, (
            "The analysis found multiple entities but no relationships between them. "
            "An attack flow must show how steps link together. "
            "Try richer threat-report text, explicit procedures, or a STIX bundle that includes relationships, then analyze again."
        )

    adj: dict[str, set[str]] = {i: set() for i in ids}
    for e in edges:
        s, t = e.get("source"), e.get("target")
        if s is None or t is None:
            continue
        s, t = str(s), str(t)
        if s in ids and t in ids:
            adj[s].add(t)
            adj[t].add(s)

    visited: set[str] = set()
    components = 0
    for nid in ids:
        if nid in visited:
            continue
        components += 1
        stack = [nid]
        while stack:
            u = stack.pop()
            if u in visited:
                continue
            visited.add(u)
            for v in adj.get(u, ()):
                if v not in visited:
                    stack.append(v)

    if components > 1:
        return False, (
            "The graph is not fully connected: some parts of the attack have no path to the rest. "
            "This app expects a single linked attack flow. "
            "Use source material that ties techniques together, or one coherent incident narrative, then analyze again."
        )

    return True, ""
