"""Tests for STIX to React Flow converter."""
from app.integrations.ttp_chainer.converter import stix_bundle_to_react_flow


def test_basic_conversion(sample_stix_bundle):
    result = stix_bundle_to_react_flow(sample_stix_bundle)
    assert "nodes" in result
    assert "edges" in result
    assert len(result["nodes"]) == 4  # 2 actions + 1 malware + 1 tool
    assert len(result["edges"]) == 2  # 2 relationships


def test_node_types_mapped(sample_stix_bundle):
    result = stix_bundle_to_react_flow(sample_stix_bundle)
    types = {n["type"] for n in result["nodes"]}
    assert "action" in types
    assert "malware" in types
    assert "tool" in types


def test_action_node_has_technique(sample_stix_bundle):
    result = stix_bundle_to_react_flow(sample_stix_bundle)
    action_nodes = [n for n in result["nodes"] if n["type"] == "action"]
    assert any(n["data"].get("technique_id") == "T1566.001" for n in action_nodes)


def test_edge_labels(sample_stix_bundle):
    result = stix_bundle_to_react_flow(sample_stix_bundle)
    labels = {e["label"] for e in result["edges"]}
    assert "leads to" in labels
    assert "uses" in labels


def test_empty_bundle():
    result = stix_bundle_to_react_flow({"type": "bundle", "objects": []})
    assert result["nodes"] == []
    assert result["edges"] == []


def test_deduplication():
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "tool", "id": "tool--1", "name": "Tool A"},
            {"type": "tool", "id": "tool--1", "name": "Tool A"},  # duplicate
        ],
    }
    result = stix_bundle_to_react_flow(bundle)
    assert len(result["nodes"]) == 1
