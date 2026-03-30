"""Tests for TLP enforcement."""
import os
import pytest
from app.core.tlp import TLPEnforcer
from app.core.errors import AttackFlowError


os.environ.setdefault("CTIX_BASE_URL", "http://test")
os.environ.setdefault("CTIX_ACCESS_ID", "test")
os.environ.setdefault("CTIX_SECRET_KEY", "test")


@pytest.fixture
def enforcer():
    return TLPEnforcer()


def test_tlp_green_allowed(enforcer, sample_report):
    decision = enforcer.check(sample_report)
    assert decision.allowed is True
    assert decision.tlp_level == "TLP:GREEN"
    assert "gpt-4o" in decision.model


def test_tlp_red_with_local_model(enforcer, sample_report_tlp_red):
    os.environ["LLM_LOCAL_MODEL"] = "ollama/llama3"
    from app.config import get_settings

    get_settings(reload=True)

    decision = enforcer.check(sample_report_tlp_red)
    assert decision.allowed is True
    assert "ollama" in decision.model
    assert decision.tlp_level == "TLP:RED"


def test_tlp_red_no_local_model(enforcer, sample_report_tlp_red):
    os.environ["LLM_LOCAL_MODEL"] = ""
    from app.config import get_settings

    get_settings(reload=True)

    with pytest.raises(AttackFlowError) as exc_info:
        enforcer.check(sample_report_tlp_red)
    assert exc_info.value.code.value == "TLP_RESTRICTED"
    assert "TLP:RED" in exc_info.value.message


def test_no_markings_allowed(enforcer):
    report = {"id": "report--1", "object_marking_refs": []}
    decision = enforcer.check(report)
    assert decision.allowed is True
    assert decision.tlp_level is None


def test_propagate_markings(enforcer, sample_report):
    artifacts = {
        "objects": [
            {"id": "obj-1", "type": "attack-action"},
            {"id": "obj-2", "type": "malware"},
        ]
    }
    result = enforcer.propagate_markings(sample_report, artifacts)
    for obj in result["objects"]:
        assert "object_marking_refs" in obj
