"""Tests for narrative assembly."""
import os
import pytest
from app.core.narrative import assemble_narrative
from app.core.errors import AttackFlowError


os.environ.setdefault("CTIX_BASE_URL", "http://test")
os.environ.setdefault("CTIX_ACCESS_ID", "test")
os.environ.setdefault("CTIX_SECRET_KEY", "test")


def test_narrative_from_description(sample_report, sample_sdos):
    result = assemble_narrative(sample_report, sample_sdos)
    assert "APT29 Phishing Campaign Analysis" in result
    assert "spear-phishing" in result
    assert "T1566.001" in result


def test_narrative_from_sdos(sample_report_no_description, sample_sdos):
    result = assemble_narrative(sample_report_no_description, sample_sdos)
    assert "Black Basta Ransomware Campaign" in result
    assert "APT29" in result
    assert "Cobalt Strike" in result
    assert "Mimikatz" in result
    assert "T1566.001" in result


def test_narrative_insufficient_content(sample_report_no_description):
    thin_sdos = [
        {"id": "indicator--1", "type": "indicator", "name": "192.168.1.1"},
        {"id": "indicator--2", "type": "indicator", "name": "10.0.0.1"},
    ]
    with pytest.raises(AttackFlowError) as exc_info:
        assemble_narrative(sample_report_no_description, thin_sdos)
    assert exc_info.value.code.value == "REPORT_CONTENT_INSUFFICIENT"


def test_narrative_with_description_bypasses_sdo_check(sample_report):
    result = assemble_narrative(sample_report, [])
    assert "APT29" in result


def test_narrative_technique_hints(sample_report, sample_sdos):
    result = assemble_narrative(sample_report, sample_sdos)
    assert "T1059.001" in result
    assert "T1021.001" in result
