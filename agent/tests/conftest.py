"""Shared test fixtures."""
import pytest


@pytest.fixture
def sample_report() -> dict:
    """A minimal CTIX report with description."""
    return {
        "id": "report--test-001",
        "type": "report",
        "name": "APT29 Phishing Campaign Analysis",
        "description": (
            "APT29 conducted a spear-phishing campaign targeting government agencies. "
            "The attackers used malicious Word documents with embedded macros to deliver "
            "Cobalt Strike beacons. Initial access was via T1566.001 (Spearphishing Attachment). "
            "The payload executed PowerShell scripts (T1059.001) to download Cobalt Strike. "
            "Lateral movement was achieved via RDP (T1021.001) after credential dumping with "
            "Mimikatz (T1003.001). Data was exfiltrated over DNS tunneling (T1048.003)."
        ),
        "published": "2026-03-15T00:00:00Z",
        "created": "2026-03-15T00:00:00Z",
        "report_types": ["threat-report"],
        "object_marking_refs": [
            "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"  # TLP:GREEN
        ],
    }


@pytest.fixture
def sample_report_no_description() -> dict:
    """A CTIX report without a description field."""
    return {
        "id": "report--test-002",
        "type": "report",
        "name": "Black Basta Ransomware Campaign",
        "published": "2026-03-20T00:00:00Z",
        "report_types": ["threat-report"],
        "object_marking_refs": [],
    }


@pytest.fixture
def sample_report_tlp_red() -> dict:
    """A TLP:RED report."""
    return {
        "id": "report--test-003",
        "type": "report",
        "name": "Classified Threat Assessment",
        "description": "Highly sensitive threat analysis.",
        "object_marking_refs": [
            "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"  # TLP:RED
        ],
    }


@pytest.fixture
def sample_sdos() -> list[dict]:
    """Sample related SDOs for narrative assembly."""
    return [
        {
            "id": "threat-actor--ta-001",
            "type": "threat-actor",
            "name": "APT29",
            "description": "Russian state-sponsored threat actor",
        },
        {
            "id": "malware--mal-001",
            "type": "malware",
            "name": "Cobalt Strike",
            "description": "Commercial penetration testing tool used by threat actors",
            "malware_types": ["backdoor"],
        },
        {
            "id": "tool--tool-001",
            "type": "tool",
            "name": "Mimikatz",
            "description": "Credential dumping tool",
            "tool_types": ["credential-exploitation"],
        },
        {
            "id": "attack-pattern--ap-001",
            "type": "attack-pattern",
            "name": "Spearphishing Attachment",
            "description": "Phishing emails with malicious attachments",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566.001"}
            ],
        },
        {
            "id": "attack-pattern--ap-002",
            "type": "attack-pattern",
            "name": "PowerShell",
            "description": "Abuse of PowerShell for execution",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1059.001"}
            ],
        },
        {
            "id": "attack-pattern--ap-003",
            "type": "attack-pattern",
            "name": "Remote Desktop Protocol",
            "description": "Lateral movement via RDP",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1021.001"}
            ],
        },
        {
            "id": "indicator--ind-001",
            "type": "indicator",
            "name": "192.168.1.100",
            "description": "C2 IP address",
        },
    ]


@pytest.fixture
def sample_stix_bundle() -> dict:
    """A minimal STIX 2.1 bundle for converter tests."""
    return {
        "type": "bundle",
        "id": "bundle--test-001",
        "objects": [
            {
                "type": "attack-action",
                "id": "attack-action--aa-001",
                "name": "Spearphishing Attachment",
                "description": "Attacker sends phishing email",
                "technique_id": "T1566.001",
                "tactic_id": "TA0001",
            },
            {
                "type": "attack-action",
                "id": "attack-action--aa-002",
                "name": "PowerShell Execution",
                "description": "Macro runs PowerShell",
                "technique_id": "T1059.001",
                "tactic_id": "TA0002",
            },
            {
                "type": "malware",
                "id": "malware--mal-001",
                "name": "Cobalt Strike",
                "description": "C2 beacon",
                "malware_types": ["backdoor"],
            },
            {
                "type": "tool",
                "id": "tool--tool-001",
                "name": "Mimikatz",
                "description": "Credential dumper",
                "tool_types": ["credential-exploitation"],
            },
            {
                "type": "relationship",
                "id": "relationship--rel-001",
                "source_ref": "attack-action--aa-001",
                "target_ref": "attack-action--aa-002",
                "relationship_type": "leads-to",
            },
            {
                "type": "relationship",
                "id": "relationship--rel-002",
                "source_ref": "attack-action--aa-002",
                "target_ref": "malware--mal-001",
                "relationship_type": "uses",
            },
        ],
    }
