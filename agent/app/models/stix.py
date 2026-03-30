from __future__ import annotations

# TLP marking definition IDs (STIX 2.1 standard)
TLP_MARKINGS = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "TLP:WHITE",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "TLP:GREEN",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "TLP:AMBER",
    "marking-definition--826578e1-40a3-4b12-afc3-1a6a7123caef": "TLP:AMBER+STRICT",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "TLP:RED",
}

# Reverse lookup
TLP_BY_LEVEL = {v: k for k, v in TLP_MARKINGS.items()}

RESTRICTED_TLP_LEVELS = {"TLP:RED", "TLP:AMBER+STRICT"}

# STIX node types that map to React Flow node types
STIX_TO_FLOW_TYPE: dict[str, str] = {
    "attack-action": "action",
    "attack-pattern": "action",
    "tool": "tool",
    "malware": "malware",
    "attack-asset": "asset",
    "infrastructure": "infrastructure",
    "vulnerability": "vulnerability",
    "attack-condition": "asset",
    "attack-operator": "AND_operator",  # Will be overridden by operator value
    "process": "asset",
    "file": "asset",
    "url": "url",
    "ipv4-addr": "infrastructure",
    "ipv6-addr": "infrastructure",
    "domain-name": "infrastructure",
}

# MITRE ATT&CK tactic names
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
}


def get_tlp_level(marking_refs: list[str] | None) -> str | None:
    if not marking_refs:
        return None
    for ref in marking_refs:
        if ref in TLP_MARKINGS:
            return TLP_MARKINGS[ref]
    return None


def is_tlp_restricted(marking_refs: list[str] | None) -> bool:
    level = get_tlp_level(marking_refs)
    return level in RESTRICTED_TLP_LEVELS if level else False
