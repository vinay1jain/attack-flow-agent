"""LLM-powered, behavioral detection rules for major SIEM/EDR/IDS platforms."""
from __future__ import annotations

import io
import json
import zipfile
from typing import Any

import litellm
import structlog

from .config import get_settings

logger = structlog.get_logger(__name__)

ALLOWED_FORMATS = frozenset({
    "sigma",
    "splunk_spl",
    "elastic_eql",
    "elastic_kql",
    "microsoft_sentinel_kql",
    "crowdstrike_fql",
    "chronicle_yaral",
    "qradar_aql",
    "yara",
    "suricata",
})
LEGACY_DEFAULT_FORMATS = ["sigma", "yara", "suricata"]

META_KEYS = (
    "mitre_tactic",
    "mitre_technique_id",
    "mitre_technique_name",
    "behavioral_summary",
    "data_sources",
    "false_positives",
    "implementation_guide",
)

OUTPUT_SPECS: dict[str, tuple[str, str]] = {
    "sigma": (
        "Sigma (YAML)",
        "Complete Sigma rule: behavioral selections first (process chains, parent/child, CLI patterns, "
        "registry, service events). Prefer ECS-aligned field names in `detection` where possible. "
        "Include title, status, description, logsource, detection, level, tags with MITRE id if known.",
    ),
    "splunk_spl": (
        "Splunk SPL",
        "Production SPL for a saved search or alert. Use Splunk **CIM**-style fields where applicable "
        "(e.g. `src`, `dest`, `user`, `process`, `process_name`, `parent_process_name`) and comment "
        "assumed `index`/`sourcetype`. Focus on behavior, not one-off strings unless necessary.",
    ),
    "elastic_eql": (
        "Elastic EQL",
        "EQL sequence or event query for Elastic Security. Use **ECS** field names (`process.name`, "
        "`process.parent.name`, `winlog.event_id`, `file.path`, `user.name`, etc.). Prefer sequences "
        "for multi-step behavior.",
    ),
    "elastic_kql": (
        "Elastic KQL",
        "KQL for Kibana Discover / Elastic Security rule predicates. ECS fields; suitable for "
        "threshold or building-block queries. Behavioral, not only hash/IP.",
    ),
    "microsoft_sentinel_kql": (
        "Microsoft Sentinel KQL",
        "KQL using common Sentinel tables (`SecurityEvent`, `Device*Events`, `SigninLogs`, "
        "`AuditLogs`, `CommonSecurityLog`, etc.) as appropriate. Map to **Microsoft** schema names; "
        "behavioral joins where useful.",
    ),
    "crowdstrike_fql": (
        "CrowdStrike (Falcon / LogScale-style query)",
        "Realistic Falcon telemetry query: comment expected event platforms (`#event_simpleName`, "
        "CrowdStrike process/network fields). Behavioral process or network patterns.",
    ),
    "chronicle_yaral": (
        "Google Chronicle YARA-L",
        "Chronicle **YARA-L 2.0** detection rule: `rule`, `meta`, `events`, `match`, `condition` "
        "structure; UDM field references where appropriate. Behavior-centric.",
    ),
    "qradar_aql": (
        "IBM QRadar AQL",
        "QRadar **AQL** for offense or search: realistic `WHERE` on QRadar event categories / "
        "high-level fields; note log source types in comments.",
    ),
    "yara": (
        "YARA",
        "If the technique implies **file or memory** artifacts, provide a full YARA rule. "
        "If not applicable, return a YARA comment block explaining N/A and point to process/network "
        "telemetry instead (still valid YARA syntax).",
    ),
    "suricata": (
        "Suricata / Snort",
        "Suricata-compatible rule emphasizing **behavioral** network patterns (protocol abuse, "
        "anomalies) where possible; explain in `msg` if indicators are thin.",
    ),
}

ZIP_FOLDER_EXT: dict[str, tuple[str, str]] = {
    "sigma": ("sigma", ".yml"),
    "splunk_spl": ("splunk", ".spl"),
    "elastic_eql": ("elastic_eql", ".eql"),
    "elastic_kql": ("elastic_kql", ".kql"),
    "microsoft_sentinel_kql": ("sentinel", ".kql"),
    "crowdstrike_fql": ("crowdstrike", ".fql"),
    "chronicle_yaral": ("chronicle", ".yaral"),
    "qradar_aql": ("qradar", ".aql"),
    "yara": ("yara", ".yar"),
    "suricata": ("suricata", ".rules"),
}


def normalize_output_formats(formats: list[str] | None) -> list[str]:
    if not formats:
        return list(LEGACY_DEFAULT_FORMATS)
    out: list[str] = []
    for f in formats:
        if f in ALLOWED_FORMATS and f not in out:
            out.append(f)
    return out or list(LEGACY_DEFAULT_FORMATS)


def _meta_placeholder(key: str) -> str:
    return f"(Not generated for {key}.)"


def _analyst_pack_markdown(rule: dict[str, Any]) -> str:
    blocks: list[str] = []
    title = f"# Analyst pack: {rule.get('technique_name', 'detection')}"
    if rule.get("technique_id"):
        title += f" ({rule['technique_id']})"
    blocks.append(title)
    if rule.get("mitre_tactic"):
        blocks.append(f"## MITRE tactic\n{rule['mitre_tactic']}")
    tid = rule.get("mitre_technique_id") or rule.get("technique_id")
    tname = rule.get("mitre_technique_name")
    if tid or tname:
        blocks.append(f"## MITRE technique\n**ID:** {tid or '—'}\n**Name:** {tname or '—'}")
    if rule.get("behavioral_summary"):
        blocks.append(f"## Behavioral summary\n{rule['behavioral_summary']}")
    if rule.get("data_sources"):
        blocks.append(f"## Data sources & telemetry\n{rule['data_sources']}")
    if rule.get("false_positives"):
        blocks.append(f"## False positives & tuning\n{rule['false_positives']}")
    if rule.get("implementation_guide"):
        blocks.append(f"## Implementation guide\n{rule['implementation_guide']}")
    return "\n\n".join(blocks)


def _build_prompt(
    context: str,
    intro: str,
    formats: list[str],
) -> str:
    format_bullets: list[str] = []
    for i, fmt in enumerate(formats, start=1):
        title, spec = OUTPUT_SPECS[fmt]
        format_bullets.append(f"{i}. **{title}** — {spec}")

    meta_bullets = "\n".join(
        f'- "{k}": string (markdown allowed where noted)'
        for k in META_KEYS
    )
    meta_descriptions = """
- mitre_tactic: Official ATT&CK tactic name best matching this detection.
- mitre_technique_id: Technique or sub-technique ID (e.g. T1059.001); best effort from context.
- mitre_technique_name: Official ATT&CK technique name.
- behavioral_summary: 2–5 sentences: what malicious behavior this surfaces and why it is behavioral.
- data_sources: Bullet list as plain text — specific Windows Event IDs, Sysmon Event IDs, ETW, Linux audit, cloud control plane logs, identity logs, etc. that must be ingested.
- false_positives: Bullet list as plain text — common administrative/IT false positives and concrete tuning steps (thresholds, exclusions, parent process allowlists).
- implementation_guide: One markdown document for a production analyst: prerequisites/ingest checks, step-by-step deployment for EACH requested platform section, validation queries, and escalation notes. Use clear headings and copy-paste blocks."""

    all_keys = json.dumps(list(META_KEYS) + formats)

    return f"""You are a senior enterprise detection engineer. Produce **high-fidelity, behavioral**
detection content derived from the attack-flow context below. Prioritize **TTPs, sequences, and
telemetry patterns**; avoid relying only on static IOCs unless the scenario is purely indicator-based.

## Context
{context}

## Target
{intro}

## Required JSON keys (exactly these keys, no others)
Return a single JSON object with ALL of the following keys: {all_keys}

### Analyst / MITRE / operations (always fill every one of these string values)
{meta_bullets}
{meta_descriptions}

### Detection formats (requested outputs only — fill each requested key with full rule/query text)
Generate exactly these detection outputs:
{chr(10).join(format_bullets)}

**Quality bar:** Queries must be copy-paste plausible for the stated vendor. Name standard data models
(**Splunk CIM**, **Elastic ECS**, Microsoft table names, etc.) in comments or `meta` where helpful.

If the context includes **Analyst-supplied additional context**, treat it as authoritative for
grounding detections, data sources, and false positives when it conflicts with vaguer node text.

Return ONLY valid JSON. Use \\n for newlines inside strings. No markdown fences outside the JSON."""


async def generate_rules(
    technique_name: str,
    technique_id: str | None = None,
    tactic_name: str | None = None,
    description: str | None = None,
    source_excerpt: str | None = None,
    focus: str = "technique",
    output_formats: list[str] | None = None,
    additional_context: str | None = None,
) -> dict[str, str]:
    """Generate analyst metadata + platform-specific rules."""
    settings = get_settings()
    formats = normalize_output_formats(output_formats)

    tid = (technique_id or "").strip() or "N/A"
    if focus == "technique":
        context = f"MITRE ATT&CK technique: {technique_name} ({tid})"
        intro = "MITRE ATT&CK technique listed above"
    else:
        focus_label = focus.replace("_", " ").title()
        context = f"Threat artifact type: {focus_label}\nName / label: {technique_name}"
        if tid != "N/A":
            context += f"\nRelated technique or reference ID (if any): {tid}"
        intro = f"{focus_label} described above"

    if tactic_name:
        context += f"\nReported tactic (if applicable): {tactic_name}"
    if description:
        context += f"\nDescription: {description}"
    if source_excerpt:
        context += f"\nEvidence from report: {source_excerpt}"
    ac = (additional_context or "").strip()
    if ac:
        context += (
            "\n\n---\n**Analyst-supplied additional context** (prioritize for grounding rules, "
            "data sources, and tuning):\n"
            f"{ac}"
        )

    prompt = _build_prompt(context, intro, formats)
    out: dict[str, str] = {}

    try:
        response = await litellm.acompletion(
            model=settings.llm_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.25,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
        parsed = json.loads(content)

        for key in META_KEYS:
            raw = parsed.get(key)
            if isinstance(raw, str) and raw.strip():
                out[key] = raw.strip()
            else:
                out[key] = _meta_placeholder(key)

        for fmt in formats:
            raw = parsed.get(fmt)
            if isinstance(raw, str) and raw.strip():
                out[fmt] = raw.strip()
            else:
                out[fmt] = f"# No {fmt} output generated"

        if tid != "N/A" and out.get("mitre_technique_id") == _meta_placeholder("mitre_technique_id"):
            out["mitre_technique_id"] = tid

        return out
    except Exception as exc:
        logger.error("rules.generation_failed", technique=tid, error=str(exc))
        for key in META_KEYS:
            out[key] = f"Error: {exc}"
        for fmt in formats:
            out[fmt] = f"# Error generating {fmt}: {exc}"
        return out


async def generate_bulk_rules(
    techniques: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Generate rules for multiple techniques."""
    results = []
    for tech in techniques:
        rules = await generate_rules(
            technique_name=tech["technique_name"],
            technique_id=tech.get("technique_id"),
            tactic_name=tech.get("tactic_name"),
            description=tech.get("description"),
            source_excerpt=tech.get("source_excerpt"),
            focus=tech.get("focus") or "technique",
            output_formats=tech.get("output_formats"),
            additional_context=tech.get("additional_context"),
        )
        tid_out = (tech.get("technique_id") or "").strip() or "custom"
        row: dict[str, Any] = {
            "technique_id": tid_out,
            "technique_name": tech["technique_name"],
        }
        row.update(rules)
        results.append(row)
    return results


def package_rules_zip(rules: list[dict[str, Any]]) -> bytes:
    """ZIP: per-platform folders + analyst_pack markdown per item."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, rule in enumerate(rules):
            raw_tid = rule.get("technique_id") or "custom"
            tid = str(raw_tid).replace(".", "_").replace("/", "_")[:32]
            name = str(rule["technique_name"]).replace(" ", "_").replace("/", "_")[:40]
            base = f"{i + 1:02d}_{tid}_{name}"[:80]

            zf.writestr(f"analyst_pack/{base}.md", _analyst_pack_markdown(rule))

            for fmt, (folder, ext) in ZIP_FOLDER_EXT.items():
                body = rule.get(fmt)
                if isinstance(body, str) and body.strip():
                    zf.writestr(f"{folder}/{base}{ext}", body)

        index_lines = [
            "# Detection rules pack (behavioral, multi-platform)",
            "",
            "Each row has: `analyst_pack/*.md` (MITRE, data sources, FPs, deployment guide) "
            "and vendor folders for selected formats.",
            "",
            f"Total items: {len(rules)}",
            "",
        ]
        for rule in rules:
            index_lines.append(f"- {rule['technique_id']}: {rule['technique_name']}")
        zf.writestr("README.md", "\n".join(index_lines))

    return buf.getvalue()
