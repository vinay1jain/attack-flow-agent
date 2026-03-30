"""File upload handling: parse PDF to text, validate STIX bundles."""
from __future__ import annotations

import io
import json
from typing import Any

import pdfplumber
import structlog

logger = structlog.get_logger(__name__)


def parse_pdf(file_bytes: bytes) -> str:
    """Extract text from a PDF file."""
    text_parts: list[str] = []
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)
    full_text = "\n\n".join(text_parts)
    logger.info("upload.pdf_parsed", pages=len(text_parts), chars=len(full_text))
    return full_text


def parse_stix_bundle(file_bytes: bytes) -> tuple[str, dict[str, Any]]:
    """Parse a STIX JSON bundle and extract a text narrative from it.

    Returns (narrative_text, stix_bundle_dict).
    """
    bundle = json.loads(file_bytes)
    if not isinstance(bundle, dict):
        raise ValueError("Invalid STIX bundle: expected JSON object")

    bundle_type = bundle.get("type", "")
    if bundle_type != "bundle":
        raise ValueError(f"Invalid STIX bundle: expected type 'bundle', got '{bundle_type}'")

    objects = bundle.get("objects", [])
    if not objects:
        raise ValueError("STIX bundle contains no objects")

    parts: list[str] = []

    for obj in objects:
        if obj.get("type") == "report":
            name = obj.get("name", "")
            desc = obj.get("description", "")
            if name:
                parts.append(f"# {name}\n")
            if desc:
                parts.append(desc)

    type_groups: dict[str, list[dict]] = {}
    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type in ("report", "relationship", "marking-definition", "identity", "bundle"):
            continue
        type_groups.setdefault(obj_type, []).append(obj)

    for obj_type, objs in sorted(type_groups.items()):
        parts.append(f"\n## {obj_type.replace('-', ' ').title()}\n")
        for obj in objs:
            name = obj.get("name", obj.get("value", "unnamed"))
            desc = obj.get("description", "")
            line = f"- [{obj_type.upper()}] {name}"
            if desc:
                line += f" — {desc[:300]}"
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    line += f" (MITRE {ref.get('external_id', '')})"
            parts.append(line)

    narrative = "\n".join(parts)
    logger.info("upload.stix_parsed", objects=len(objects), narrative_chars=len(narrative))
    return narrative, bundle


def parse_text_file(file_bytes: bytes) -> str:
    """Read a plain text file.

    Handles UTF-8 with BOM (common from Notepad / Google Docs export), UTF-16 LE/BE,
    and normalizes CRLF to LF so downstream LLM pipelines see clean text.
    """
    if file_bytes.startswith(b"\xff\xfe"):
        text = file_bytes[2:].decode("utf-16-le", errors="replace")
    elif file_bytes.startswith(b"\xfe\xff"):
        text = file_bytes[2:].decode("utf-16-be", errors="replace")
    else:
        # utf-8-sig strips UTF-8 BOM (EF BB BF)
        text = file_bytes.decode("utf-8-sig", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    logger.info("upload.text_parsed", chars=len(text))
    return text


def detect_file_type(filename: str, content: bytes) -> str:
    """Detect if file is PDF, STIX JSON, or plain text."""
    lower = filename.lower()
    if lower.endswith(".pdf"):
        return "pdf"
    if lower.endswith((".json", ".stix")):
        return "stix"
    if lower.endswith((".txt", ".md", ".csv", ".log")):
        return "text"
    try:
        data = json.loads(content)
        if isinstance(data, dict) and data.get("type") == "bundle":
            return "stix"
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    if content[:4] == b"%PDF":
        return "pdf"
    # If it looks like readable text, treat it as text
    try:
        decoded = content.decode("utf-8-sig")
        if len(decoded.strip()) > 0:
            return "text"
    except UnicodeDecodeError:
        pass
    raise ValueError(f"Unsupported file type: {filename}. Upload a STIX JSON bundle, PDF, or text report.")
