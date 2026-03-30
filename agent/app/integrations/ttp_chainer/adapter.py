"""Clean adapter wrapping the ttp_chainer pipeline.

Handles DSPy/LiteLLM initialization, calls ``aaftre.main()`` with the
narrative text, and returns structured output (extracted_data, STIX bundle,
AFB JSON).
"""

from __future__ import annotations

import importlib
import json
import sys
from typing import Any

import structlog

from ...config import get_settings

logger = structlog.get_logger(__name__)

_ttp_chainer_loaded = False


def _ensure_ttp_chainer_on_path() -> None:
    """Add the ttp_chainer directory to sys.path once."""
    global _ttp_chainer_loaded
    if _ttp_chainer_loaded:
        return
    settings = get_settings()
    chainer_path = settings.ttp_chainer_path
    if chainer_path not in sys.path:
        sys.path.insert(0, chainer_path)
    _ttp_chainer_loaded = True


class TTPChainerAdapter:
    """Wraps ttp_chainer's ``aaftre.main()`` with configurable LLM models."""

    def __init__(self, model: str | None = None) -> None:
        settings = get_settings()
        self.model = model or settings.llm.model
        self.extraction_model = settings.llm.extraction_model

    def run(self, narrative: str) -> TTPChainerResult:
        """Execute the full ttp_chainer pipeline.

        Parameters
        ----------
        narrative:
            The assembled threat report narrative text.

        Returns
        -------
        TTPChainerResult with ``extracted_data``, ``stix_bundle``, and
        ``afb_data`` populated.
        """
        _ensure_ttp_chainer_on_path()

        logger.info(
            "ttp_chainer.starting",
            model=self.model,
            extraction_model=self.extraction_model,
            narrative_len=len(narrative),
        )

        self._configure_dspy()

        try:
            aaftre = importlib.import_module("aaftre")
            extracted_data: dict[str, Any] = aaftre.main(narrative)
        except Exception:
            logger.exception("ttp_chainer.aaftre_failed")
            raise

        stix_bundle = self._create_stix_bundle(extracted_data)
        afb_data = self._create_afb(extracted_data, stix_bundle)

        node_count = len(extracted_data.get("attack_report_graph", {}).get("nodes", []))
        edge_count = len(extracted_data.get("attack_report_graph", {}).get("edges", []))
        logger.info("ttp_chainer.complete", nodes=node_count, edges=edge_count)

        return TTPChainerResult(
            extracted_data=extracted_data,
            stix_bundle=stix_bundle,
            afb_data=afb_data,
        )

    def _configure_dspy(self) -> None:
        """Set up DSPy with our configured LLM models."""
        import dspy  # noqa: delayed import after path setup
        import os

        settings = get_settings()
        api_key = settings.llm.openai_api_key or os.environ.get("OPENAI_API_KEY", "")

        reasoning_llm = dspy.LM(model=self.model, api_key=api_key, cache=False)
        dspy.settings.configure(lm=reasoning_llm, cache_dir="/tmp/dspy_cache")

    def _create_stix_bundle(self, extracted_data: dict[str, Any]) -> dict[str, Any]:
        stix_object_creator = importlib.import_module("stix_object_creator")
        bundle = stix_object_creator.create_stix_bundle(extracted_data)
        if hasattr(bundle, "serialize"):
            return json.loads(bundle.serialize())
        return bundle

    def _create_afb(
        self,
        extracted_data: dict[str, Any],
        stix_bundle: dict[str, Any],
    ) -> dict[str, Any]:
        stix_2_afb = importlib.import_module("stix_2_afb")
        converter = stix_2_afb.StixToAfbConverter()
        layout_data = extracted_data.get("node_layout", {})
        return converter.convert_stix_to_afb(stix_bundle, layout_data)


class TTPChainerResult:
    """Container for the three output artifacts of the ttp_chainer pipeline."""

    __slots__ = ("extracted_data", "stix_bundle", "afb_data")

    def __init__(
        self,
        *,
        extracted_data: dict[str, Any],
        stix_bundle: dict[str, Any],
        afb_data: dict[str, Any],
    ) -> None:
        self.extracted_data = extracted_data
        self.stix_bundle = stix_bundle
        self.afb_data = afb_data
