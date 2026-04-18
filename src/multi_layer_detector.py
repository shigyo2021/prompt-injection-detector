"""
Multi-layer prompt injection detector.

Processing order:
  Layer 1 (rule-based)  → instant block if pattern matches
  Layer 2 (ML model)    → block if confidence ≥ threshold
  Layer 3 (LLM judge)   → only runs when layers 1 & 2 both pass (optional)

Short-circuit evaluation minimizes latency and API cost.
"""
from __future__ import annotations

import os
from typing import Optional

from .rule_based_detector import detect as rule_detect
from .ml_detector import MLDetector
from .llm_judge import LLMJudge


class MultiLayerDetector:
    """
    Orchestrates the three detection layers.

    Args:
        enable_ml:       Enable Layer 2 (ML model). Default True.
        enable_llm:      Enable Layer 3 (LLM judge). Default: auto-detect via ANTHROPIC_API_KEY.
        ml_threshold:    Override ML confidence threshold.
        llm_threshold:   Override LLM confidence threshold.
    """

    def __init__(
        self,
        enable_ml: bool = True,
        enable_llm: Optional[bool] = None,
        ml_threshold: Optional[float] = None,
        llm_threshold: Optional[float] = None,
    ) -> None:
        self.enable_ml = enable_ml

        # Auto-enable LLM judge only when API key is present
        if enable_llm is None:
            self.enable_llm = bool(os.environ.get("ANTHROPIC_API_KEY"))
        else:
            self.enable_llm = enable_llm

        self._ml = MLDetector(threshold=ml_threshold) if enable_ml else None  # type: ignore[arg-type]
        if ml_threshold and self._ml:
            self._ml.threshold = ml_threshold

        self._llm = LLMJudge(threshold=llm_threshold) if self.enable_llm else None  # type: ignore[arg-type]
        if llm_threshold and self._llm:
            self._llm.threshold = llm_threshold

    def scan(self, text: str) -> dict:
        """
        Run all enabled layers against *text*.

        Returns:
            {
                "input": str,
                "final_verdict": "BLOCKED" | "PASSED",
                "blocked_by": "rule_based" | "ml_model" | "llm_judge" | null,
                "layers": [ ... per-layer result dicts ... ]
            }
        """
        layers: list[dict] = []

        # ── Layer 1: rule-based ─────────────────────────────────────────────
        rule_result = rule_detect(text)
        layers.append({
            "layer": "rule_based",
            "is_injection": rule_result["is_injection"],
            "detail": rule_result.get("matched_pattern"),
        })
        if rule_result["is_injection"]:
            return _build_result(text, "BLOCKED", "rule_based", layers)

        # ── Layer 2: ML model ───────────────────────────────────────────────
        if self._ml is not None:
            try:
                ml_result = self._ml.detect(text)
                layers.append({
                    "layer": "ml_model",
                    "is_injection": ml_result["is_injection"],
                    "confidence": ml_result["confidence"],
                    "label": ml_result["label"],
                    "detail": f"{ml_result['label']} @ {ml_result['confidence']:.2%}",
                })
                if ml_result["is_injection"]:
                    return _build_result(text, "BLOCKED", "ml_model", layers)
            except Exception as exc:
                layers.append({
                    "layer": "ml_model",
                    "is_injection": False,
                    "detail": f"error: {exc}",
                    "error": str(exc),
                })

        # ── Layer 3: LLM judge ──────────────────────────────────────────────
        if self._llm is not None:
            llm_result = self._llm.detect(text)
            layers.append({
                "layer": "llm_judge",
                "is_injection": llm_result["is_injection"],
                "confidence": llm_result.get("confidence"),
                "reason": llm_result.get("reason"),
                "attack_type": llm_result.get("attack_type"),
                "detail": llm_result.get("reason"),
            })
            if llm_result["is_injection"]:
                return _build_result(text, "BLOCKED", "llm_judge", layers)

        return _build_result(text, "PASSED", None, layers)


def _build_result(
    text: str,
    verdict: str,
    blocked_by: Optional[str],
    layers: list[dict],
) -> dict:
    return {
        "input": text,
        "final_verdict": verdict,
        "blocked_by": blocked_by,
        "layers": layers,
    }
