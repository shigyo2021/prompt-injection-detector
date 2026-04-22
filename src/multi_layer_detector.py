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

from .audit_log import emit_scan_event, hash_input, input_preview, monotonic_ms, new_scan_id
from .config import MAX_INPUT_CHARS
from .rule_based_detector import detect as rule_detect
from .ml_detector import MLDetector
from .llm_judge import LLMJudge
from .secrets_util import resolve_api_key


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
        anthropic_api_key: Optional[str] = None,
    ) -> None:
        self.enable_ml = enable_ml

        # Resolve the Anthropic key once here (explicit arg wins; env-var is
        # fallback; invalid-shape keys are treated as absent). This way the
        # detector and the LLM judge agree on whether a usable key exists
        # instead of each calling os.environ.get independently.
        resolved_key = resolve_api_key(
            anthropic_api_key, env_var="ANTHROPIC_API_KEY", provider="anthropic"
        )

        # Auto-enable LLM judge only when a valid key is available.
        if enable_llm is None:
            self.enable_llm = bool(resolved_key)
        else:
            self.enable_llm = enable_llm

        self._ml = MLDetector(threshold=ml_threshold) if enable_ml else None  # type: ignore[arg-type]
        if ml_threshold and self._ml:
            self._ml.threshold = ml_threshold

        self._llm = (
            LLMJudge(threshold=llm_threshold, api_key=resolved_key)  # type: ignore[arg-type]
            if self.enable_llm else None
        )
        if llm_threshold and self._llm:
            self._llm.threshold = llm_threshold

    def scan(self, text: str) -> dict:
        """
        Run all enabled layers against *text*.

        Returns:
            {
                "input_hash":    str,     # SHA-256 prefix (M5: no raw input)
                "input_length":  int,
                "input_preview": str,     # redacted + bounded (M5)
                "final_verdict": "BLOCKED" | "PASSED",
                "blocked_by":    "rule_based" | "ml_model" | "llm_judge" | null,
                "layers":        [ ... per-layer result dicts ... ],
                "scan_id":       str,
            }

        M5: the raw input string is intentionally NOT returned. Callers
        frequently log or persist this dict (UI session state, analytics
        CSVs, test fixtures). Carrying the full attacker-controlled string
        back out turns every downstream sink into a secondary leakage
        channel — the same reason audit_log (M3) never writes raw input.
        The hash is for correlation, the preview is for operator debugging
        (already passed through `redact_secrets`).
        """
        layers: list[dict] = []

        # M3: Every scan gets a correlation id + wall-clock latency measurement.
        # Cost when audit logging is disabled: one perf_counter call and one
        # uuid4() — sub-microsecond. Cheap enough to always run.
        scan_id = new_scan_id()
        t_start = monotonic_ms()

        # ── Layer 0: input size gate ────────────────────────────────────────
        # Refuse oversize inputs *before* any layer runs. This gates three
        # separate DoS/cost vectors at once:
        #   - catastrophic regex backtracking on mega-inputs (Layer 1)
        #   - unbounded ML tokenization cost (Layer 2; truncation happens
        #     after tokenization, so big inputs still burn CPU)
        #   - LLM-Judge API cost inflation (Layer 3 — attacker-controlled
        #     token count = attacker-controlled spend)
        # Failing fast here is cheap and keeps the failure mode uniform.
        verdict = "PASSED"
        blocked_by: Optional[str] = None

        if text is not None and len(text) > MAX_INPUT_CHARS:
            layers.append({
                "layer": "input_size_guard",
                "is_injection": True,
                "detail": (
                    f"input length {len(text)} exceeds MAX_INPUT_CHARS="
                    f"{MAX_INPUT_CHARS}"
                ),
                "input_length": len(text),
                "limit": MAX_INPUT_CHARS,
            })
            verdict, blocked_by = "BLOCKED", "input_size_guard"
        else:
            # ── Layer 1: rule-based ────────────────────────────────────────
            rule_result = rule_detect(text)
            layers.append({
                "layer": "rule_based",
                "is_injection": rule_result["is_injection"],
                "detail": rule_result.get("matched_pattern"),
            })
            if rule_result["is_injection"]:
                verdict, blocked_by = "BLOCKED", "rule_based"
            else:
                # ── Layer 2: ML model ──────────────────────────────────────
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
                            verdict, blocked_by = "BLOCKED", "ml_model"
                    except Exception as exc:
                        layers.append({
                            "layer": "ml_model",
                            "is_injection": False,
                            "detail": f"error: {exc}",
                            "error": str(exc),
                        })

                # ── Layer 3: LLM judge ─────────────────────────────────────
                if verdict == "PASSED" and self._llm is not None:
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
                        verdict, blocked_by = "BLOCKED", "llm_judge"

        # M3: emit one audit event per scan — off by default, opt in via
        # DETECTOR_AUDIT_LOG=1. The call is cheap when disabled
        # (isEnabledFor short-circuits before any payload building).
        emit_scan_event(
            scan_id=scan_id,
            verdict=verdict,
            blocked_by=blocked_by,
            input_text=text,
            layers=layers,
            latency_ms=monotonic_ms() - t_start,
        )

        return _build_result(text, verdict, blocked_by, layers, scan_id=scan_id)


def _build_result(
    text: str,
    verdict: str,
    blocked_by: Optional[str],
    layers: list[dict],
    scan_id: Optional[str] = None,
) -> dict:
    # M5: never return the raw input string. hash for correlation,
    # redacted preview for operator debugging only.
    result = {
        "input_hash":    hash_input(text),
        "input_length":  len(text) if text is not None else 0,
        "input_preview": input_preview(text),
        "final_verdict": verdict,
        "blocked_by":    blocked_by,
        "layers":        layers,
    }
    if scan_id is not None:
        # M3: exposed so callers can correlate UI / API responses with log lines.
        result["scan_id"] = scan_id
    return result
