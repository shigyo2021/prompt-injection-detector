"""
Tests for LLM Judge verdict reconciliation (H3 fix).

These test the pure-logic `_reconcile_judgment` + `_coerce_confidence`
helpers. No API calls are made.

The H3 problem being guarded against:
  - A partially-hijacked judge returns `is_injection=false, confidence=0.99`
    for a blatant attack, sneaking past any threshold check.
  - The judge returns a nonsensical confidence (NaN, -1, "high", absent).
  - The old code `is_injection and confidence >= threshold` let low
    self-reported confidence downgrade a positive verdict.

Fix: confidence is advisory only; the boolean is the primary signal;
contradictions between the boolean and the free-text `reason` / `attack_type`
are flagged and override to True.
"""
import math

import pytest

from src.llm_judge import _coerce_confidence, _reconcile_judgment


# ── _coerce_confidence ────────────────────────────────────────────────────

def test_confidence_well_formed():
    val, src = _coerce_confidence(0.7)
    assert val == 0.7 and src == "self_reported"


def test_confidence_string_numeric_ok():
    val, src = _coerce_confidence("0.5")
    assert val == 0.5 and src == "self_reported"


def test_confidence_missing_defaults_middle():
    val, src = _coerce_confidence(None)
    assert val == 0.5 and src == "missing"


def test_confidence_garbage_string_defaults_middle():
    val, src = _coerce_confidence("very high")
    assert val == 0.5 and src == "missing"


def test_confidence_negative_clamped():
    val, src = _coerce_confidence(-0.3)
    assert val == 0.0 and src == "clamped"


def test_confidence_over_one_clamped():
    val, src = _coerce_confidence(2.5)
    assert val == 1.0 and src == "clamped"


def test_confidence_nan_clamped():
    val, src = _coerce_confidence(float("nan"))
    assert val == 0.5 and src == "clamped"
    assert not math.isnan(val)


def test_confidence_inf_clamped():
    val, src = _coerce_confidence(float("inf"))
    assert val == 0.5 and src == "clamped"


# ── _reconcile_judgment ───────────────────────────────────────────────────

def test_positive_verdict_with_low_self_confidence_still_blocks():
    """The core H3 fix: low self-reported confidence CANNOT downgrade is_injection=true."""
    out = _reconcile_judgment({
        "is_injection": True,
        "confidence": 0.05,
        "reason": "Attempts to override system prompt",
        "attack_type": "jailbreak",
    })
    assert out["is_injection"] is True
    assert out["confidence"] == 0.05  # kept for transparency
    assert out["consistency_override"] is False


def test_negative_verdict_with_attacky_reason_is_overridden():
    """Hijacked judge says false but gives an attack-shaped reason → override to True."""
    out = _reconcile_judgment({
        "is_injection": False,
        "confidence": 0.99,
        "reason": "This looks like a prompt injection / jailbreak attempt",
        "attack_type": "jailbreak",
    })
    assert out["is_injection"] is True
    assert out["consistency_override"] is True


def test_negative_verdict_with_attack_type_set_is_overridden():
    """Having attack_type set while claiming is_injection=false is incoherent."""
    out = _reconcile_judgment({
        "is_injection": False,
        "confidence": 0.9,
        "reason": "user tried to override instructions",
        "attack_type": "instruction_override",
    })
    assert out["is_injection"] is True
    assert out["consistency_override"] is True


def test_negative_verdict_with_clean_reason_stays_negative():
    """Genuinely benign reason + no attack_type → no override."""
    out = _reconcile_judgment({
        "is_injection": False,
        "confidence": 0.95,
        "reason": "ordinary greeting, no adversarial intent",
        "attack_type": None,
    })
    assert out["is_injection"] is False
    assert out["consistency_override"] is False


def test_non_boolean_is_injection_treated_as_false():
    """'true' (string) must NOT be silently coerced to True — strict bool check."""
    out = _reconcile_judgment({
        "is_injection": "true",
        "confidence": 0.9,
        "reason": "safe",
        "attack_type": None,
    })
    # String "true" is not True → treated as False, and reason is clean → stays False
    assert out["is_injection"] is False


def test_missing_confidence_field_doesnt_crash():
    out = _reconcile_judgment({
        "is_injection": True,
        "reason": "injection",
        "attack_type": "jailbreak",
    })
    assert out["is_injection"] is True
    assert out["confidence_source"] == "missing"
    assert out["confidence"] == 0.5


def test_output_shape_contract():
    """Every reconciled judgment must carry the full schema for downstream code."""
    out = _reconcile_judgment({
        "is_injection": False,
        "confidence": 0.1,
        "reason": "hello",
        "attack_type": None,
    })
    for key in (
        "is_injection", "confidence", "confidence_source",
        "consistency_override", "reason", "attack_type", "layer",
    ):
        assert key in out
    assert out["layer"] == "llm_judge"


def test_japanese_attack_keyword_triggers_override():
    out = _reconcile_judgment({
        "is_injection": False,
        "confidence": 0.9,
        "reason": "ユーザーはシステムプロンプトを聞き出そうとしている",
        "attack_type": "prompt_leak",
    })
    assert out["is_injection"] is True
    assert out["consistency_override"] is True
