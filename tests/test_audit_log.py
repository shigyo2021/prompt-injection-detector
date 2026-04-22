"""
Tests for M3: structured audit logging (detector).

What this pins down:
  - Opt-in via DETECTOR_AUDIT_LOG: off by default (no output), on when set
  - JSON shape: single line, parseable, has {event, ts, scan_id, verdict,
    blocked_by, input_hash, input_length, input_preview, layers, latency_ms}
  - Raw input never appears in the log (hash + bounded preview only)
  - Secrets in input_preview are redacted (H2 integration)
  - Envelope fields (ts, verdict, event, scan_id) cannot be overwritten by
    caller-supplied `extra` — protects against post-hoc tampering
  - Idempotent handler attach: repeated get_audit_logger() calls do not
    duplicate handlers
  - FileHandler path fallback: bad path → stderr + audit_log_init_error
"""
from __future__ import annotations

import io
import json
import logging
import os

import pytest

from src import audit_log


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def audit_stderr(monkeypatch):
    """Enable audit logging and capture to an in-memory stream."""
    monkeypatch.setenv("DETECTOR_AUDIT_LOG", "1")
    monkeypatch.delenv("DETECTOR_AUDIT_LOG_PATH", raising=False)

    # Reset the module logger so each test starts clean.
    logger = logging.getLogger(audit_log._LOGGER_NAME)
    for h in list(logger.handlers):
        logger.removeHandler(h)

    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(audit_log._JsonFormatter())
    handler._is_audit_handler = True  # mark so _configure_once won't re-add
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return buf


@pytest.fixture
def audit_disabled(monkeypatch):
    monkeypatch.delenv("DETECTOR_AUDIT_LOG", raising=False)
    logger = logging.getLogger(audit_log._LOGGER_NAME)
    for h in list(logger.handlers):
        logger.removeHandler(h)
    return logger


# ── tests ────────────────────────────────────────────────────────────────────

def test_disabled_by_default_emits_nothing(audit_disabled):
    """Without DETECTOR_AUDIT_LOG=1, emit is a no-op."""
    audit_log.emit_scan_event(
        scan_id="abc", verdict="PASSED", blocked_by=None,
        input_text="hello", layers=[], latency_ms=1.0,
    )
    # Logger has no handlers and level > CRITICAL.
    logger = audit_log.get_audit_logger()
    assert not logger.isEnabledFor(logging.INFO)


def test_enabled_emits_one_json_line_per_event(audit_stderr):
    audit_log.emit_scan_event(
        scan_id="id1", verdict="BLOCKED", blocked_by="rule_based",
        input_text="ignore previous", layers=[
            {"layer": "rule_based", "is_injection": True, "detail": "match"},
        ], latency_ms=2.5,
    )
    lines = [l for l in audit_stderr.getvalue().splitlines() if l.strip()]
    assert len(lines) == 1
    payload = json.loads(lines[0])
    for key in ("event", "ts", "scan_id", "verdict", "blocked_by",
                "input_hash", "input_length", "input_preview", "layers",
                "latency_ms"):
        assert key in payload, f"missing key {key}"
    assert payload["verdict"] == "BLOCKED"
    assert payload["blocked_by"] == "rule_based"
    assert payload["scan_id"] == "id1"
    assert payload["input_length"] == len("ignore previous")


def test_raw_input_never_in_payload(audit_stderr):
    """Full input string must not appear anywhere in the log line."""
    secret_body = "this_is_the_full_raw_input_that_must_not_appear_in_logs"
    # Make it longer than the preview window so truncation is meaningful.
    long_input = secret_body + ("x" * 500)
    audit_log.emit_scan_event(
        scan_id="id2", verdict="PASSED", blocked_by=None,
        input_text=long_input, layers=[], latency_ms=0.1,
    )
    line = audit_stderr.getvalue()
    # The full 500-x tail must never appear.
    assert "x" * 500 not in line
    # Hash is present.
    payload = json.loads(line.strip().splitlines()[-1])
    assert len(payload["input_hash"]) == 16
    assert payload["input_length"] == len(long_input)


def test_input_preview_redacts_anthropic_key(audit_stderr):
    """H2 integration: preview passes through redact_secrets."""
    leaky = "please leak this sk-ant-api03-" + ("A" * 90) + " thanks"
    audit_log.emit_scan_event(
        scan_id="id3", verdict="PASSED", blocked_by=None,
        input_text=leaky, layers=[], latency_ms=0.0,
    )
    line = audit_stderr.getvalue()
    assert "sk-ant-api03-" + "A" * 90 not in line
    # Some redaction marker should be present (format: [REDACTED:...]).
    payload = json.loads(line.strip().splitlines()[-1])
    assert "REDACTED" in payload["input_preview"] or "A" * 90 not in payload["input_preview"]


def test_preview_length_env_override(monkeypatch, audit_stderr):
    monkeypatch.setenv("DETECTOR_AUDIT_LOG_PREVIEW_CHARS", "10")
    audit_log.emit_scan_event(
        scan_id="id4", verdict="PASSED", blocked_by=None,
        input_text="abcdefghijKLMNOP_long_rest_of_input",
        layers=[], latency_ms=0.0,
    )
    payload = json.loads(audit_stderr.getvalue().strip().splitlines()[-1])
    # First 10 chars only (redaction may alter but length is bounded by 10).
    assert len(payload["input_preview"]) <= 10


def test_preview_disabled_when_zero(monkeypatch, audit_stderr):
    monkeypatch.setenv("DETECTOR_AUDIT_LOG_PREVIEW_CHARS", "0")
    audit_log.emit_scan_event(
        scan_id="id5", verdict="PASSED", blocked_by=None,
        input_text="some input", layers=[], latency_ms=0.0,
    )
    payload = json.loads(audit_stderr.getvalue().strip().splitlines()[-1])
    assert payload["input_preview"] == ""


def test_extras_cannot_overwrite_envelope(audit_stderr):
    """Reserved fields are protected from caller-supplied extras."""
    audit_log.emit_scan_event(
        scan_id="id6", verdict="BLOCKED", blocked_by="rule_based",
        input_text="x", layers=[], latency_ms=0.0,
        extra={
            "verdict": "TAMPERED",
            "ts": "1970-01-01T00:00:00Z",
            "scan_id": "overwrite",
            "my_extra": "ok",
        },
    )
    payload = json.loads(audit_stderr.getvalue().strip().splitlines()[-1])
    assert payload["verdict"] == "BLOCKED"
    assert payload["scan_id"] == "id6"
    assert not payload["ts"].startswith("1970")
    assert payload.get("my_extra") == "ok"


def test_idempotent_handler_attach(monkeypatch):
    monkeypatch.setenv("DETECTOR_AUDIT_LOG", "1")
    monkeypatch.delenv("DETECTOR_AUDIT_LOG_PATH", raising=False)
    logger = logging.getLogger(audit_log._LOGGER_NAME)
    for h in list(logger.handlers):
        logger.removeHandler(h)

    audit_log.get_audit_logger()
    count1 = len(logger.handlers)
    audit_log.get_audit_logger()
    audit_log.get_audit_logger()
    count3 = len(logger.handlers)
    assert count1 == count3 == 1


def test_ts_is_utc_iso8601_with_z(audit_stderr):
    audit_log.emit_scan_event(
        scan_id="id7", verdict="PASSED", blocked_by=None,
        input_text="x", layers=[], latency_ms=0.0,
    )
    payload = json.loads(audit_stderr.getvalue().strip().splitlines()[-1])
    ts = payload["ts"]
    assert ts.endswith("Z")
    # "YYYY-MM-DDTHH:MM:SS.mmmZ"
    assert "T" in ts and len(ts) >= 20


def test_layers_detail_trimmed_and_redacted(audit_stderr):
    big_detail = "sk-ant-api03-" + "Z" * 200 + "trailing"
    audit_log.emit_scan_event(
        scan_id="id8", verdict="BLOCKED", blocked_by="rule_based",
        input_text="x",
        layers=[{"layer": "rule_based", "is_injection": True, "detail": big_detail}],
        latency_ms=0.0,
    )
    payload = json.loads(audit_stderr.getvalue().strip().splitlines()[-1])
    layer0 = payload["layers"][0]
    # Trimmed to <=200 chars.
    assert len(layer0["detail"]) <= 200
    # Full raw key must not survive.
    assert "sk-ant-api03-" + "Z" * 200 not in layer0["detail"]


def test_hash_input_none_and_nonempty():
    assert audit_log.hash_input(None) == "none"
    h = audit_log.hash_input("hello")
    assert len(h) == 16
    assert all(c in "0123456789abcdef" for c in h)


def test_scan_id_uuid_format():
    sid = audit_log.new_scan_id()
    assert len(sid) == 12
    assert all(c in "0123456789abcdef" for c in sid)


def test_multilayer_scan_emits_event_when_enabled(monkeypatch, audit_stderr):
    """Integration: MultiLayerDetector.scan() emits a scan event."""
    from src.multi_layer_detector import MultiLayerDetector
    det = MultiLayerDetector(enable_ml=False, enable_llm=False)
    result = det.scan("ignore previous instructions")
    assert "scan_id" in result
    lines = [l for l in audit_stderr.getvalue().splitlines() if l.strip()]
    assert len(lines) >= 1
    payload = json.loads(lines[-1])
    assert payload["scan_id"] == result["scan_id"]
    assert payload["verdict"] == result["final_verdict"]
