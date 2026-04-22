"""
M3: Structured audit logging for detection decisions.

What this solves
----------------
Before this module, a blocked attack left no trace: the verdict showed on
the Streamlit UI for one session and then evaporated. That's fine for a
demo but unusable for:

  - incident reconstruction ("show me every time we blocked this attacker")
  - base-rate analysis ("which layer catches the most? which catches
    nothing?")
  - SIEM integration (Splunk / Elasticsearch / CloudWatch Logs Insights
    all speak JSON natively)

Design choices
--------------
1. **Single-line JSON** per event. Machine-parseable by every log pipeline
   without a custom plugin. Human-readable with `jq`.

2. **No raw input.** The input string may itself contain stolen secrets,
   other users' system prompts, PII, etc. Logging it verbatim would turn
   the audit log into the next leakage channel. We store:
     - `input_hash`   : SHA-256 (first 16 hex chars) — enough to correlate
                        repeat offenders without reversibility
     - `input_length` : raw length
     - `input_preview`: first N chars, passed through the H2
                        `redact_secrets` scrubber to strip any API keys
       N defaults to 80 and is tunable via DETECTOR_AUDIT_LOG_PREVIEW_CHARS.

3. **UTC, ISO 8601.** The single most common cause of "I can't reproduce
   this incident" is timezone mismatch between the worker, the log
   pipeline, and the analyst. Pin one answer: UTC.

4. **Opt-in via env var.** Logging to stderr by default when
   DETECTOR_AUDIT_LOG=1 is set; optional file via
   DETECTOR_AUDIT_LOG_PATH. Off entirely otherwise — tests and local
   demos don't need noisy output, and forcing it on would surprise
   existing embedders.

5. **No external dependency.** stdlib `logging` + `json`. Portfolio
   code stays portable.

What this does NOT do
---------------------
This is not a tamper-proof audit chain. Production systems should:
  - stream to a write-once backend (S3 Object Lock, append-only DB)
  - hash-chain adjacent events so deletion is detectable
  - replicate off-host before the worker can touch the file again
These are intentionally out of scope for a portfolio module — but the
contract below (`emit_scan_event`) is stable enough that a real
implementation could swap the sink without touching callers.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .secrets_util import redact_secrets


_LOGGER_NAME = "prompt_injection_detector.audit"


def _utc_now_iso() -> str:
    """ISO 8601 with Z suffix. Pinned to UTC on purpose — see module docstring."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class _JsonFormatter(logging.Formatter):
    """Emits one JSON object per log record.

    The record's `msg` is expected to already be a dict (we build it in
    `emit_scan_event`). If some caller uses plain logger.info("text"),
    we still emit a well-formed event with `message` set."""

    def format(self, record: logging.LogRecord) -> str:
        if isinstance(record.msg, dict):
            payload = dict(record.msg)
        else:
            payload = {"message": record.getMessage()}
        payload.setdefault("level", record.levelname)
        payload.setdefault("ts", _utc_now_iso())
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _configure_once(logger: logging.Logger) -> None:
    """Attach exactly one JSON handler. Idempotent — safe to call repeatedly."""
    if any(getattr(h, "_is_audit_handler", False) for h in logger.handlers):
        return

    path = os.environ.get("DETECTOR_AUDIT_LOG_PATH", "").strip()
    if path:
        # Append mode, line-buffered. If this fails (permissions, missing
        # dir) we fall back to stderr rather than crashing the caller —
        # audit logging should not take down detection.
        try:
            handler: logging.Handler = logging.FileHandler(
                path, mode="a", encoding="utf-8"
            )
        except OSError as exc:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(_JsonFormatter())
            handler._is_audit_handler = True  # type: ignore[attr-defined]
            logger.addHandler(handler)
            logger.error({
                "event": "audit_log_init_error",
                "error": str(exc),
                "path": path,
                "fallback": "stderr",
            })
            return
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(_JsonFormatter())
    handler._is_audit_handler = True  # type: ignore[attr-defined]
    logger.addHandler(handler)


def get_audit_logger() -> logging.Logger:
    """
    Return the audit logger, wiring handlers on first call.

    If DETECTOR_AUDIT_LOG is not set, the returned logger has its level
    raised above CRITICAL so calls are effectively no-ops. That keeps
    the hot path free of both string formatting and I/O when logging is
    off — important because `emit_scan_event` runs on every scan.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    # Don't propagate to root — audit events should not leak into whatever
    # the embedding app's root logger is doing.
    logger.propagate = False

    if _env_flag("DETECTOR_AUDIT_LOG"):
        _configure_once(logger)
        logger.setLevel(logging.INFO)
    else:
        # No handlers, level above CRITICAL → emits are cheap no-ops.
        logger.setLevel(logging.CRITICAL + 1)

    return logger


# ── helpers for callers ────────────────────────────────────────────────────

def hash_input(text: Optional[str]) -> str:
    """SHA-256 first 16 hex chars — correlates repeat inputs without storing them."""
    if text is None:
        return "none"
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def input_preview(text: Optional[str]) -> str:
    """
    Short, key-redacted preview of the input.

    Length is controlled by DETECTOR_AUDIT_LOG_PREVIEW_CHARS (default 80).
    Setting it to 0 disables the preview entirely — useful for strict
    privacy environments where even a fragment is too much.
    """
    if text is None:
        return ""
    try:
        n = int(os.environ.get("DETECTOR_AUDIT_LOG_PREVIEW_CHARS", "80"))
    except ValueError:
        n = 80
    if n <= 0:
        return ""
    snippet = text[:n]
    return redact_secrets(snippet)


def new_scan_id() -> str:
    """Short correlation id — enough entropy for in-process correlation."""
    return uuid.uuid4().hex[:12]


def emit_scan_event(
    *,
    scan_id: str,
    verdict: str,
    blocked_by: Optional[str],
    input_text: Optional[str],
    layers: list[dict] | None = None,
    latency_ms: Optional[float] = None,
    extra: Optional[dict[str, Any]] = None,
    event: str = "scan",
) -> None:
    """
    Emit one structured scan event.

    Safe to call when logging is disabled — the cost is one dict-build
    and an early-return inside `logger.info`. Callers that need absolute
    minimum overhead can guard with `if logger.isEnabledFor(logging.INFO)`.
    """
    logger = get_audit_logger()
    if not logger.isEnabledFor(logging.INFO):
        return

    payload: dict[str, Any] = {
        "event": event,
        "ts": _utc_now_iso(),
        "scan_id": scan_id,
        "verdict": verdict,
        "blocked_by": blocked_by,
        "input_hash": hash_input(input_text),
        "input_length": len(input_text) if input_text is not None else 0,
        "input_preview": input_preview(input_text),
    }
    if latency_ms is not None:
        payload["latency_ms"] = round(latency_ms, 3)
    if layers is not None:
        # Summarize per-layer outcome — full layer detail can balloon the log
        # line with model output / reasons. Trim to the shape needed for
        # base-rate dashboards.
        payload["layers"] = [
            {
                "layer": layer.get("layer"),
                "is_injection": layer.get("is_injection"),
                "detail": (
                    redact_secrets(str(layer.get("detail")))[:200]
                    if layer.get("detail") is not None else None
                ),
            }
            for layer in layers
        ]
    if extra:
        # Never let extras overwrite core fields — silent overwrites here
        # would let callers tamper with verdict/ts post-hoc.
        reserved = set(payload.keys())
        for k, v in extra.items():
            if k in reserved:
                continue
            payload[k] = v
    logger.info(payload)


def monotonic_ms() -> float:
    """perf_counter in ms — use with start/end pairs to compute latency_ms."""
    return time.perf_counter() * 1000.0
