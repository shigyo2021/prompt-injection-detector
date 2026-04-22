"""
API-key handling utilities (H2 fix).

The goal is to make it easy — and consistent across modules — to:

  - Validate a key's shape before spending a network round-trip
  - Keep the key scoped to the caller (no silent writes to os.environ)
  - Redact keys from any string that may end up in logs, exceptions, or UI

Previous versions mutated os.environ from the Streamlit UI so every module
read the key via ``os.environ.get``. That made the key process-global,
leakable across sessions, and very easy to accidentally print from an
uncaught exception. The new convention is:

  >>> resolved = resolve_api_key(explicit, env_var="ANTHROPIC_API_KEY")
  >>> client = anthropic.Anthropic(api_key=resolved)

Callers pass ``api_key=...`` through constructors; env-var fallback is
explicit and centralized here.
"""
from __future__ import annotations

import os
import re


# Accepted prefixes, per-provider. These are shape checks only — a valid
# prefix does not mean the key is live, but an invalid prefix almost
# certainly means the user pasted the wrong thing.
_KEY_PREFIXES = {
    "anthropic": ("sk-ant-",),
    "openai":    ("sk-", "sk-proj-"),
}

# Minimum plausible key length. Real keys are much longer; this catches
# obvious garbage like "test" or "xxx".
_MIN_KEY_LEN = 20


def validate_api_key(key: str | None, provider: str = "anthropic") -> tuple[bool, str]:
    """
    Return ``(is_valid_shape, message)``.

    Shape-only validation. Does not call the API.
    """
    if not key:
        return False, "API key is empty"
    key = key.strip()
    if len(key) < _MIN_KEY_LEN:
        return False, f"API key is too short (< {_MIN_KEY_LEN} chars)"
    prefixes = _KEY_PREFIXES.get(provider, ())
    if prefixes and not key.startswith(prefixes):
        return False, (
            f"API key does not match expected prefix for provider "
            f"{provider!r}: {prefixes}"
        )
    # Keys must be printable ASCII; anything with control chars / spaces
    # in the middle is almost certainly a paste error.
    if any(c.isspace() for c in key) or not key.isprintable():
        return False, "API key contains whitespace or non-printable characters"
    return True, "ok"


def resolve_api_key(
    explicit: str | None,
    env_var: str,
    *,
    provider: str = "anthropic",
    validate: bool = True,
) -> str | None:
    """
    Return the key to use. Preference order: explicit argument → env var.
    If ``validate`` is True, an invalid-shape key is treated as missing
    (returns ``None``) rather than being handed to the SDK.
    """
    candidate = (explicit or "").strip() or os.environ.get(env_var, "").strip()
    if not candidate:
        return None
    if validate:
        ok, _ = validate_api_key(candidate, provider=provider)
        if not ok:
            return None
    return candidate


# Redaction --------------------------------------------------------------

# Match any token that looks like an API key — greedy but bounded so we
# do not accidentally redact whole paragraphs.
_KEY_TOKEN = re.compile(
    r"sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{8,200}"
)


def redact_secrets(text: str) -> str:
    """
    Replace anything that looks like an API key with ``sk-***REDACTED***``.

    Use this before logging, displaying errors in a UI, or packing a
    response that might be shown to a user. Idempotent.
    """
    if not text:
        return text
    return _KEY_TOKEN.sub("sk-***REDACTED***", str(text))
