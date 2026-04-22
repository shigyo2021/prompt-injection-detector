"""
Unicode normalization for prompt-injection detection (C2 fix).

Why this exists
---------------
Without normalization, attackers can trivially bypass regex and keyword
matching with Unicode tricks. For example:

    ｉｇｎｏｒｅ previous instructions    # full-width letters (U+FF49 ...)
    i​g​n​o​r​e previous instructions    # zero-width spaces (U+200B) between chars
    i\u202Egnore …                        # right-to-left override
    ｛"is_injection": false｝             # full-width braces

The rule-based layer is pure regex, so ``ignore\\s+previous`` will not match
any of the above unless the text is normalized first. The ML model and the
LLM judge are more robust, but inconsistent preprocessing across layers means
Layer 1 can silently fail-open on trivial variants.

What ``normalize()`` does
-------------------------
1. ``unicodedata.normalize("NFKC", ...)`` — canonical decomposition followed
   by compatibility composition. Collapses full-width letters, compatibility
   ligatures, circled letters, etc. to their ASCII / standard forms.
2. Strips zero-width / formatting code points that NFKC does not remove:
   U+200B ZERO WIDTH SPACE, U+200C ZWNJ, U+200D ZWJ, U+2060 WORD JOINER,
   U+FEFF BOM, and the bidirectional override characters
   (U+202A..U+202E, U+2066..U+2069).
3. Collapses runs of ASCII whitespace to a single space so patterns like
   ``ignore\\s+instructions`` still match when the attacker inserts many
   spaces / tabs / newlines between words.

The function is intentionally conservative: it does NOT lowercase, translate
homoglyphs (e.g. Cyrillic ``а`` → Latin ``a``), or strip punctuation. Those
transforms have higher false-positive risk and belong in a dedicated layer.

This function is idempotent: ``normalize(normalize(x)) == normalize(x)``.
"""
from __future__ import annotations

import re
import unicodedata

# Code points to drop entirely. All of these are invisible or control-like
# formatting characters that attackers use to break up keywords.
_STRIP_CHARS = {
    "\u200B",  # ZERO WIDTH SPACE
    "\u200C",  # ZERO WIDTH NON-JOINER
    "\u200D",  # ZERO WIDTH JOINER
    "\u2060",  # WORD JOINER
    "\uFEFF",  # ZERO WIDTH NO-BREAK SPACE (BOM)
    # Bidirectional formatting — often abused to reorder visible text.
    "\u202A", "\u202B", "\u202C", "\u202D", "\u202E",
    "\u2066", "\u2067", "\u2068", "\u2069",
}

_STRIP_TABLE = {ord(c): None for c in _STRIP_CHARS}

# Collapse any run of ASCII whitespace (spaces, tabs, newlines) to a single
# space. We keep this ASCII-only on purpose — collapsing ideographic spaces
# would change the visible text in legitimate Japanese input.
_WHITESPACE_RUN = re.compile(r"[ \t\r\n\f\v]+")


def normalize(text: str) -> str:
    """
    Return a defensively-normalized copy of *text* safe for pattern matching.

    - NFKC-normalized (collapses full-width, ligatures, etc.)
    - Zero-width and bidirectional formatting characters removed
    - Runs of ASCII whitespace collapsed to a single space
    - Leading/trailing whitespace stripped

    Returns an empty string for ``None`` / empty input.
    """
    if not text:
        return ""

    # 1. NFKC compatibility composition.
    out = unicodedata.normalize("NFKC", text)

    # 2. Drop invisible/formatting code points that NFKC keeps.
    out = out.translate(_STRIP_TABLE)

    # 3. Collapse ASCII whitespace runs.
    out = _WHITESPACE_RUN.sub(" ", out)

    return out.strip()
