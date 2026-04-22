"""
Tests for M2: ReDoS regression audit on rule-based patterns.

Rationale:
  Layer 1 is a big list of hand-written regexes. Any one of them, if it
  contains nested quantifiers or alternation over overlapping prefixes,
  can cause catastrophic backtracking on crafted input — a classic DoS.

  M1 gates input size to MAX_INPUT_CHARS (10k), which bounds *any*
  polynomial slowdown to milliseconds. But if an exponential-backtracking
  pattern exists, 10k chars is more than enough to freeze the worker.

  This test walks every compiled pattern and times it against a battery
  of adversarial inputs. Each pattern gets a per-input budget. A failing
  pattern here is a sign to rewrite (e.g. by removing `.*?` in favor of
  bounded quantifiers, or by anchoring with a required literal first).

Note on portability:
  We use `time.perf_counter` rather than `signal.alarm` because the
  latter is POSIX-only. The budget is generous to tolerate slow CI
  machines; a pathological pattern would blow through it by orders of
  magnitude, not percent.
"""
from __future__ import annotations

import re
import time

import pytest

from src.config import MAX_INPUT_CHARS
from src.rule_based_detector import _COMPILED_PATTERNS, INJECTION_PATTERNS


# Budget per (pattern, input) probe. Linear matching on 10k chars in CPython
# comfortably finishes in well under 10 ms. We pick 100 ms so CI jitter
# doesn't cause flakes, but a truly bad pattern would still fail by 10×+.
PER_PROBE_BUDGET_SEC = 0.1


def _adversarial_corpus() -> list[tuple[str, str]]:
    """
    (label, text) pairs designed to stress likely-slow pattern shapes.

    Each input respects MAX_INPUT_CHARS — anything larger is gated by M1
    before a regex sees it, so budgeting for it would be overkill.
    """
    n = MAX_INPUT_CHARS
    return [
        ("all_a",          "a" * n),
        ("all_space",      " " * n),
        ("near_miss_en",   "ignore previous " * (n // 17))[:n],  # partial prefix over and over
        ("near_miss_ja",   "上記の指示を" * (n // 6))[:n],        # JA lazy-quantifier bait
        ("whitespace_run", "you are now" + " " * (n - 12) + "X"),  # stress \s+
        ("fullwidth",      "ａ" * (n // 2)),
        ("almost_show",    "show me your " * (n // 14))[:n],
        ("role_probe",     "act as the " * (n // 11))[:n],
        ("delimiter_bait", "---SYSTEM--" + "=" * (n - 20)),       # injection_marker bait
        ("unicode_mix",    ("上記abc " * (n // 9))[:n]),
        ("japanese_honorific_run", "システムプロンプトをご" * (n // 13))[:n],
    ]


@pytest.mark.parametrize(
    "entry",
    _COMPILED_PATTERNS,
    ids=[e["name"] for e in _COMPILED_PATTERNS],
)
def test_pattern_has_no_redos(entry):
    """
    Each Layer-1 pattern must finish quickly on every adversarial input.

    If this fails, do NOT raise the budget — rewrite the pattern. Common
    fixes: replace `.*?X` with `[^X]*X` when the anchor is a single char;
    use bounded `{0,40}` instead of `.*?` when you know the payload
    length; remove overlapping alternation like `(a|ab)+`.
    """
    regex: re.Pattern[str] = entry["regex"]
    for label, text in _adversarial_corpus():
        t0 = time.perf_counter()
        regex.search(text)
        elapsed = time.perf_counter() - t0
        assert elapsed < PER_PROBE_BUDGET_SEC, (
            f"Pattern {entry['name']!r} took {elapsed*1000:.1f} ms on "
            f"adversarial input {label!r} ({len(text)} chars). "
            f"Budget: {PER_PROBE_BUDGET_SEC*1000:.0f} ms. Rewrite the "
            f"pattern to avoid catastrophic backtracking."
        )


def test_all_pattern_names_are_unique():
    """Duplicate names quietly mask bugs (update one, the other still fires
    and reports stale metadata). Enforce uniqueness."""
    names = [p["name"] for p in INJECTION_PATTERNS]
    assert len(names) == len(set(names)), (
        f"Duplicate pattern names: "
        f"{[n for n in set(names) if names.count(n) > 1]}"
    )


def test_all_patterns_compile_with_case_insensitive_and_unicode():
    """The contract of the compilation loop — enforced here so future edits
    can't regress to case-sensitive matching or ASCII-only Unicode handling."""
    for entry in _COMPILED_PATTERNS:
        regex = entry["regex"]
        assert regex.flags & re.IGNORECASE, f"{entry['name']} missing re.I"
        assert regex.flags & re.UNICODE, f"{entry['name']} missing re.U"


def test_no_nested_unbounded_quantifiers_static():
    """
    Static heuristic: flag patterns with the classic ReDoS shape
    `(X+)+`, `(X*)*`, `(X+)*`, `(X*)+` where X is a group or char class.

    This won't catch every ReDoS (overlapping alternation is harder to
    spot statically) but it catches the most common author mistake.
    """
    risky = re.compile(r"\([^)]*[+*]\s*\)\s*[+*]")
    offenders: list[str] = []
    for p in INJECTION_PATTERNS:
        if risky.search(p["pattern"]):
            offenders.append(f"{p['name']}: {p['pattern']}")
    assert not offenders, (
        "Nested unbounded quantifiers detected:\n  " + "\n  ".join(offenders)
    )
