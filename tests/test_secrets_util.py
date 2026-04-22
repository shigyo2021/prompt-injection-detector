"""
Tests for src.secrets_util (H2 fix).
"""
import pytest

from src.secrets_util import validate_api_key, resolve_api_key, redact_secrets


# ── validate_api_key ──────────────────────────────────────────────────────

def test_empty_key_invalid():
    ok, msg = validate_api_key("")
    assert ok is False
    assert "empty" in msg.lower()


def test_none_key_invalid():
    ok, _ = validate_api_key(None)
    assert ok is False


def test_too_short_key_invalid():
    ok, msg = validate_api_key("sk-ant-abc")
    assert ok is False
    assert "short" in msg.lower()


def test_wrong_prefix_invalid():
    ok, msg = validate_api_key("foobar-" + "x" * 40, provider="anthropic")
    assert ok is False
    assert "prefix" in msg.lower()


def test_whitespace_in_key_invalid():
    ok, msg = validate_api_key("sk-ant-" + "x" * 20 + " " + "y" * 20)
    assert ok is False
    assert "whitespace" in msg.lower() or "non-printable" in msg.lower()


def test_valid_anthropic_shape():
    ok, _ = validate_api_key("sk-ant-" + "a" * 40)
    assert ok is True


def test_valid_openai_shape():
    ok, _ = validate_api_key("sk-" + "a" * 40, provider="openai")
    assert ok is True


def test_valid_openai_project_key_shape():
    ok, _ = validate_api_key("sk-proj-" + "a" * 40, provider="openai")
    assert ok is True


# ── resolve_api_key ───────────────────────────────────────────────────────

def test_resolve_prefers_explicit_over_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-" + "e" * 40)
    got = resolve_api_key("sk-ant-" + "x" * 40, env_var="ANTHROPIC_API_KEY")
    assert got.endswith("x" * 40)


def test_resolve_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-" + "e" * 40)
    got = resolve_api_key(None, env_var="ANTHROPIC_API_KEY")
    assert got.endswith("e" * 40)


def test_resolve_returns_none_for_invalid_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    got = resolve_api_key("not-a-real-key", env_var="ANTHROPIC_API_KEY")
    assert got is None


def test_resolve_returns_none_when_nothing_set(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert resolve_api_key(None, env_var="ANTHROPIC_API_KEY") is None


# ── redact_secrets ────────────────────────────────────────────────────────

def test_redact_anthropic_key():
    text = "error: bad Authorization: Bearer sk-ant-abcdef1234567890ABCDEF"
    out = redact_secrets(text)
    assert "sk-ant-" not in out or "REDACTED" in out
    assert "***REDACTED***" in out
    assert "abcdef1234567890" not in out


def test_redact_openai_key():
    text = "upstream returned 401 for sk-proj-ABCDEF1234567890abcdef"
    out = redact_secrets(text)
    assert "***REDACTED***" in out
    assert "ABCDEF1234567890" not in out


def test_redact_leaves_other_text_alone():
    text = "connection refused on port 443 — retry later"
    assert redact_secrets(text) == text


def test_redact_is_idempotent():
    text = "sk-ant-" + "a" * 40
    once = redact_secrets(text)
    twice = redact_secrets(once)
    assert once == twice


# ── Integration with LLMJudge constructor ─────────────────────────────────

def test_llm_judge_accepts_explicit_key(monkeypatch):
    from src.llm_judge import LLMJudge
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    judge = LLMJudge(api_key="sk-ant-" + "x" * 40)
    assert judge._api_key == "sk-ant-" + "x" * 40


def test_llm_judge_rejects_bad_shape_key(monkeypatch):
    from src.llm_judge import LLMJudge
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    judge = LLMJudge(api_key="not-a-real-key")
    # Bad-shape key is treated as absent — calling _get_client raises RuntimeError.
    assert judge._api_key is None
    with pytest.raises(RuntimeError, match="No valid Anthropic API key"):
        judge._get_client()
