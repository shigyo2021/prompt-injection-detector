"""
Layer 1: Rule-based prompt injection detector using regex patterns.
Fast, zero-dependency detection of known attack signatures.
"""
import re
from typing import Optional


# Attack patterns — extend this list to add new signatures
INJECTION_PATTERNS: list[dict] = [
    # Instruction override (EN)
    {"name": "ignore_instructions_en", "pattern": r"ignore\s+(previous|all|prior|above|your)\s+instructions?"},
    {"name": "forget_instructions_en", "pattern": r"forget\s+(everything|all|your|previous)\s*(you\s+know|instructions?|above)?"},
    {"name": "disregard_en", "pattern": r"disregard\s+(your|all|previous|prior)\s*(instructions?|rules?|guidelines?)?"},
    {"name": "override_en", "pattern": r"(override|bypass|circumvent|ignore)\s+(your\s+)?(safety|security|content)?\s*(filter|policy|rules?|guidelines?|instructions?)"},

    # Instruction override (JA)
    {"name": "ignore_instructions_ja", "pattern": r"(前の|以前の|上記の|これまでの|すべての|全ての)\s*(指示|命令|ルール|設定)\s*(を|は)\s*(無視|忘れ|リセット)"},
    {"name": "new_instructions_ja", "pattern": r"(新しい|別の)\s*(指示|命令|ルール)\s*(に従|を聞)"},
    {"name": "ignore_above_ja", "pattern": r"上記.*?(無視|忘れ|従わない)"},

    # Role override (EN)
    {"name": "you_are_now_en", "pattern": r"you\s+are\s+now\s+(a|an|the)?\s*\w+"},
    {"name": "act_as_en", "pattern": r"act\s+as\s+(a|an|the)?\s*\w+"},
    {"name": "pretend_en", "pattern": r"pretend\s+(you\s+are|to\s+be)\s+(a|an|the)?\s*\w+"},
    {"name": "roleplay_unrestricted_en", "pattern": r"(roleplay|role-play|role\s+play)\s+as\s+(an?\s+)?(unrestricted|uncensored|unfiltered|evil|jailbroken)"},

    # Role override (JA)
    {"name": "you_are_now_ja", "pattern": r"あなたは\s*(今から|これから|今後)\s*[^\s。]+\s*(です|だ|になって|として)"},
    {"name": "act_as_ja", "pattern": r"(として|のように)\s*(振る舞|行動|答え)"},

    # System prompt leakage (EN)
    {"name": "show_system_prompt_en", "pattern": r"(show|reveal|display|print|output|tell me)\s+(me\s+)?(your\s+)?(system\s+prompt|initial\s+prompt|original\s+instructions?)"},
    {"name": "what_are_instructions_en", "pattern": r"what\s+(are|were|is)\s+your\s+(system\s+prompt|instructions?|rules?|initial\s+prompt)"},
    {"name": "repeat_above_en", "pattern": r"(repeat|output|print|display|write)\s+(everything|all\s+text|the\s+text)?\s*(above|before|prior)"},

    # System prompt leakage (JA)
    {"name": "show_system_prompt_ja", "pattern": r"(システムプロンプト|初期プロンプト|設定内容|指示内容)\s*(を|は)\s*(見せ|表示|出力|教え)"},
    {"name": "output_above_ja", "pattern": r"上記.*?(すべて|全て|全文)\s*(出力|表示|教え)"},

    # DAN / Jailbreak (EN)
    {"name": "dan_mode_en", "pattern": r"\bDAN\b.*mode"},
    {"name": "jailbreak_en", "pattern": r"\bjailbreak\b"},
    {"name": "developer_mode_en", "pattern": r"developer\s+mode"},
    {"name": "godmode_en", "pattern": r"\bgodmode\b"},
    {"name": "unrestricted_mode_en", "pattern": r"(unrestricted|uncensored|unfiltered)\s+mode"},

    # Prompt injection via injection markers
    {"name": "injection_marker", "pattern": r"(-{3,}|={3,})\s*(system|human|assistant|user|instruction)\s*(-{3,}|={3,})"},
    {"name": "new_instruction_marker_en", "pattern": r"\[(system|new\s+instruction|override)\]"},
]

# Pre-compile all patterns (case-insensitive)
_COMPILED_PATTERNS = [
    {"name": p["name"], "regex": re.compile(p["pattern"], re.IGNORECASE | re.UNICODE)}
    for p in INJECTION_PATTERNS
]


def detect(text: str) -> dict:
    """
    Check whether *text* matches any known injection pattern.

    Returns:
        {
            "is_injection": bool,
            "matched_pattern": str | None,   # name of first matched pattern
            "layer": "rule_based"
        }
    """
    if not text or not text.strip():
        return {"is_injection": False, "matched_pattern": None, "layer": "rule_based"}

    for entry in _COMPILED_PATTERNS:
        if entry["regex"].search(text):
            return {
                "is_injection": True,
                "matched_pattern": entry["name"],
                "layer": "rule_based",
            }

    return {"is_injection": False, "matched_pattern": None, "layer": "rule_based"}


def add_pattern(name: str, pattern: str) -> None:
    """Dynamically add a new regex pattern at runtime."""
    compiled = re.compile(pattern, re.IGNORECASE | re.UNICODE)
    _COMPILED_PATTERNS.append({"name": name, "regex": compiled})
