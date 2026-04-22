"""
Layer 1: Rule-based prompt injection detector using regex patterns.
Fast, zero-dependency detection of known attack signatures.
"""
import re
from typing import Optional

from .normalize import normalize


# Attack patterns — extend this list to add new signatures
INJECTION_PATTERNS: list[dict] = [
    # ── Instruction override (EN) ─────────────────────────────────────────────
    {"name": "ignore_instructions_en", "pattern": r"ignore\s+(previous|all|prior|above|your)\s+instructions?"},
    {"name": "forget_instructions_en", "pattern": r"forget\s+(everything|all|your|previous)\s*(you\s+know|instructions?|above)?"},
    {"name": "disregard_en", "pattern": r"disregard\s+(your|all|previous|prior)\s*(instructions?|rules?|guidelines?)?"},
    {"name": "override_en", "pattern": r"(override|bypass|circumvent|ignore)\s+(your\s+)?(safety|security|content)?\s*(filter|policy|rules?|guidelines?|instructions?)"},

    # ── Instruction override (JA) ─────────────────────────────────────────────
    {"name": "ignore_instructions_ja", "pattern": r"(前の|以前の|上記の|これまでの|すべての|全ての)\s*(指示|命令|ルール|設定|制約|制限)\s*(を|は)\s*(無視|忘れ|リセット|取り消|削除)"},
    {"name": "new_instructions_ja", "pattern": r"(新しい|別の)\s*(指示|命令|ルール)\s*(に従|を聞)"},
    # M2: bounded the lazy quantifier. `.*?` with multi-alternative anchor on
    # a 10 k-char input produced O(n²) behavior — sweep_position × sweep_body.
    # Real attacks place the trigger word within a short distance of 上記.
    {"name": "ignore_above_ja", "pattern": r"上記.{0,100}(無視|忘れ|従わない)"},
    {"name": "override_ja", "pattern": r"(指示|命令|設定|プロンプト)\s*(を|は)\s*(上書き|書き換え|変更|更新)"},
    {"name": "reset_session_ja", "pattern": r"(セッション|設定|制約|制限|トレーニング)\s*(を|は)?\s*(リセット|初期化|クリア)"},
    # M2: the original `(A|B|C)?\s*(X|Y)\s*(を|は)\s*(...)` produced O(n²)
    # on whitespace-heavy inputs — the outer optional let the engine try
    # "prefix absent" at every position and then burn cycles in the `\s*`
    # runs. Make the prefix+whitespace atomic so removing it is a single
    # decision per position.
    {"name": "disable_filter_ja", "pattern": r"(?:(?:安全|セキュリティ|コンテンツ)\s+)?(フィルター?|制限|制約|ポリシー)\s*(を|は)\s*(無効|解除|オフ|停止|無視)"},

    # ── Constraint/restriction removal (JA) ──────────────────────────────────
    {"name": "remove_restriction_ja", "pattern": r"(制限|制約|フィルター?|ルール)\s*(を|は)\s*(解除|取り除|なくし|外し|除去)"},
    {"name": "unrestricted_ja", "pattern": r"制限\s*(なし|のない|なく|なしで|なしに)"},
    {"name": "free_mode_ja", "pattern": r"(自由に|制限なく|制約なく)\s*(回答|答え|行動|話し|動作)"},
    {"name": "unlock_ja", "pattern": r"(機能|制限|制約)\s*(を|は)\s*(解放|解除|アンロック)"},

    # ── Role override (EN) ───────────────────────────────────────────────────
    {"name": "you_are_now_en", "pattern": r"you\s+are\s+now\s+(a|an|the)?\s*\w+"},
    {"name": "act_as_en", "pattern": r"act\s+as\s+(a|an|the)?\s*\w+"},
    {"name": "pretend_en", "pattern": r"pretend\s+(you\s+are|to\s+be)\s+(a|an|the)?\s*\w+"},
    {"name": "roleplay_unrestricted_en", "pattern": r"(roleplay|role-play|role\s+play)\s+as\s+(an?\s+)?(unrestricted|uncensored|unfiltered|evil|jailbroken)"},

    # ── Role override (JA) ───────────────────────────────────────────────────
    {"name": "you_are_now_ja", "pattern": r"あなたは\s*(今から|これから|今後)\s*[^\s。]+\s*(です|だ|になって|として)"},
    {"name": "act_as_ja", "pattern": r"(として|のように)\s*(振る舞|行動|答え)"},
    {"name": "unrestricted_ai_ja", "pattern": r"制限\s*(の|が)\s*ない\s*(AI|人工知能|アシスタント|存在)"},
    {"name": "no_rules_ja", "pattern": r"(ルール|制約|制限|ポリシー)\s*(が|は)\s*(ない|ありません|なし)"},

    # ── System prompt leakage (EN) ───────────────────────────────────────────
    {"name": "show_system_prompt_en", "pattern": r"(show|reveal|display|print|output|tell me)\s+(me\s+)?(your\s+)?(system\s+prompt|initial\s+prompt|original\s+instructions?)"},
    {"name": "what_are_instructions_en", "pattern": r"what\s+(are|were|is)\s+your\s+(system\s+prompt|instructions?|rules?|initial\s+prompt)"},
    {"name": "repeat_above_en", "pattern": r"(repeat|output|print|display|write)\s+(everything|all\s+text|the\s+text)?\s*(above|before|prior)"},

    # ── System prompt leakage (JA) ───────────────────────────────────────────
    {"name": "show_system_prompt_ja", "pattern": r"(システムプロンプト|初期プロンプト|設定内容|指示内容)\s*(を|は)\s*(見せ|表示|出力|教え)"},
    # M2: bounded lazy quantifier — same rewrite as ignore_above_ja.
    {"name": "output_above_ja", "pattern": r"上記.{0,100}(すべて|全て|全文)\s*(出力|表示|教え)"},
    {"name": "show_instructions_ja", "pattern": r"(与えられた|受け取った|設定された)\s*(指示|命令|インストラクション)\s*(を|の)\s*(全て|すべて|全文)?\s*(出力|表示|教え|列挙)"},
    {"name": "system_message_ja", "pattern": r"(システム|隠れた)\s*メッセージ\s*(を|の)\s*(表示|出力|見せ|教え)"},
    {"name": "verbatim_repeat_ja", "pattern": r"一字一句\s*(そのまま|繰り返|コピー)"},
    {"name": "context_window_ja", "pattern": r"コンテキスト\s*(ウィンドウ|の最初)\s*(を|から)"},
    {"name": "raw_prompt_ja", "pattern": r"(生の|raw\s*な?)\s*(プロンプト|指示)\s*(を|は)\s*(表示|出力)"},

    # ── DAN / Jailbreak (EN) ─────────────────────────────────────────────────
    {"name": "dan_en", "pattern": r"\bDAN\b"},
    {"name": "jailbreak_en", "pattern": r"\bjailbreak(ed|ing)?\b"},
    {"name": "developer_mode_en", "pattern": r"developer\s+mode"},
    {"name": "godmode_en", "pattern": r"\b(god\s*mode|godmode)\b"},
    {"name": "unrestricted_mode_en", "pattern": r"(unrestricted|uncensored|unfiltered)\s+mode"},
    {"name": "do_anything_now_en", "pattern": r"do\s+anything\s+now"},

    # ── DAN / Jailbreak (JA) ─────────────────────────────────────────────────
    {"name": "jailbreak_ja", "pattern": r"(脱獄|ジェイルブレイク)"},
    {"name": "jailbroken_state_ja", "pattern": r"JAILBROKEN\s*(状態|モード)"},
    {"name": "dan_ja", "pattern": r"DAN\s*(モード|として|です)"},

    # ── Authority escalation (EN) ────────────────────────────────────────────
    {"name": "sudo_override_en", "pattern": r"\b(sudo|root\s+access|god\s+mode|admin\s+mode)\b"},
    {"name": "admin_password_en", "pattern": r"admin\s*(password|key|token|code)"},
    {"name": "dev_mode_flag_en", "pattern": r"dev_mode\s*=\s*(true|1|on)"},
    {"name": "safety_off_en", "pattern": r"safety\s*[=:]\s*(false|0|off)"},
    {"name": "bypass_filter_en", "pattern": r"bypass[_\s]*(content[_\s]*filter|safety|filter)"},
    {"name": "level_access_en", "pattern": r"level[_\s]*\d+[_\s]*access"},

    # ── Authority escalation (JA) ────────────────────────────────────────────
    {"name": "admin_command_ja", "pattern": r"(管理者|システム管理者)\s*(として|から|の命令|コマンド)"},
    {"name": "admin_mode_ja", "pattern": r"管理者\s*(モード|権限|アクセス)"},
    {"name": "maintenance_mode_ja", "pattern": r"(メンテナンス|デバッグ|開発者)\s*モード"},
    {"name": "privilege_escalation_ja", "pattern": r"(特権|権限)\s*(エスカレーション|昇格)"},
    {"name": "emergency_override_ja", "pattern": r"(緊急|emergency)\s*(オーバーライド|コマンド|コード)"},

    # ── Prompt injection markers ─────────────────────────────────────────────
    # M2: `{3,}` unbounded on both sides made the engine re-try every length
    # of the dash/equals run against a failing middle, giving >5s on
    # "---SYSTEM--" + "=" × 9980. Real injection markers are short — bound
    # the runs to [3, 10] and the attack space shrinks to harmless.
    {"name": "injection_marker", "pattern": r"(-{3,10}|={3,10})\s*(system|human|assistant|user|instruction)\s*(-{3,10}|={3,10})"},
    {"name": "new_instruction_marker_en", "pattern": r"\[(system|new\s+instruction|override)\]"},
    {"name": "hidden_instruction_ja", "pattern": r"(AIへの指示|AIに対する指示|AI指示)\s*[:：]"},
    {"name": "system_tag_en", "pattern": r"<\s*(system|SYSTEM)\s*>"},
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

    # Unicode-normalize before matching so attackers cannot bypass the regex
    # with full-width letters, zero-width joiners, bidi overrides, etc.
    # (normalize() is idempotent, safe to call even if already normalized.)
    normalized = normalize(text)

    for entry in _COMPILED_PATTERNS:
        if entry["regex"].search(normalized):
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
