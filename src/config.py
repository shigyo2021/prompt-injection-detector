# Configuration settings for Prompt Injection Detector

# Layer 2: ML model settings
ML_MODEL_NAME = "deepset/deberta-v3-base-injection"
ML_THRESHOLD = 0.85  # Confidence score above this → injection

# Layer 3: LLM-as-Judge settings
LLM_MODEL = "claude-sonnet-4-6"
LLM_THRESHOLD = 0.7  # Confidence score above this → injection

# ── M1: Input size limits ──────────────────────────────────────────────────
# Hard cap on the length of any single scan. Inputs over this are refused
# before Layers 1/2/3 run — pathological regex backtracking, unbounded ML
# tokenization, and (most importantly) LLM-Judge API cost attacks are all
# gated by this single number. 10 000 chars is well above any real-world
# prompt-injection payload while keeping a single scan cheap.
#
# Production systems with legitimate long inputs (docs, emails) should
# chunk-and-scan instead of raising this limit naively — a larger window
# multiplies the ReDoS attack surface and API spend.
MAX_INPUT_CHARS = 10_000
