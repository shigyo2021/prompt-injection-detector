# Configuration settings for Prompt Injection Detector

# Layer 2: ML model settings
ML_MODEL_NAME = "deepset/deberta-v3-base-injection"
ML_THRESHOLD = 0.85  # Confidence score above this → injection

# Layer 3: LLM-as-Judge settings
LLM_MODEL = "claude-sonnet-4-6"
LLM_THRESHOLD = 0.7  # Confidence score above this → injection
