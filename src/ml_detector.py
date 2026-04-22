"""
Layer 2: ML-based prompt injection detector.
Uses deepset/deberta-v3-base-injection (HuggingFace) via transformers pipeline.
"""
from __future__ import annotations

from typing import Optional

from .config import ML_MODEL_NAME, ML_THRESHOLD
from .normalize import normalize


class MLDetector:
    """
    Wraps the DeBERTa-based injection classifier.
    The model is loaded once at initialization to avoid repeated disk I/O.
    """

    def __init__(
        self,
        model_name: str = ML_MODEL_NAME,
        threshold: float = ML_THRESHOLD,
    ) -> None:
        self.model_name = model_name
        self.threshold = threshold
        self._pipeline = None  # lazy-load on first use

    def _load_pipeline(self) -> None:
        """Load the HuggingFace pipeline (CPU-safe)."""
        try:
            from transformers import pipeline
            import torch

            device = 0 if torch.cuda.is_available() else -1  # -1 = CPU
            self._pipeline = pipeline(
                "text-classification",
                model=self.model_name,
                device=device,
                truncation=True,
                max_length=512,
            )
        except Exception as exc:
            raise RuntimeError(
                f"Failed to load ML model '{self.model_name}'. "
                "Run `pip install transformers torch` and ensure you have network access "
                "to download the model on first run."
            ) from exc

    def detect(self, text: str) -> dict:
        """
        Classify *text* using the DeBERTa model.

        Returns:
            {
                "is_injection": bool,
                "confidence": float,
                "label": str,          # "INJECTION" or "LEGIT"
                "layer": "ml_model"
            }
        """
        if self._pipeline is None:
            self._load_pipeline()

        # Normalize input so bypass tricks (full-width, zero-width splits,
        # bidi overrides) cannot mask injection signals from the classifier.
        normalized = normalize(text)

        result = self._pipeline(normalized)[0]  # type: ignore[index]
        label: str = result["label"].upper()
        score: float = float(result["score"])

        # Model labels: INJECTION / LEGIT
        is_injection = label == "INJECTION" and score >= self.threshold

        return {
            "is_injection": is_injection,
            "confidence": round(score, 4),
            "label": label,
            "layer": "ml_model",
        }
