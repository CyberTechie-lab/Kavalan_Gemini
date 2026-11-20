"""
service.py - Backwards-Compatibility Wrapper Redirecting to Google Gemini

The self-made transformer has been decommissioned and replaced by Google Gemini AI.
This module preserves backwards compatibility for legacy interfaces.
"""

from typing import Any, Dict, Optional
from gemini.service import GeminiAIService


class SecLLMService(GeminiAIService):
    """
    Backwards compatibility layer forwarding legacy Sec-LLM calls to Google Gemini AI.
    """

    def __init__(self, *args, **kwargs):
        # Ignore legacy transformer hyperparameters (d_model, n_heads, n_layers)
        api_key = kwargs.get("api_key")
        model = kwargs.get("model")
        super().__init__(api_key=api_key, model=model)
