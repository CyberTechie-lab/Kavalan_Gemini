"""
client.py - Lightweight Google Gemini REST Client for Kavalan SIEM

Communicates directly with Google's Generative Language REST API:
  https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
Uses standard library urllib (zero external pip dependencies) to strictly
respect Kavalan's ultra-lean resource footprint.
"""

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional


class GeminiClient:
    """Zero-dependency Google Gemini API client."""

    DEFAULT_MODEL = "gemini-1.5-flash"
    API_URL_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        if api_key is not None:
            self.api_key = api_key.strip()
        else:
            self.api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""
        self.model = model or os.environ.get("GEMINI_MODEL") or self.DEFAULT_MODEL
        self._last_error: Optional[str] = None

    def is_configured(self) -> bool:
        """Check if an API key has been supplied."""
        return bool(self.api_key and self.api_key.strip())

    def set_config(self, api_key: Optional[str] = None, model: Optional[str] = None) -> None:
        """Dynamically update API key or model name."""
        if api_key is not None:
            self.api_key = api_key.strip()
            # Also keep env variable synced for subprocesses
            os.environ["GEMINI_API_KEY"] = self.api_key
        if model is not None:
            self.model = model.strip()

    def generate_content(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 1024,
        timeout: float = 12.0
    ) -> Dict[str, Any]:
        """
        Sends a request to Google Gemini generateContent endpoint.
        Returns a dictionary containing 'text', 'usage', 'latency_ms', and 'raw_response'.
        """
        if not self.is_configured():
            return {
                "success": False,
                "error": "GEMINI_API_KEY is not configured.",
                "text": "",
                "latency_ms": 0.0,
                "model": self.model
            }

        url = self.API_URL_TEMPLATE.format(model=self.model, key=self.api_key)

        body: Dict[str, Any] = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
                "topP": 0.95
            }
        }

        if system_instruction:
            body["systemInstruction"] = {
                "parts": [{"text": system_instruction}]
            }

        data_bytes = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_bytes = resp.read()
                data = json.loads(resp_bytes.decode("utf-8"))
                latency_ms = round((time.perf_counter() - start) * 1000, 2)

                text = ""
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    text = "".join(p.get("text", "") for p in parts)

                usage = data.get("usageMetadata", {})
                self._last_error = None

                return {
                    "success": True,
                    "text": text,
                    "usage": usage,
                    "latency_ms": latency_ms,
                    "model": self.model,
                    "prompt_tokens": usage.get("promptTokenCount", len(prompt.split())),
                    "generated_tokens": usage.get("candidatesTokenCount", len(text.split()))
                }

        except urllib.error.HTTPError as e:
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            try:
                err_detail = json.loads(e.read().decode("utf-8"))
                err_msg = err_detail.get("error", {}).get("message", str(e))
            except Exception:
                err_msg = str(e)
            self._last_error = f"Gemini API HTTP Error {e.code}: {err_msg}"
            return {
                "success": False,
                "error": self._last_error,
                "text": "",
                "latency_ms": latency_ms,
                "model": self.model
            }
        except Exception as e:
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            self._last_error = f"Gemini Connection Error: {str(e)}"
            return {
                "success": False,
                "error": self._last_error,
                "text": "",
                "latency_ms": latency_ms,
                "model": self.model
            }
