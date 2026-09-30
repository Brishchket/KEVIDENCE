"""
gemini.py — Google Gemini LLM provider.
Uses the google-genai SDK. Free-tier friendly.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.config import GEMINI_API_KEY, GEMINI_MODEL, LLM_TEMPERATURE
from app.llm.base import LLMClient

logger = logging.getLogger(__name__)


class GeminiClient(LLMClient):
    """Gemini API client using google-genai SDK."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self._api_key = api_key or GEMINI_API_KEY
        self._model = model or GEMINI_MODEL
        if not self._api_key:
            raise ValueError("GEMINI_API_KEY is required for the Gemini provider")

    @property
    def provider_name(self) -> str:
        return "gemini"

    @property
    def model_name(self) -> str:
        return self._model

    async def generate(self, system: str, user: str) -> str:
        try:
            from google import genai
            from google.genai import types
        except ImportError:
            raise ImportError("Install google-genai: pip install google-genai")

        client = genai.Client(api_key=self._api_key)

        config = types.GenerateContentConfig(
            system_instruction=system,
            temperature=LLM_TEMPERATURE,
        )

        # Run in thread pool since the SDK may be synchronous
        def _call():
            response = client.models.generate_content(
                model=self._model,
                contents=user,
                config=config,
            )
            return response.text or ""

        loop = asyncio.get_event_loop()
        for attempt in range(15):
            try:
                result = await loop.run_in_executor(None, _call)
                await asyncio.sleep(4.1) # Throttle to stay under 15 RPM free tier limit
                return result.strip()
            except Exception as exc:
                if "429" in str(exc) or "RESOURCE_EXHAUSTED" in str(exc) or "503" in str(exc) or "UNAVAILABLE" in str(exc):
                    wait = min(60, (attempt + 1) * 10)
                    logger.warning("Gemini API busy/rate limit, waiting %ds: %s", wait, exc)
                    await asyncio.sleep(wait)
                else:
                    raise
        raise RuntimeError("Gemini API failed after 15 retries")
