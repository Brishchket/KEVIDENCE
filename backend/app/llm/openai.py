"""
openai.py — OpenAI LLM provider.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.config import LLM_TEMPERATURE, OPENAI_API_KEY, OPENAI_MODEL
from app.llm.base import LLMClient

logger = logging.getLogger(__name__)


class OpenAIClient(LLMClient):
    """OpenAI API client."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self._api_key = api_key or OPENAI_API_KEY
        self._model = model or OPENAI_MODEL
        if not self._api_key:
            raise ValueError("OPENAI_API_KEY is required for the OpenAI provider")

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self._model

    async def generate(self, system: str, user: str) -> str:
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("Install openai: pip install openai")

        client = OpenAI(api_key=self._api_key)

        def _call():
            response = client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=LLM_TEMPERATURE,
                max_tokens=500,
            )
            return response.choices[0].message.content or ""

        loop = asyncio.get_event_loop()
        for attempt in range(3):
            try:
                result = await loop.run_in_executor(None, _call)
                return result.strip()
            except Exception as exc:
                if "429" in str(exc) or "rate" in str(exc).lower():
                    wait = (attempt + 1) * 15
                    logger.warning("OpenAI rate limit, waiting %ds: %s", wait, exc)
                    await asyncio.sleep(wait)
                else:
                    raise
        raise RuntimeError("OpenAI API failed after 3 retries")
