"""
anthropic.py — Anthropic Claude LLM provider.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.config import ANTHROPIC_API_KEY, ANTHROPIC_MODEL, LLM_TEMPERATURE
from app.llm.base import LLMClient

logger = logging.getLogger(__name__)


class AnthropicClient(LLMClient):
    """Anthropic Claude API client."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self._api_key = api_key or ANTHROPIC_API_KEY
        self._model = model or ANTHROPIC_MODEL
        if not self._api_key:
            raise ValueError("ANTHROPIC_API_KEY is required for the Anthropic provider")

    @property
    def provider_name(self) -> str:
        return "anthropic"

    @property
    def model_name(self) -> str:
        return self._model

    async def generate(self, system: str, user: str) -> str:
        try:
            import anthropic
        except ImportError:
            raise ImportError("Install anthropic: pip install anthropic")

        client = anthropic.Anthropic(api_key=self._api_key)

        def _call():
            try:
                response = client.messages.create(
                    model=self._model,
                    max_tokens=500,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                    temperature=LLM_TEMPERATURE,
                )
            except TypeError:
                response = client.messages.create(
                    model=self._model,
                    max_tokens=500,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                )
            return response.content[0].text if response.content else ""

        loop = asyncio.get_event_loop()
        for attempt in range(3):
            try:
                result = await loop.run_in_executor(None, _call)
                return result.strip()
            except Exception as exc:
                if "429" in str(exc) or "rate" in str(exc).lower():
                    wait = (attempt + 1) * 15
                    logger.warning("Anthropic rate limit, waiting %ds: %s", wait, exc)
                    await asyncio.sleep(wait)
                else:
                    raise
        raise RuntimeError("Anthropic API failed after 3 retries")
