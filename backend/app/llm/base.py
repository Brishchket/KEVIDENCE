"""
base.py — Abstract LLM client interface.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class LLMClient(ABC):
    """Interface that all LLM providers must implement."""

    @abstractmethod
    async def generate(self, system: str, user: str) -> str:
        """
        Generate a completion given a system prompt and user prompt.
        Returns the text response.
        """
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider identifier (e.g. 'gemini', 'openai')."""
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Return the model identifier."""
        ...
