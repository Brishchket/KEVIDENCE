"""
base.py — Abstract interface for PhantomPatch scoring models.

All scoring models must implement ScoringModel.score().
The registry maps model name strings to model instances.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ScoringModel(ABC):
    """Abstract base class for all priority scoring models."""

    #: Human-readable name (matches the registry key and SCORE_MODEL env var)
    name: str
    #: Semantic version string stored alongside each scored CVE
    version: str

    @abstractmethod
    def score(self, record: dict[str, Any]) -> dict[str, Any]:
        """
        Compute priority information for *record* and return an enriched copy.

        The returned dict MUST include at minimum:
          - priority_score:     float in [0.0, 1.0]
          - priority_label:     one of CRITICAL / HIGH / MEDIUM / LOW
          - priority_breakdown: dict with at least "components" list
          - missing_signals:    list[str]
          - reasons:            list[str]
          - score_model:        str  (== self.name)
          - score_version:      str  (== self.version)

        The input dict MUST NOT be mutated.
        """

    def __call__(self, record: dict[str, Any]) -> dict[str, Any]:
        return self.score(record)
