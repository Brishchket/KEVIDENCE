"""
scorer.py — Composite priority scoring engine.

Supports pluggable scoring models via a registry.
The active model is determined by the SCORING_MODEL env var.
"""
from __future__ import annotations

import logging
from typing import Any

from app.config import SCORING_MODEL
from app.scoring.base import ScoringModel
from app.scoring.models.weighted_v1 import WeightedV1
from app.scoring.models.vmc_chain import VmcChainV1

logger = logging.getLogger(__name__)

# Model Registry
SCORING_MODELS: dict[str, ScoringModel] = {
    "weighted_v1": WeightedV1(),
    "vmc_chain_v1": VmcChainV1(),
}

def get_scoring_model(model_name: str | None = None) -> ScoringModel:
    """Return the requested scoring model instance, falling back to config."""
    name = model_name or SCORING_MODEL
    if name not in SCORING_MODELS:
        logger.warning("Unknown scoring model '%s', falling back to 'weighted_v1'", name)
        name = "weighted_v1"
    return SCORING_MODELS[name]

def prioritize(record: dict[str, Any], model_name: str | None = None) -> dict[str, Any]:
    """
    Compute and attach priority information using the configured (or requested) model.
    """
    model = get_scoring_model(model_name)
    return model.score(record)
