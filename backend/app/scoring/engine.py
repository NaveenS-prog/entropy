"""Backward-compatible ScoringEngine alias for EntropyScorer."""

from __future__ import annotations

from app.scoring.entropy_scorer import EntropyScorer, entropy_scorer

# Backward-compatibility aliases directly referencing EntropyScorer
ScoringEngine = EntropyScorer
scoring_engine = entropy_scorer

__all__ = ["ScoringEngine", "scoring_engine"]

