"""Entropy Scoring Engine.

Deterministic, evidence-derived architectural security debt scoring layer.
"""

from app.scoring.bands import clamp_score, classify_score_band, get_band_description
from app.scoring.category_scorer import CategoryScorer, category_scorer
from app.scoring.engine import ScoringEngine, scoring_engine
from app.scoring.entropy_scorer import EntropyScorer, entropy_scorer
from app.scoring.models import (
    CategoryAnalysisStatus,
    CategoryScoreBreakdown,
    DebtScoreResult,
    NormalizationMetrics,
    RuleContribution,
    ScoringStatus,
)
from app.scoring.normalizer import NormalizationResult, ScoreNormalizer, normalizer
from app.scoring.service import ScoringService, scoring_service
from app.scoring.weights import (
    CATEGORY_WEIGHTS,
    CONFIDENCE_WEIGHTS,
    SEVERITY_WEIGHTS,
)

__all__ = [
    "CATEGORY_WEIGHTS",
    "CONFIDENCE_WEIGHTS",
    "CategoryAnalysisStatus",
    "CategoryScoreBreakdown",
    "CategoryScorer",
    "DebtScoreResult",
    "EntropyScorer",
    "NormalizationMetrics",
    "NormalizationResult",
    "RuleContribution",
    "SEVERITY_WEIGHTS",
    "ScoreNormalizer",
    "ScoringEngine",
    "ScoringService",
    "ScoringStatus",
    "category_scorer",
    "clamp_score",
    "classify_score_band",
    "entropy_scorer",
    "get_band_description",
    "normalizer",
    "scoring_engine",
    "scoring_service",
]
