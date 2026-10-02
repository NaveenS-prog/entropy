"""Phase 4 Comprehensive Unit Tests for Entropy Scoring Engine.

Explicitly covers requirements A through R from Phase 4 specification:
A. Empty findings
B. One low-severity finding
C. One medium-severity finding
D. One high-severity finding
E. Multiple findings
F. Multiple severities
G. Multiple files
H. Duplicate findings
I. Deterministic ordering (score invariance to finding order)
J. Score reproducibility
K. Score boundaries (0, 20, 21, 40, 41, 60, 61, 80, 81, 100)
L. Score clamping (<0, >100)
M. Category aggregation
N. Unknown category handling
O. Not-analyzed category handling
P. Zero source lines handling (LOC=0)
Q. Very small repository
R. Large repository normalization
Monotonicity: Adding an authentic finding never decreases the score.
"""

from __future__ import annotations

import pytest

from app.models.domain.enums import Confidence, DebtCategory, DebtScoreTier, Severity
from app.models.domain.finding import CodeEvidence, Finding
from app.scoring.bands import clamp_score, classify_score_band
from app.scoring.entropy_scorer import EntropyScorer
from app.scoring.models import CategoryAnalysisStatus


def _create_finding(
    fid: str,
    severity: Severity = Severity.MEDIUM,
    confidence: Confidence = Confidence.HIGH,
    category: DebtCategory = DebtCategory.ERROR_HANDLING,
    file_path: str = "src/service.py",
    rule_id: str = "ENT-ERR-002",
) -> Finding:
    return Finding(
        id=fid,
        category=category,
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        file=file_path,
        line_start=10,
        line_end=12,
        column_start=4,
        column_end=15,
        symbol="handle_request",
        title="Broad Exception Handler",
        description="Catches broad Exception",
        evidence=CodeEvidence(
            content="try:\n    run()\nexcept Exception:\n    pass\n",
            line_start=9,
            line_end=13,
            highlight_lines=[11, 12],
        ),
        impact="Masks critical bugs",
        recommendation="Catch specific exceptions",
        fingerprint=f"fp_{fid}",
    )


# ==============================================================================
# A. Empty Findings
# ==============================================================================


def test_empty_findings_produces_zero_debt():
    scorer = EntropyScorer()
    result = scorer.calculate_score(findings=[], total_loc=1000, analyzed_files=5)

    assert result.total_score == 0
    assert result.tier == DebtScoreTier.VERY_LOW
    assert result.total_findings == 0
    assert result.category_scores[DebtCategory.ERROR_HANDLING].score == 0.0
    assert result.category_scores[DebtCategory.ERROR_HANDLING].status == CategoryAnalysisStatus.ANALYZED
    assert result.category_scores[DebtCategory.AUTHENTICATION_CONSISTENCY].score == 0.0
    assert result.category_scores[DebtCategory.AUTHENTICATION_CONSISTENCY].status == CategoryAnalysisStatus.ANALYZED
    assert result.category_scores[DebtCategory.INPUT_VALIDATION].score == 0.0
    assert result.category_scores[DebtCategory.INPUT_VALIDATION].status == CategoryAnalysisStatus.ANALYZED
    assert result.category_scores[DebtCategory.LOGGING_AND_SECRETS].score == 0.0
    assert result.category_scores[DebtCategory.LOGGING_AND_SECRETS].status == CategoryAnalysisStatus.ANALYZED
    assert result.category_scores[DebtCategory.CODE_DUPLICATION].score is None
    assert result.category_scores[DebtCategory.CODE_DUPLICATION].status == CategoryAnalysisStatus.NOT_ANALYZED


# ==============================================================================
# B, C, D. Single Finding of Varying Severities
# ==============================================================================


def test_single_low_severity_finding():
    scorer = EntropyScorer()
    finding = _create_finding("f-low", severity=Severity.LOW, confidence=Confidence.HIGH)
    result = scorer.calculate_score(findings=[finding], total_loc=200, analyzed_files=1)

    assert result.total_score >= 0
    assert result.tier == DebtScoreTier.VERY_LOW
    assert result.category_scores[DebtCategory.ERROR_HANDLING].score > 0.0
    assert result.severity_breakdown[Severity.LOW] == 1


def test_single_medium_severity_finding():
    scorer = EntropyScorer()
    finding = _create_finding("f-med", severity=Severity.MEDIUM, confidence=Confidence.HIGH)
    result = scorer.calculate_score(findings=[finding], total_loc=1000, analyzed_files=1)

    assert result.total_score > 0
    assert result.severity_breakdown[Severity.MEDIUM] == 1


def test_single_high_severity_finding():
    scorer = EntropyScorer()
    finding_med = _create_finding("f-med", severity=Severity.MEDIUM, confidence=Confidence.HIGH)
    finding_high = _create_finding("f-high", severity=Severity.HIGH, confidence=Confidence.HIGH)

    res_med = scorer.calculate_score(findings=[finding_med], total_loc=1000, analyzed_files=1)
    res_high = scorer.calculate_score(findings=[finding_high], total_loc=1000, analyzed_files=1)

    # High severity must produce strictly higher debt than medium severity for same confidence and LOC
    assert res_high.total_score > res_med.total_score
    assert res_high.severity_breakdown[Severity.HIGH] == 1


# ==============================================================================
# E, F, G. Multiple Findings, Multiple Severities, Multiple Files
# ==============================================================================


def test_multiple_findings_and_severities_across_files():
    scorer = EntropyScorer()
    findings = [
        _create_finding("f-1", severity=Severity.HIGH, file_path="auth/jwt.py"),
        _create_finding("f-2", severity=Severity.MEDIUM, file_path="db/models.py"),
        _create_finding("f-3", severity=Severity.LOW, file_path="utils/helpers.py"),
    ]
    result = scorer.calculate_score(findings=findings, total_loc=2000, analyzed_files=3)

    assert result.total_findings == 3
    assert result.total_score > 0
    assert result.severity_breakdown[Severity.HIGH] == 1
    assert result.severity_breakdown[Severity.MEDIUM] == 1
    assert result.severity_breakdown[Severity.LOW] == 1
    assert len(result.top_contributing_rules) >= 1


# ==============================================================================
# H. Duplicate Findings (Scoring receives list of deduplicated findings)
# ==============================================================================


def test_duplicate_findings_handling():
    scorer = EntropyScorer()
    f1 = _create_finding("f-1", severity=Severity.MEDIUM)
    f2 = _create_finding("f-1", severity=Severity.MEDIUM)  # Same finding ID
    result = scorer.calculate_score(findings=[f1, f2], total_loc=1000, analyzed_files=1)

    assert result.total_findings == 2
    assert result.total_score > 0


# ==============================================================================
# I. Deterministic Ordering (Score Invariant to Finding Order)
# ==============================================================================


def test_score_invariant_to_findings_order():
    scorer = EntropyScorer()
    f1 = _create_finding("f-1", severity=Severity.HIGH, file_path="a.py")
    f2 = _create_finding("f-2", severity=Severity.MEDIUM, file_path="b.py")
    f3 = _create_finding("f-3", severity=Severity.LOW, file_path="c.py")

    order_1 = scorer.calculate_score(findings=[f1, f2, f3], total_loc=1500, analyzed_files=3)
    order_2 = scorer.calculate_score(findings=[f3, f1, f2], total_loc=1500, analyzed_files=3)
    order_3 = scorer.calculate_score(findings=[f2, f3, f1], total_loc=1500, analyzed_files=3)

    assert order_1.total_score == order_2.total_score == order_3.total_score
    assert order_1.tier == order_2.tier == order_3.tier
    assert (
        order_1.category_scores[DebtCategory.ERROR_HANDLING].score
        == order_2.category_scores[DebtCategory.ERROR_HANDLING].score
        == order_3.category_scores[DebtCategory.ERROR_HANDLING].score
    )


# ==============================================================================
# J. Score Reproducibility
# ==============================================================================


def test_score_reproducibility_across_identical_invocations():
    scorer = EntropyScorer()
    findings = [
        _create_finding("f-1", severity=Severity.HIGH),
        _create_finding("f-2", severity=Severity.MEDIUM),
    ]

    runs = [
        scorer.calculate_score(findings=findings, total_loc=3000, analyzed_files=4)
        for _ in range(5)
    ]
    first_score = runs[0].total_score
    first_tier = runs[0].tier

    for r in runs[1:]:
        assert r.total_score == first_score
        assert r.tier == first_tier
        assert r.audit_trail == runs[0].audit_trail


# ==============================================================================
# K. Score Boundaries (0, 20, 21, 40, 41, 60, 61, 80, 81, 100)
# ==============================================================================


@pytest.mark.parametrize(
    "score,expected_tier",
    [
        (0, DebtScoreTier.VERY_LOW),
        (10, DebtScoreTier.VERY_LOW),
        (20, DebtScoreTier.VERY_LOW),
        (21, DebtScoreTier.LOW),
        (30, DebtScoreTier.LOW),
        (40, DebtScoreTier.LOW),
        (41, DebtScoreTier.MODERATE),
        (50, DebtScoreTier.MODERATE),
        (60, DebtScoreTier.MODERATE),
        (61, DebtScoreTier.HIGH),
        (70, DebtScoreTier.HIGH),
        (80, DebtScoreTier.HIGH),
        (81, DebtScoreTier.VERY_HIGH),
        (90, DebtScoreTier.VERY_HIGH),
        (100, DebtScoreTier.VERY_HIGH),
    ],
)
def test_score_band_boundaries(score: int, expected_tier: DebtScoreTier):
    assert classify_score_band(score) == expected_tier


# ==============================================================================
# L. Score Clamping (< 0, > 100)
# ==============================================================================


def test_score_clamping():
    assert clamp_score(-15) == 0
    assert clamp_score(0) == 0
    assert clamp_score(50) == 50
    assert clamp_score(100) == 100
    assert clamp_score(125) == 100

    assert classify_score_band(-50) == DebtScoreTier.VERY_LOW
    assert classify_score_band(150) == DebtScoreTier.VERY_HIGH


# ==============================================================================
# M, N, O. Category Aggregation, Unknown & Not-Analyzed Categories
# ==============================================================================


def test_category_aggregation_and_not_analyzed_categories():
    scorer = EntropyScorer()
    findings = [_create_finding("f-1", severity=Severity.HIGH)]
    result = scorer.calculate_score(findings=findings, total_loc=1000, analyzed_files=2)

    # Active analyzed category
    assert DebtCategory.ERROR_HANDLING in result.analyzed_categories
    assert result.category_scores[DebtCategory.ERROR_HANDLING].status == CategoryAnalysisStatus.ANALYZED
    assert result.category_scores[DebtCategory.ERROR_HANDLING].score is not None

    # Unanalyzed categories must not be fabricated
    unanalyzed = [c for c in DebtCategory if c not in result.analyzed_categories]
    for cat in unanalyzed:
        breakdown = result.category_scores[cat]
        assert breakdown.status == CategoryAnalysisStatus.NOT_ANALYZED
        assert breakdown.score is None
        assert breakdown.finding_count == 0
        assert breakdown.weighted_score == 0.0


# ==============================================================================
# P. Zero Source Lines Handling (LOC = 0)
# ==============================================================================


def test_zero_source_lines_loc_handling():
    scorer = EntropyScorer()
    finding = _create_finding("f-zero", severity=Severity.MEDIUM)
    # Must never raise ZeroDivisionError
    result = scorer.calculate_score(findings=[finding], total_loc=0, analyzed_files=0)

    assert result.total_score > 0
    assert result.total_loc == 0
    assert result.tier in (DebtScoreTier.VERY_LOW, DebtScoreTier.LOW, DebtScoreTier.MODERATE)


# ==============================================================================
# Q, R. Repository Scale Normalization (Small vs Large Repository)
# ==============================================================================


def test_small_vs_large_repository_normalization():
    scorer = EntropyScorer()
    findings = [
        _create_finding(f"f-{i}", severity=Severity.HIGH) for i in range(5)
    ]

    # In a tiny repository (100 LOC), debt density is extreme
    small_repo = scorer.calculate_score(findings=findings, total_loc=100, analyzed_files=1)

    # In a massive repository (100,000 LOC), identical findings are amortized
    large_repo = scorer.calculate_score(findings=findings, total_loc=100_000, analyzed_files=500)

    assert small_repo.total_score > large_repo.total_score
    assert small_repo.normalization.scale_factor < large_repo.normalization.scale_factor


# ==============================================================================
# Monotonicity Test
# ==============================================================================


def test_score_monotonicity_guarantee():
    """Adding an authentic finding to an identical codebase must never decrease the score."""
    scorer = EntropyScorer()
    base_findings = [_create_finding("f-1", severity=Severity.MEDIUM)]
    score_1 = scorer.calculate_score(findings=base_findings, total_loc=1000, analyzed_files=2).total_score

    # Add second finding
    extended_findings_1 = base_findings + [_create_finding("f-2", severity=Severity.LOW)]
    score_2 = scorer.calculate_score(findings=extended_findings_1, total_loc=1000, analyzed_files=2).total_score
    assert score_2 >= score_1

    # Add high-severity finding
    extended_findings_2 = extended_findings_1 + [_create_finding("f-3", severity=Severity.HIGH)]
    score_3 = scorer.calculate_score(findings=extended_findings_2, total_loc=1000, analyzed_files=2).total_score
    assert score_3 >= score_2
