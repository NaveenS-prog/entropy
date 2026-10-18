"""Phase 2 Unit Tests: Density-Based Scoring Engine.

Verifies:
1. Property-style test: Same defect density at 500 LOC and 500,000 LOC produces identical (or almost identical) scores.
2. Monotonicity: Adding an authentic finding never decreases the score.
3. Boundedness: Scores are strictly bounded in [0, 100] across any scale.
4. Scale Floor: Repositories below MIN_LOC_FLOOR do not mathematically explode.
5. Audit trail transparency and density formula verification.
"""

from __future__ import annotations

import pytest

from app.models.domain.enums import Confidence, DebtCategory, Severity
from app.models.domain.finding import CodeEvidence, Finding
from app.scoring.entropy_scorer import EntropyScorer
from app.scoring.normalizer import ScoreNormalizer
from app.scoring.weights import (
    DENSITY_SATURATION_FACTOR,
    MIN_LOC_FLOOR,
)


def _make_finding(
    fid: str,
    severity: Severity = Severity.MEDIUM,
    category: DebtCategory = DebtCategory.ERROR_HANDLING,
    file_path: str = "src/app.py",
) -> Finding:
    return Finding(
        id=fid,
        category=category,
        rule_id="ENT-ERR-001",
        severity=severity,
        confidence=Confidence.HIGH,
        file=file_path,
        line_start=10,
        line_end=12,
        column_start=1,
        column_end=10,
        symbol="test_func",
        title="Test Finding",
        description="Test Finding Description",
        evidence=CodeEvidence(
            content="test code",
            line_start=10,
            line_end=12,
            highlight_lines=[10],
        ),
        impact="Test Impact",
        recommendation="Test Fix",
        fingerprint=f"fp_{fid}",
    )


class TestDensityScoringProperties:
    """Property-style tests validating density-based scoring mechanics."""

    def test_property_a_same_density_gives_same_score(self):
        """Property (a): Same defect density at 500 and 500,000 LOC gives (almost) identical score.

        E.g. 1 MEDIUM defect (4.0 pts) per 100 LOC = 40 pts / KLOC.
        At 500 LOC: 5 findings (20.0 raw pts) / 0.5 KLOC = 40 pts / KLOC.
        At 500,000 LOC: 5,000 findings (20,000 raw pts) / 500 KLOC = 40 pts / KLOC.
        """
        scorer = EntropyScorer()

        # 500 LOC with 5 medium findings
        findings_500 = [_make_finding(f"f500_{i}", Severity.MEDIUM) for i in range(5)]
        result_500 = scorer.calculate_score(findings=findings_500, total_loc=500, analyzed_files=5)

        # 5,000 LOC with 50 medium findings
        findings_5k = [_make_finding(f"f5k_{i}", Severity.MEDIUM) for i in range(50)]
        result_5k = scorer.calculate_score(findings=findings_5k, total_loc=5000, analyzed_files=20)

        # 50,000 LOC with 500 medium findings
        findings_50k = [_make_finding(f"f50k_{i}", Severity.MEDIUM) for i in range(500)]
        result_50k = scorer.calculate_score(findings=findings_50k, total_loc=50_000, analyzed_files=100)

        # 500,000 LOC with 5,000 medium findings
        findings_500k = [_make_finding(f"f500k_{i}", Severity.MEDIUM) for i in range(5000)]
        result_500k = scorer.calculate_score(findings=findings_500k, total_loc=500_000, analyzed_files=500)

        # Category scores should be strictly identical because density is exactly 40.0 pts/KLOC
        cat_500 = result_500.category_scores[DebtCategory.ERROR_HANDLING].score
        cat_5k = result_5k.category_scores[DebtCategory.ERROR_HANDLING].score
        cat_50k = result_50k.category_scores[DebtCategory.ERROR_HANDLING].score
        cat_500k = result_500k.category_scores[DebtCategory.ERROR_HANDLING].score

        assert cat_500 is not None and cat_500k is not None
        assert abs(cat_500 - cat_5k) <= 0.1
        assert abs(cat_500 - cat_50k) <= 0.1
        assert abs(cat_500 - cat_500k) <= 0.1

        # Total scores must be identical (or within ±1 point due to round())
        assert abs(result_500.total_score - result_500k.total_score) <= 1

    def test_property_b_adding_finding_never_lowers_score(self):
        """Property (b): Adding an authentic finding never lowers the score (monotonicity)."""
        scorer = EntropyScorer()
        total_loc = 2500

        findings: list[Finding] = []
        prev_score = 0

        # Incrementally add findings of various severities
        severities = [
            Severity.LOW,
            Severity.MEDIUM,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
            Severity.LOW,
            Severity.HIGH,
        ]

        for i, sev in enumerate(severities):
            findings.append(_make_finding(f"f_{i}", sev))
            res = scorer.calculate_score(findings=findings, total_loc=total_loc, analyzed_files=5)
            assert res.total_score >= prev_score, f"Adding {sev} decreased score from {prev_score} to {res.total_score}"
            prev_score = res.total_score

    @pytest.mark.parametrize("loc", [0, 50, 100, 200, 1000, 50000, 1000000])
    @pytest.mark.parametrize("finding_count", [0, 1, 5, 20, 100, 2000])
    def test_property_c_score_strictly_within_0_to_100(self, loc: int, finding_count: int):
        """Property (c): Score stays strictly within [0, 100] across any repository scale."""
        scorer = EntropyScorer()
        findings = [_make_finding(f"f_{i}", Severity.CRITICAL) for i in range(finding_count)]
        result = scorer.calculate_score(findings=findings, total_loc=loc, analyzed_files=max(1, loc // 100))

        assert 0 <= result.total_score <= 100
        for breakdown in result.category_scores.values():
            if breakdown.score is not None:
                assert 0.0 <= breakdown.score <= 100.0

    def test_minimum_loc_floor_prevents_explosion(self):
        """Tiny repos (e.g. 10 LOC) use MIN_LOC_FLOOR so a single medium defect does not score 90+."""
        normalizer = ScoreNormalizer()

        # 1 medium finding (4 pts) in a 10 LOC repository
        norm_result = normalizer.normalize_category_penalty(raw_penalty=4.0, total_loc=10)

        # KLOC must be MIN_LOC_FLOOR / 1000 = 0.20
        assert norm_result.kloc == MIN_LOC_FLOOR / 1000.0
        # Weighted density = 4.0 / 0.20 = 20.0 pts/KLOC
        assert norm_result.weighted_debt_density == 20.0
        # Score = 100 * (1 - exp(-20 / 40)) = 39.3 (bounded in Low/Moderate, not 99)
        assert norm_result.category_score < 50.0

    def test_density_formula_audit_trail_and_result(self):
        """Audit trail and formula summary explicitly document density calculations."""
        scorer = EntropyScorer()
        findings = [_make_finding("f1", Severity.HIGH)]
        result = scorer.calculate_score(findings=findings, total_loc=1000, analyzed_files=2)

        assert "Weighted_Debt_Density" in result.formula_summary
        assert "DENSITY_SATURATION_FACTOR" not in result.formula_summary  # Constant substituted
        assert str(DENSITY_SATURATION_FACTOR) in result.formula_summary
        assert any("Active analyzed categories" in log for log in result.audit_trail)
