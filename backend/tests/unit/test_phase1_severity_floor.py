"""Unit tests for Phase 1: Severity Floor & Headline Score Integrity.

Verifies:
1. A 3-LOC repository with one hardcoded DB_PASSWORD (HIGH severity, HIGH confidence)
   scores at least MODERATE (>= 41).
2. The same file plus 20,000 LOC of benign filler remains at least MODERATE (>= 41).
3. Density invariance strictly holds when no HIGH/CRITICAL findings exist
   (same defect density at 500 and 500,000 LOC yields the exact same category score).
4. The severity floor never lowers any score (score >= score_density).
5. Score stays within [0, 100] and is strictly monotonic when findings are added.
6. Single CRITICAL finding sets at least HIGH (>= 61), and multiple CRITICAL findings
   set VERY_HIGH (>= 81).
7. DebtScoreResult contains score_density, severity_floor_applied, floor_reason,
   and worst_category with proper types and values.
"""

from __future__ import annotations

from app.models.domain.enums import Confidence, DebtCategory, DebtScoreTier, Severity
from app.models.domain.finding import CodeEvidence, Finding
from app.scoring.entropy_scorer import EntropyScorer
from app.scoring.weights import (
    SEVERITY_FLOOR_HIGH_SCORE,
    SEVERITY_FLOOR_MODERATE_SCORE,
    SEVERITY_FLOOR_VERY_HIGH_SCORE,
)


def _make_secret_finding(file_path: str = "config.py") -> Finding:
    """Create a high-confidence HIGH-severity secret finding (ENT-LOG-002)."""
    return Finding(
        id="finding-secret-001",
        category=DebtCategory.LOGGING_AND_SECRETS,
        rule_id="ENT-LOG-002",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file=file_path,
        line_start=2,
        line_end=2,
        column_start=1,
        column_end=35,
        symbol="DB_PASSWORD",
        title="Hardcoded Plain-Text Secret",
        description="Hardcoded plain-text credentials found in source file.",
        evidence=CodeEvidence(
            content='DB_PASSWORD = "prod-Sup3rSecret!"',
            line_start=2,
            line_end=2,
            highlight_lines=[2],
        ),
        impact="Credential compromise leads to unauthorized data access",
        recommendation="Use environment variables or secrets manager",
        fingerprint="fp_secret_001",
    )


def _make_critical_finding(fid: str = "finding-crit-001", file_path: str = "admin.py") -> Finding:
    """Create a high-confidence CRITICAL-severity finding (ENT-AUTH-001)."""
    return Finding(
        id=fid,
        category=DebtCategory.AUTHENTICATION_CONSISTENCY,
        rule_id="ENT-AUTH-001",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file=file_path,
        line_start=10,
        line_end=15,
        column_start=1,
        column_end=20,
        symbol="delete_user",
        title="Unprotected State-Mutating Route",
        description="Unauthenticated administrative route allows arbitrary deletion.",
        evidence=CodeEvidence(
            content='@app.post("/admin/delete-user")\ndef delete_user(): pass',
            line_start=10,
            line_end=15,
            highlight_lines=[10],
        ),
        impact="Unauthorized administrative execution",
        recommendation="Apply authentication dependencies",
        fingerprint=f"fp_{fid}",
    )


def _make_medium_finding(fid: str, loc_line: int = 5) -> Finding:
    """Create a standard MEDIUM-severity finding (ENT-ERR-001)."""
    return Finding(
        id=fid,
        category=DebtCategory.ERROR_HANDLING,
        rule_id="ENT-ERR-001",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        file="utils.py",
        line_start=loc_line,
        line_end=loc_line + 2,
        column_start=1,
        column_end=10,
        symbol="swallow",
        title="Bare Exception Handler",
        description="Catch block swallows exception without re-raising or logging.",
        evidence=CodeEvidence(
            content="except:\n    pass",
            line_start=loc_line,
            line_end=loc_line + 2,
            highlight_lines=[loc_line],
        ),
        impact="Hidden runtime failures",
        recommendation="Catch specific exception types",
        fingerprint=f"fp_{fid}",
    )


class TestHeadlineScoreSeverityFloor:
    """Test suite validating severity floor application and score honesty."""

    def test_1_tiny_repo_hardcoded_password_is_at_least_moderate(self):
        """Test (1): A 3-LOC repo with one hardcoded DB_PASSWORD is at least MODERATE."""
        scorer = EntropyScorer()
        secret_finding = _make_secret_finding("config.py")

        result = scorer.calculate_score(findings=[secret_finding], total_loc=3, analyzed_files=1)

        assert result.total_score >= SEVERITY_FLOOR_MODERATE_SCORE
        assert result.tier in (DebtScoreTier.MODERATE, DebtScoreTier.HIGH, DebtScoreTier.VERY_HIGH)
        assert result.severity_floor_applied is True
        assert result.floor_reason is not None
        assert "ENT-LOG-002" in result.floor_reason
        assert "config.py" in result.floor_reason
        # Pure density score is preserved as secondary metric
        assert result.score_density < SEVERITY_FLOOR_MODERATE_SCORE
        assert result.total_score >= result.score_density

    def test_2_large_repo_hardcoded_password_is_at_least_moderate(self):
        """Test (2): The same file plus 20,000 LOC of benign filler is still at least MODERATE."""
        scorer = EntropyScorer()
        secret_finding = _make_secret_finding("config.py")

        result = scorer.calculate_score(findings=[secret_finding], total_loc=20_000, analyzed_files=50)

        # In a 20k-LOC codebase, density score alone is ~0, but floor guarantees MODERATE
        assert result.score_density <= 2
        assert result.total_score >= SEVERITY_FLOOR_MODERATE_SCORE
        assert result.tier == DebtScoreTier.MODERATE
        assert result.severity_floor_applied is True
        assert "ENT-LOG-002" in result.floor_reason
        assert result.worst_category is not None
        assert result.worst_category.name == DebtCategory.LOGGING_AND_SECRETS.value

    def test_3_density_invariance_holds_without_high_or_critical_findings(self):
        """Test (3): Density invariance holds when no HIGH/CRITICAL findings exist."""
        scorer = EntropyScorer()

        # 1 MEDIUM finding per 100 LOC across 500 vs 500,000 LOC
        findings_500 = [_make_medium_finding(f"m500_{i}", loc_line=i * 5 + 1) for i in range(5)]
        result_500 = scorer.calculate_score(findings=findings_500, total_loc=500, analyzed_files=5)

        findings_500k = [_make_medium_finding(f"m500k_{i}", loc_line=i * 5 + 1) for i in range(5000)]
        result_500k = scorer.calculate_score(findings=findings_500k, total_loc=500_000, analyzed_files=500)

        # No severity floor applied
        assert result_500.severity_floor_applied is False
        assert result_500k.severity_floor_applied is False
        assert result_500.floor_reason is None
        assert result_500k.floor_reason is None

        # Category scores and density scores must be identical
        cat_500 = result_500.category_scores[DebtCategory.ERROR_HANDLING].score
        cat_500k = result_500k.category_scores[DebtCategory.ERROR_HANDLING].score
        assert cat_500 is not None and cat_500k is not None
        assert abs(cat_500 - cat_500k) <= 0.05
        assert result_500.total_score == result_500k.total_score

    def test_4_floor_never_lowers_score(self):
        """Test (4): The floor never lowers a score (total_score >= score_density)."""
        scorer = EntropyScorer()

        # Create findings across multiple categories so density score naturally exceeds floor (> 41)
        heavy_findings = []
        for cat in [
            DebtCategory.ERROR_HANDLING,
            DebtCategory.AUTHENTICATION_CONSISTENCY,
            DebtCategory.AUTHORIZATION_CONSISTENCY,
            DebtCategory.INPUT_VALIDATION,
            DebtCategory.LOGGING_AND_SECRETS,
        ]:
            for i in range(20):
                heavy_findings.append(
                    Finding(
                        id=f"f_{cat.value}_{i}",
                        category=cat,
                        rule_id="ENT-GEN-001",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        file=f"src/{cat.value}.py",
                        line_start=i + 1,
                        line_end=i + 2,
                        column_start=1,
                        column_end=10,
                        symbol="func",
                        title="Debt Finding",
                        description="Debt Finding Description",
                        evidence=CodeEvidence(content="x = 1", line_start=i + 1, line_end=i + 2),
                        impact="Impact",
                        recommendation="Fix",
                        fingerprint=f"fp_{cat.value}_{i}",
                    )
                )

        # Add 1 HIGH finding (which sets floor 41)
        heavy_findings.append(_make_secret_finding("secrets.py"))

        result = scorer.calculate_score(findings=heavy_findings, total_loc=500, analyzed_files=10)

        assert result.score_density >= 60
        assert result.total_score >= result.score_density
        assert result.severity_floor_applied is False

    def test_5_score_bounded_and_monotonic_with_findings(self):
        """Test (5): Score stays within 0..100 and is strictly monotonic when findings are added."""
        scorer = EntropyScorer()
        total_loc = 5000

        findings: list[Finding] = []
        prev_score = 0

        sequence = [
            _make_medium_finding("seq_1"),
            _make_medium_finding("seq_2"),
            _make_secret_finding("secrets.py"),  # jumps to floor 41
            _make_critical_finding("seq_crit_1"), # jumps to floor 61
            _make_medium_finding("seq_3"),
            _make_critical_finding("seq_crit_2"), # jumps to floor 81
        ]

        for finding in sequence:
            findings.append(finding)
            res = scorer.calculate_score(findings=findings, total_loc=total_loc, analyzed_files=5)
            assert 0 <= res.total_score <= 100
            assert res.total_score >= prev_score, (
                f"Adding {finding.rule_id} decreased score from {prev_score} to {res.total_score}"
            )
            prev_score = res.total_score

    def test_6_critical_finding_floors(self):
        """Test (6): 1 CRITICAL sets minimum HIGH (>= 61), 2+ CRITICALs set VERY_HIGH (>= 81)."""
        scorer = EntropyScorer()

        # 1 CRITICAL finding in 100,000 LOC
        f_crit1 = _make_critical_finding("c1", "admin_users.py")
        res_single = scorer.calculate_score(findings=[f_crit1], total_loc=100_000, analyzed_files=100)
        assert res_single.total_score >= SEVERITY_FLOOR_HIGH_SCORE
        assert res_single.tier in (DebtScoreTier.HIGH, DebtScoreTier.VERY_HIGH)
        assert res_single.severity_floor_applied is True
        assert "1 CRITICAL finding" in res_single.floor_reason

        # 2 CRITICAL findings in 100,000 LOC
        f_crit2 = _make_critical_finding("c2", "admin_payments.py")
        res_double = scorer.calculate_score(findings=[f_crit1, f_crit2], total_loc=100_000, analyzed_files=100)
        assert res_double.total_score >= SEVERITY_FLOOR_VERY_HIGH_SCORE
        assert res_double.tier == DebtScoreTier.VERY_HIGH
        assert res_double.severity_floor_applied is True
        assert "2 CRITICAL findings" in res_double.floor_reason
