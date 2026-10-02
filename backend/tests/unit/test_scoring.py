"""Unit tests for the Scoring Engine."""

from app.models.domain.enums import Confidence, DebtCategory, DebtScoreTier, Severity
from app.models.domain.finding import CodeEvidence, Finding
from app.scoring.engine import ScoringEngine


def test_scoring_zero_findings():
    engine = ScoringEngine()
    result = engine.calculate_score(findings=[], total_loc=1000, analyzed_files=5)

    assert result.total_score == 0
    assert result.tier == DebtScoreTier.VERY_LOW
    assert result.total_findings == 0
    assert result.is_explainable is True
    assert len(result.audit_trail) > 0

    # Analyzed category with zero findings has score 0.0
    assert result.category_scores[DebtCategory.ERROR_HANDLING].score == 0.0
    assert result.category_scores[DebtCategory.ERROR_HANDLING].status == "analyzed"

    # Unanalyzed categories must not have fabricated 0.0 scores
    for cat in DebtCategory:
        if cat not in result.analyzed_categories:
            assert result.category_scores[cat].score is None
            assert result.category_scores[cat].status == "not_analyzed"


def test_scoring_with_findings():
    evidence = CodeEvidence(content="except: pass", line_start=1, line_end=1)
    findings = [
        Finding(
            id="f-1",
            category=DebtCategory.ERROR_HANDLING,
            rule_id="ERR-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            file="auth.py",
            line_start=10,
            line_end=11,
            symbol="login",
            title="Swallowed Exception",
            description="Swallowed",
            evidence=evidence,
            impact="Risk",
            recommendation="Fix",
            fingerprint="fp1",
        ),
        Finding(
            id="f-2",
            category=DebtCategory.ERROR_HANDLING,
            rule_id="ERR-002",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            file="api.py",
            line_start=20,
            line_end=22,
            symbol="handler",
            title="Bare Exception",
            description="Bare",
            evidence=evidence,
            impact="Risk",
            recommendation="Fix",
            fingerprint="fp2",
        ),
    ]

    engine = ScoringEngine()
    result = engine.calculate_score(findings=findings, total_loc=200, analyzed_files=2)

    assert result.total_findings == 2
    assert result.total_score > 0
    assert result.category_scores[DebtCategory.ERROR_HANDLING].score > 0
    assert result.category_scores[DebtCategory.ERROR_HANDLING].finding_count == 2
    assert result.category_scores[DebtCategory.CODE_DUPLICATION].score == 0.0
    assert result.category_scores[DebtCategory.CODE_DUPLICATION].status == "analyzed"
    assert result.category_scores[DebtCategory.ARCHITECTURAL_CONSISTENCY].score is None
    assert result.category_scores[DebtCategory.ARCHITECTURAL_CONSISTENCY].status == "not_analyzed"
    assert result.category_scores[DebtCategory.INPUT_VALIDATION].status == "analyzed"
    assert "Entropy_Score" in result.formula_summary
