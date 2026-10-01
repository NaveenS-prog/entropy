"""Unit tests for domain models."""

from app.models.domain.enums import (
    Confidence,
    DebtCategory,
    DebtScoreTier,
    Severity,
)
from app.models.domain.finding import CodeEvidence, Finding


def test_debt_score_tier_mapping():
    assert DebtScoreTier.from_score(0.0) == DebtScoreTier.VERY_LOW
    assert DebtScoreTier.from_score(20.0) == DebtScoreTier.VERY_LOW
    assert DebtScoreTier.from_score(21.0) == DebtScoreTier.LOW
    assert DebtScoreTier.from_score(40.0) == DebtScoreTier.LOW
    assert DebtScoreTier.from_score(41.0) == DebtScoreTier.MODERATE
    assert DebtScoreTier.from_score(60.0) == DebtScoreTier.MODERATE
    assert DebtScoreTier.from_score(61.0) == DebtScoreTier.HIGH
    assert DebtScoreTier.from_score(80.0) == DebtScoreTier.HIGH
    assert DebtScoreTier.from_score(81.0) == DebtScoreTier.VERY_HIGH
    assert DebtScoreTier.from_score(100.0) == DebtScoreTier.VERY_HIGH


def test_finding_instantiation_and_fingerprint():
    evidence = CodeEvidence(
        content="try:\n    pass\nexcept:\n    pass\n",
        line_start=1,
        line_end=4,
        highlight_lines=[3, 4],
    )
    fp = Finding.generate_fingerprint("ERR-001", "service.py", "auth_func", "swallowed")
    finding = Finding(
        id="f-123",
        category=DebtCategory.ERROR_HANDLING,
        rule_id="ERR-001",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file="service.py",
        line_start=3,
        line_end=4,
        symbol="auth_func",
        title="Swallowed Exception",
        description="Testing swallowed exception",
        evidence=evidence,
        impact="High risk of silent failures",
        recommendation="Log and handle",
        fingerprint=fp,
    )

    assert finding.id == "f-123"
    assert finding.category == DebtCategory.ERROR_HANDLING
    assert finding.fingerprint == fp
    assert len(finding.evidence.highlight_lines) == 2
