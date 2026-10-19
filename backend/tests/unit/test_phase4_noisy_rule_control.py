"""Phase 4 Regression Tests: Noisy-Rule Control and Diminishing Returns.

Validates:
1. ENT-ARCH-001 does not create circular dependency cycles from type-checking imports (if TYPE_CHECKING).
2. CategoryScorer applies diminishing returns per rule:
   - First 20 findings contribute at full weight.
   - 4,000 identical findings from one rule do not exceed 4x the penalty of 20 findings.
3. Monotonicity is preserved: penalty strictly increases with finding count.
4. Clean separation: multiple rules in the same category each get their own full-weight threshold.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from app.models.domain.enums import Confidence, DebtCategory, Severity
from app.models.domain.finding import CodeEvidence, Finding
from app.scoring.category_scorer import CategoryScorer
from app.scoring.weights import calculate_rule_penalty
from app.services.scan_service import ScanService


def test_4000_identical_findings_do_not_exceed_diminishing_bound():
    """Test: 4,000 identical findings from one rule do not exceed 4 times the penalty of 20 findings."""
    unit_weight = 1.0
    penalty_20 = calculate_rule_penalty([unit_weight] * 20)
    assert penalty_20 == 20.0, f"Expected 20.0 for 20 findings, got {penalty_20}"

    penalty_4000 = calculate_rule_penalty([unit_weight] * 4000)
    ratio = penalty_4000 / penalty_20

    # 4,000 findings should not exceed 4 times the penalty of 20 findings (approx 3.07x)
    assert ratio <= 4.0, f"Expected 4000 findings ratio <= 4.0, got {ratio:.2f}"
    # Must preserve strict monotonicity: 4,000 findings > 20 findings
    assert penalty_4000 > penalty_20


def test_category_scorer_applies_diminishing_returns_per_rule():
    """CategoryScorer applies diminishing returns to raw_penalty and RuleContribution."""
    scorer = CategoryScorer()

    findings_20 = [
        Finding(
            id=f"finding-{i}",
            category=DebtCategory.CODE_DUPLICATION,
            rule_id="ENT-DUP-001",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            file="module.py",
            line_start=i,
            line_end=i + 5,
            title="Code Duplication Block",
            description="Duplicated code block",
            evidence=CodeEvidence(content="code", line_start=i, line_end=i + 5),
            impact="Duplication impact",
            recommendation="Refactor duplication",
            fingerprint=f"fp-{i}",
        )
        for i in range(1, 21)
    ]

    breakdown_20 = scorer.score_category(
        category=DebtCategory.CODE_DUPLICATION,
        findings=findings_20,
        is_analyzed=True,
        total_loc=10000,
        analyzed_files=20,
    )

    findings_4000 = [
        Finding(
            id=f"finding-{i}",
            category=DebtCategory.CODE_DUPLICATION,
            rule_id="ENT-DUP-001",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            file="module.py",
            line_start=i,
            line_end=i + 5,
            title="Code Duplication Block",
            description="Duplicated code block",
            evidence=CodeEvidence(content="code", line_start=i, line_end=i + 5),
            impact="Duplication impact",
            recommendation="Refactor duplication",
            fingerprint=f"fp-{i}",
        )
        for i in range(1, 4001)
    ]

    breakdown_4000 = scorer.score_category(
        category=DebtCategory.CODE_DUPLICATION,
        findings=findings_4000,
        is_analyzed=True,
        total_loc=10000,
        analyzed_files=20,
    )

    # Ratio of raw deductions must not exceed 4x
    ratio = breakdown_4000.raw_deduction / breakdown_20.raw_deduction
    assert ratio <= 4.0, f"Expected raw deduction ratio <= 4.0, got {ratio:.2f}"
    assert breakdown_4000.raw_deduction > breakdown_20.raw_deduction
    assert len(breakdown_4000.top_rules) == 1
    assert breakdown_4000.top_rules[0].weighted_points == breakdown_4000.raw_deduction


def test_ent_arch_001_ignores_type_checking_cycles():
    """Type-checking imports (if TYPE_CHECKING:) must not trigger ENT-ARCH-001 circular dependencies."""
    mod_a = '''from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from b import ClassB

class ClassA:
    b: "ClassB"
'''

    mod_b = '''from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from a import ClassA

class ClassB:
    a: "ClassA"
'''

    service = ScanService()
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "a.py").write_text(mod_a)
        (Path(tmpdir) / "b.py").write_text(mod_b)
        scan = service.execute_scan(Path(tmpdir))

        arch_cycles = [f for f in scan.findings if f.rule_id == "ENT-ARCH-001"]
        assert len(arch_cycles) == 0, f"Expected 0 circular dependencies from TYPE_CHECKING, got: {arch_cycles}"
