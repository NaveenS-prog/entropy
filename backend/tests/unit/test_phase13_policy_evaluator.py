"""Unit tests for Phase 13 Deterministic Policy Evaluator.

Covers all 15 specification tests:
1. Score pass
2. Score fail
3. Delta pass
4. Delta fail
5. New findings pass/fail
6. High findings fail
7. Critical findings fail
8. Category delta pass/fail
9. Forbidden rule fail
10. Baseline absence (NOT_APPLICABLE)
11. Multiple violations
12. Warning status
13. Determinism
14. Invalid config rejection
15. Policy version snapshotting
"""

from datetime import UTC, datetime

import pytest

from app.comparison.models import (
    CategoryComparison,
    ComparisonFindingItem,
    ComparisonSummary,
    FindingLifecycleStatus,
    ScanComparisonResult,
    ScoreComparison,
)
from app.models.domain.enums import Confidence, DebtCategory, Severity
from app.policy.evaluator import PolicyEvaluator
from app.policy.models import (
    CategoryRulesConfig,
    FindingRulesConfig,
    PolicyConfig,
    PolicyStatus,
    RuleSpecificRulesConfig,
    ScoreRulesConfig,
)
from app.policy.parser import PolicyConfigurationError, parse_policy_dict, parse_policy_yaml


def make_mock_comparison(
    current_score: int,
    previous_score: int,
    new_findings: list[ComparisonFindingItem] | None = None,
    category_deltas: dict[str, float] | None = None,
) -> ScanComparisonResult:
    """Helper creating a deterministic mock ScanComparisonResult."""
    delta = current_score - previous_score
    findings = new_findings or []
    cat_comps = {}
    if category_deltas:
        for cat_name, c_delta in category_deltas.items():
            cat_comps[cat_name] = CategoryComparison(
                category=DebtCategory(cat_name),
                category_name=cat_name,
                previous_score=20.0,
                current_score=20.0 + c_delta,
                score_delta=c_delta,
                previous_status="analyzed",
                current_status="analyzed",
                previous_finding_count=2,
                current_finding_count=2 + len(findings),
                finding_count_delta=len(findings),
            )

    return ScanComparisonResult(
        summary=ComparisonSummary(
            repository_id="repo-test",
            repo_name="org/repo",
            previous_scan_id="scan-base",
            current_scan_id="scan-head",
            previous_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            current_timestamp=datetime(2026, 1, 2, tzinfo=UTC),
            previous_score=previous_score,
            current_score=current_score,
            score_delta=delta,
            new_findings_count=len(findings),
            resolved_findings_count=0,
            persistent_findings_count=1,
            total_current_findings=1 + len(findings),
        ),
        score_comparison=ScoreComparison(
            previous_score=previous_score,
            current_score=current_score,
            score_delta=delta,
            direction="increased" if delta > 0 else "unchanged",
            explanation=f"Debt delta is {delta}",
        ),
        category_comparisons=cat_comps,
        rule_comparisons=[],
        new_findings=findings,
        resolved_findings=[],
        persistent_findings=[],
    )


def make_finding_item(
    rule_id: str,
    severity: Severity,
    finding_id: str = "f1",
) -> ComparisonFindingItem:
    return ComparisonFindingItem(
        finding_id=finding_id,
        fingerprint=f"fp-{finding_id}",
        category=DebtCategory.LOGGING_AND_SECRETS,
        rule_id=rule_id,
        severity=severity,
        confidence=Confidence.HIGH,
        file="app/main.py",
        line_start=10,
        line_end=12,
        title="Test finding",
        description="Test description",
        lifecycle=FindingLifecycleStatus.NEW,
    )


def test_1_score_pass():
    """TEST 1: max_score = 40, actual = 20 -> PASS."""
    policy = PolicyConfig(
        score=ScoreRulesConfig(max_score=40),
    )
    result = PolicyEvaluator.evaluate(policy, current_score=20)
    assert result.status == PolicyStatus.PASS
    assert result.passed is True
    assert len(result.violations) == 0


def test_2_score_fail():
    """TEST 2: max_score = 40, actual = 45 -> FAIL."""
    policy = PolicyConfig(
        score=ScoreRulesConfig(max_score=40),
    )
    result = PolicyEvaluator.evaluate(policy, current_score=45)
    assert result.status == PolicyStatus.FAIL
    assert result.passed is False
    assert len(result.violations) == 1
    assert result.violations[0].rule_name == "max_score"
    assert result.violations[0].actual_value == 45
    assert result.violations[0].threshold == 40


def test_3_delta_pass():
    """TEST 3: base = 20, head = 23, max_delta = 5 -> PASS (delta = +3)."""
    policy = PolicyConfig(
        score=ScoreRulesConfig(max_delta=5),
    )
    comp = make_mock_comparison(current_score=23, previous_score=20)
    result = PolicyEvaluator.evaluate(policy, comparison=comp)
    assert result.status == PolicyStatus.PASS
    assert result.passed is True
    assert result.score_delta == 3


def test_4_delta_fail():
    """TEST 4: base = 20, head = 27, max_delta = 5 -> FAIL (delta = +7)."""
    policy = PolicyConfig(
        score=ScoreRulesConfig(max_delta=5),
    )
    comp = make_mock_comparison(current_score=27, previous_score=20)
    result = PolicyEvaluator.evaluate(policy, comparison=comp)
    assert result.status == PolicyStatus.FAIL
    assert result.passed is False
    assert len(result.violations) == 1
    assert result.violations[0].rule_name == "max_delta"
    assert result.violations[0].actual_value == 7
    assert result.violations[0].threshold == 5


def test_5_new_findings():
    """TEST 5: max_new = 3; actual = 2 -> PASS; actual = 4 -> FAIL."""
    policy = PolicyConfig(
        findings=FindingRulesConfig(max_new=3),
    )
    # Pass case: 2 new findings
    f2 = [
        make_finding_item("ENT-LOG-001", Severity.LOW, "f1"),
        make_finding_item("ENT-LOG-001", Severity.LOW, "f2"),
    ]
    comp_pass = make_mock_comparison(current_score=10, previous_score=10, new_findings=f2)
    res_pass = PolicyEvaluator.evaluate(policy, comparison=comp_pass)
    assert res_pass.status == PolicyStatus.PASS

    # Fail case: 4 new findings
    f4 = f2 + [
        make_finding_item("ENT-LOG-001", Severity.LOW, "f3"),
        make_finding_item("ENT-LOG-001", Severity.LOW, "f4"),
    ]
    comp_fail = make_mock_comparison(current_score=10, previous_score=10, new_findings=f4)
    res_fail = PolicyEvaluator.evaluate(policy, comparison=comp_fail)
    assert res_fail.status == PolicyStatus.FAIL
    assert len(res_fail.violations) == 1
    assert res_fail.violations[0].actual_value == 4
    assert res_fail.violations[0].threshold == 3


def test_6_high_findings():
    """TEST 6: max_new_high = 0; actual = 1 -> FAIL."""
    policy = PolicyConfig(
        findings=FindingRulesConfig(max_new_high=0),
    )
    f_high = [make_finding_item("ENT-LOG-001", Severity.HIGH, "f-high-1")]
    comp = make_mock_comparison(current_score=10, previous_score=10, new_findings=f_high)
    result = PolicyEvaluator.evaluate(policy, comparison=comp)
    assert result.status == PolicyStatus.FAIL
    assert len(result.violations) == 1
    assert result.violations[0].rule_name == "max_new_high"
    assert result.violations[0].actual_value == 1
    assert "f-high-1" in result.violations[0].finding_ids


def test_7_critical_findings():
    """TEST 7: max_new_critical = 0; actual = 1 -> FAIL."""
    policy = PolicyConfig(
        findings=FindingRulesConfig(max_new_critical=0),
    )
    f_crit = [make_finding_item("ENT-SEC-001", Severity.CRITICAL, "f-crit-1")]
    comp = make_mock_comparison(current_score=10, previous_score=10, new_findings=f_crit)
    result = PolicyEvaluator.evaluate(policy, comparison=comp)
    assert result.status == PolicyStatus.FAIL
    assert len(result.violations) == 1
    assert result.violations[0].rule_name == "max_new_critical"
    assert result.violations[0].actual_value == 1
    assert "f-crit-1" in result.violations[0].finding_ids


def test_8_category_delta():
    """TEST 8: max_category_delta = 5; actual = +3 -> PASS, actual = +6 -> FAIL."""
    policy = PolicyConfig(
        categories=CategoryRulesConfig(
            max_delta={"logging_and_secrets": 5.0},
        ),
    )
    # Pass case
    comp_pass = make_mock_comparison(
        current_score=23, previous_score=20, category_deltas={"logging_and_secrets": 3.0}
    )
    res_pass = PolicyEvaluator.evaluate(policy, comparison=comp_pass)
    assert res_pass.status == PolicyStatus.PASS

    # Fail case
    comp_fail = make_mock_comparison(
        current_score=26, previous_score=20, category_deltas={"logging_and_secrets": 6.0}
    )
    res_fail = PolicyEvaluator.evaluate(policy, comparison=comp_fail)
    assert res_fail.status == PolicyStatus.FAIL
    assert len(res_fail.violations) == 1
    assert res_fail.violations[0].category == "logging_and_secrets"
    assert res_fail.violations[0].actual_value == 6.0


def test_9_forbidden_rule():
    """TEST 9: forbidden_rules = ["ENT-LOG-002"]; PR introduces ENT-LOG-002 -> FAIL."""
    policy = PolicyConfig(
        rules=RuleSpecificRulesConfig(forbidden_rules=["ENT-LOG-002"]),
    )
    f_forbidden = [make_finding_item("ENT-LOG-002", Severity.MEDIUM, "f-forbid-1")]
    comp = make_mock_comparison(current_score=10, previous_score=10, new_findings=f_forbidden)
    result = PolicyEvaluator.evaluate(policy, comparison=comp)
    assert result.status == PolicyStatus.FAIL
    assert len(result.violations) == 1
    assert result.violations[0].rule_name == "forbidden_rules"
    assert "ENT-LOG-002" in result.violations[0].actual_value
    assert "f-forbid-1" in result.violations[0].finding_ids


def test_10_baseline_absence():
    """TEST 10: Standalone scan without baseline -> delta rules return NOT_APPLICABLE."""
    policy = PolicyConfig(
        score=ScoreRulesConfig(max_score=40, max_delta=5),
        findings=FindingRulesConfig(max_new=5, max_new_high=0),
    )
    # Standalone evaluation without comparison
    result = PolicyEvaluator.evaluate(policy, current_score=25)
    assert result.status == PolicyStatus.PASS  # max_score passed
    assert len(result.not_applicable_rules) == 3  # max_delta, max_new, max_new_high
    na_names = {r.rule_name for r in result.not_applicable_rules}
    assert "max_delta" in na_names
    assert "max_new_findings" in na_names
    assert "max_new_high" in na_names


def test_11_multiple_violations():
    """TEST 11: Score violation and new High violation -> both appear in result."""
    policy = PolicyConfig(
        score=ScoreRulesConfig(max_delta=3),
        findings=FindingRulesConfig(max_new_high=0),
    )
    f_high = [make_finding_item("ENT-LOG-001", Severity.HIGH, "fh-1")]
    comp = make_mock_comparison(current_score=25, previous_score=20, new_findings=f_high)  # delta = 5 > 3
    result = PolicyEvaluator.evaluate(policy, comparison=comp)
    assert result.status == PolicyStatus.FAIL
    assert len(result.violations) == 2
    v_rules = {v.rule_name for v in result.violations}
    assert "max_delta" in v_rules
    assert "max_new_high" in v_rules


def test_12_warn_status():
    """TEST 12: Warning threshold exceeded without blocking violations -> WARN."""
    policy = PolicyConfig(
        score=ScoreRulesConfig(max_score=50, warn_score=30, max_delta=10, warn_delta=3),
    )
    comp = make_mock_comparison(current_score=35, previous_score=30)  # delta = 5 > warn_delta (3), score 35 > warn_score (30)
    result = PolicyEvaluator.evaluate(policy, comparison=comp)
    assert result.status == PolicyStatus.WARN
    assert result.passed is True  # Warnings do not block
    assert len(result.violations) == 0
    assert len(result.warnings) == 2


def test_13_determinism():
    """TEST 13: Identical scan, comparison, and policy evaluated twice yield 100% identical outputs."""
    policy = PolicyConfig(
        score=ScoreRulesConfig(max_score=40, max_delta=5),
        findings=FindingRulesConfig(max_new=2),
    )
    comp = make_mock_comparison(current_score=22, previous_score=20)

    res1 = PolicyEvaluator.evaluate(policy, comparison=comp)
    res2 = PolicyEvaluator.evaluate(policy, comparison=comp)

    # Exclude timestamp for direct deep equality
    d1 = res1.model_dump(exclude={"evaluated_at"})
    d2 = res2.model_dump(exclude={"evaluated_at"})
    assert d1 == d2


def test_14_invalid_config():
    """TEST 14: Negative values, unknown categories, or malformed configs fail validation."""
    # Negative score
    with pytest.raises(PolicyConfigurationError):
        parse_policy_dict({"score": {"max_score": -5}})

    # Unknown category
    with pytest.raises(PolicyConfigurationError):
        parse_policy_dict({"categories": {"max_delta": {"non_existent_category": 5}}})

    # Malformed YAML
    with pytest.raises(PolicyConfigurationError):
        parse_policy_yaml("score: [unclosed list")

    # Extra/unknown field forbidden
    with pytest.raises(PolicyConfigurationError):
        parse_policy_dict({"score": {"max_score": 40}, "unknown_field": 123})


def test_15_policy_version():
    """TEST 15: Policy version changes are captured immutably in the evaluation."""
    p_v1 = PolicyConfig(name="prod", version="1.0.0", score=ScoreRulesConfig(max_score=50))
    p_v2 = PolicyConfig(name="prod", version="2.0.0", score=ScoreRulesConfig(max_score=30))

    eval_v1 = PolicyEvaluator.evaluate(p_v1, current_score=35)
    eval_v2 = PolicyEvaluator.evaluate(p_v2, current_score=35)

    assert eval_v1.policy_version == "1.0.0"
    assert eval_v1.status == PolicyStatus.PASS

    assert eval_v2.policy_version == "2.0.0"
    assert eval_v2.status == PolicyStatus.FAIL
