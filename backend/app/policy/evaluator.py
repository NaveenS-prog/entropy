"""Deterministic Policy Evaluation Engine for Entropy.

Invariants:
- 100% deterministic: identical scan + identical comparison + identical policy = identical output.
- Zero AI dependency: AI explanations are never used to decide policy.
- Zero score modification: Entropy scores, findings, severities, and fingerprints are strictly read-only.
- Baseline isolation: delta rules return NOT_APPLICABLE on standalone scans without fabricating baselines.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.comparison.models import ScanComparisonResult
from app.models.domain.enums import Severity
from app.models.domain.finding import Finding
from app.models.domain.scan import RepositoryScanResult
from app.policy.models import (
    PolicyConfig,
    PolicyEvaluation,
    PolicyRuleResult,
    PolicyRuleSeverity,
    PolicyStatus,
)


class PolicyEvaluator:
    """Evaluates scan results and scan-to-scan comparisons against a PolicyConfig."""

    @classmethod
    def evaluate(
        cls,
        policy: PolicyConfig,
        current_scan: RepositoryScanResult | None = None,
        comparison: ScanComparisonResult | None = None,
        current_score: int | None = None,
        current_findings: list[Finding] | None = None,
    ) -> PolicyEvaluation:
        """Deterministically evaluate current scan or comparison against the provided policy."""
        # 1. Resolve current score and findings
        if current_scan is not None:
            score_val = current_scan.score.total_score if current_scan.score else 0
            findings_list = current_scan.findings or []
            cat_scores = {
                cat.value: b.score
                for cat, b in (current_scan.score.category_scores.items() if current_scan.score else {}.items())
                if b.score is not None
            }
            total_findings = len(findings_list)
            total_high = sum(1 for f in findings_list if f.severity == Severity.HIGH)
            total_critical = sum(1 for f in findings_list if f.severity == Severity.CRITICAL)
        elif comparison is not None:
            score_val = (
                comparison.summary.current_score
                if comparison.summary.current_score is not None
                else (comparison.score_comparison.current_score or 0)
            )
            # Reconstruct findings counts from comparison
            findings_list = []
            cat_scores = {
                k: v.current_score
                for k, v in comparison.category_comparisons.items()
                if v.current_score is not None
            }
            total_findings = comparison.summary.total_current_findings
            total_high = sum(
                1
                for f in (comparison.new_findings + comparison.persistent_findings)
                if f.severity == Severity.HIGH
            )
            total_critical = sum(
                1
                for f in (comparison.new_findings + comparison.persistent_findings)
                if f.severity == Severity.CRITICAL
            )
        else:
            score_val = current_score or 0
            findings_list = current_findings or []
            cat_scores = {}
            total_findings = len(findings_list)
            total_high = sum(1 for f in findings_list if f.severity == Severity.HIGH)
            total_critical = sum(1 for f in findings_list if f.severity == Severity.CRITICAL)

        base_score_val: int | None = None
        score_delta_val: int | None = None
        new_findings_count_val: int | None = None

        if comparison is not None:
            base_score_val = comparison.summary.previous_score
            score_delta_val = comparison.summary.score_delta
            new_findings_count_val = comparison.summary.new_findings_count

        has_baseline = comparison is not None

        all_rules: list[PolicyRuleResult] = []

        # ---------------------------------------------------------
        # A. SCORE RULES
        # ---------------------------------------------------------
        # 1. max_score (Absolute)
        if policy.score.max_score is not None:
            thresh = policy.score.max_score
            if score_val > thresh:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="max_score",
                        rule_type="absolute",
                        status=PolicyStatus.FAIL,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=score_val,
                        threshold=thresh,
                        message=f"Entropy score of {score_val} exceeds maximum configured threshold of {thresh}.",
                    )
                )
            else:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="max_score",
                        rule_type="absolute",
                        status=PolicyStatus.PASS,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=score_val,
                        threshold=thresh,
                        message=f"Entropy score of {score_val} meets maximum threshold of {thresh}.",
                    )
                )

        # 2. warn_score (Absolute)
        if policy.score.warn_score is not None:
            thresh = policy.score.warn_score
            if score_val > thresh:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="warn_score",
                        rule_type="absolute",
                        status=PolicyStatus.WARN,
                        severity=PolicyRuleSeverity.WARN,
                        actual_value=score_val,
                        threshold=thresh,
                        message=f"Entropy score of {score_val} exceeds warning threshold of {thresh}.",
                    )
                )
            else:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="warn_score",
                        rule_type="absolute",
                        status=PolicyStatus.PASS,
                        severity=PolicyRuleSeverity.WARN,
                        actual_value=score_val,
                        threshold=thresh,
                        message=f"Entropy score of {score_val} within acceptable warning threshold of {thresh}.",
                    )
                )

        # 3. max_delta (Delta)
        if policy.score.max_delta is not None:
            thresh = policy.score.max_delta
            if not has_baseline:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="max_delta",
                        rule_type="delta",
                        status=PolicyStatus.NOT_APPLICABLE,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=None,
                        threshold=thresh,
                        message="Maximum score delta rule is not applicable without a baseline comparison.",
                    )
                )
            else:
                delta = score_delta_val if score_delta_val is not None else 0
                if delta > thresh:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="max_delta",
                            rule_type="delta",
                            status=PolicyStatus.FAIL,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=delta,
                            threshold=thresh,
                            message=(
                                f"Entropy score increased by {delta} points (from {base_score_val} to {score_val}), "
                                f"exceeding maximum configured delta of {thresh}."
                            ),
                        )
                    )
                else:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="max_delta",
                            rule_type="delta",
                            status=PolicyStatus.PASS,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=delta,
                            threshold=thresh,
                            message=f"Score delta of {delta:+d} meets maximum allowed delta of {thresh}.",
                        )
                    )

        # 4. warn_delta (Delta)
        if policy.score.warn_delta is not None:
            thresh = policy.score.warn_delta
            if not has_baseline:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="warn_delta",
                        rule_type="delta",
                        status=PolicyStatus.NOT_APPLICABLE,
                        severity=PolicyRuleSeverity.WARN,
                        actual_value=None,
                        threshold=thresh,
                        message="Warning score delta rule is not applicable without a baseline comparison.",
                    )
                )
            else:
                delta = score_delta_val if score_delta_val is not None else 0
                if delta > thresh:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="warn_delta",
                            rule_type="delta",
                            status=PolicyStatus.WARN,
                            severity=PolicyRuleSeverity.WARN,
                            actual_value=delta,
                            threshold=thresh,
                            message=(
                                f"Entropy score increased by {delta} points, exceeding warning delta threshold of {thresh}."
                            ),
                        )
                    )
                else:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="warn_delta",
                            rule_type="delta",
                            status=PolicyStatus.PASS,
                            severity=PolicyRuleSeverity.WARN,
                            actual_value=delta,
                            threshold=thresh,
                            message=f"Score delta of {delta:+d} within acceptable warning delta of {thresh}.",
                        )
                    )

        # ---------------------------------------------------------
        # B. FINDING RULES
        # ---------------------------------------------------------
        # 5. max_new (Delta)
        if policy.findings.max_new is not None:
            thresh = policy.findings.max_new
            if not has_baseline:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="max_new_findings",
                        rule_type="delta",
                        status=PolicyStatus.NOT_APPLICABLE,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=None,
                        threshold=thresh,
                        message="Maximum new findings rule is not applicable without a baseline comparison.",
                    )
                )
            else:
                new_cnt = new_findings_count_val if new_findings_count_val is not None else 0
                if new_cnt > thresh:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="max_new_findings",
                            rule_type="delta",
                            status=PolicyStatus.FAIL,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=new_cnt,
                            threshold=thresh,
                            message=f"Introduced {new_cnt} new finding(s), exceeding maximum allowed limit of {thresh}.",
                            finding_ids=[f.finding_id for f in (comparison.new_findings if comparison else [])],
                        )
                    )
                else:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="max_new_findings",
                            rule_type="delta",
                            status=PolicyStatus.PASS,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=new_cnt,
                            threshold=thresh,
                            message=f"Introduced {new_cnt} new finding(s), within allowed limit of {thresh}.",
                        )
                    )

        # 6. max_new_high (Delta)
        if policy.findings.max_new_high is not None:
            thresh = policy.findings.max_new_high
            if not has_baseline:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="max_new_high",
                        rule_type="delta",
                        status=PolicyStatus.NOT_APPLICABLE,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=None,
                        threshold=thresh,
                        message="Maximum new High findings rule is not applicable without a baseline comparison.",
                    )
                )
            else:
                new_highs = [f for f in comparison.new_findings if f.severity == Severity.HIGH]  # type: ignore[union-attr]
                count = len(new_highs)
                if count > thresh:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="max_new_high",
                            rule_type="delta",
                            status=PolicyStatus.FAIL,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=count,
                            threshold=thresh,
                            message=f"Introduced {count} new High-severity finding(s), exceeding maximum of {thresh}.",
                            finding_ids=[f.finding_id for f in new_highs],
                        )
                    )
                else:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="max_new_high",
                            rule_type="delta",
                            status=PolicyStatus.PASS,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=count,
                            threshold=thresh,
                            message=f"Introduced {count} new High-severity finding(s), within allowed limit of {thresh}.",
                        )
                    )

        # 7. max_new_critical (Delta)
        if policy.findings.max_new_critical is not None:
            thresh = policy.findings.max_new_critical
            if not has_baseline:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="max_new_critical",
                        rule_type="delta",
                        status=PolicyStatus.NOT_APPLICABLE,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=None,
                        threshold=thresh,
                        message="Maximum new Critical findings rule is not applicable without a baseline comparison.",
                    )
                )
            else:
                new_crits = [f for f in comparison.new_findings if f.severity == Severity.CRITICAL]  # type: ignore[union-attr]
                count = len(new_crits)
                if count > thresh:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="max_new_critical",
                            rule_type="delta",
                            status=PolicyStatus.FAIL,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=count,
                            threshold=thresh,
                            message=(
                                f"Introduced {count} new Critical-severity finding(s), exceeding maximum of {thresh}."
                            ),
                            finding_ids=[f.finding_id for f in new_crits],
                        )
                    )
                else:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="max_new_critical",
                            rule_type="delta",
                            status=PolicyStatus.PASS,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=count,
                            threshold=thresh,
                            message=f"Introduced {count} new Critical finding(s), within allowed limit of {thresh}.",
                        )
                    )

        # 8. max_total (Absolute)
        if policy.findings.max_total is not None:
            thresh = policy.findings.max_total
            if total_findings > thresh:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="max_total_findings",
                        rule_type="absolute",
                        status=PolicyStatus.FAIL,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=total_findings,
                        threshold=thresh,
                        message=f"Total finding count of {total_findings} exceeds maximum allowed limit of {thresh}.",
                    )
                )
            else:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="max_total_findings",
                        rule_type="absolute",
                        status=PolicyStatus.PASS,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=total_findings,
                        threshold=thresh,
                        message=f"Total finding count of {total_findings} meets maximum allowed limit of {thresh}.",
                    )
                )

        # 9. max_total_high (Absolute)
        if policy.findings.max_total_high is not None:
            thresh = policy.findings.max_total_high
            if total_high > thresh:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="max_total_high",
                        rule_type="absolute",
                        status=PolicyStatus.FAIL,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=total_high,
                        threshold=thresh,
                        message=f"Total High findings count of {total_high} exceeds maximum allowed limit of {thresh}.",
                    )
                )
            else:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="max_total_high",
                        rule_type="absolute",
                        status=PolicyStatus.PASS,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=total_high,
                        threshold=thresh,
                        message=f"Total High findings count of {total_high} meets maximum allowed limit of {thresh}.",
                    )
                )

        # 10. max_total_critical (Absolute)
        if policy.findings.max_total_critical is not None:
            thresh = policy.findings.max_total_critical
            if total_critical > thresh:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="max_total_critical",
                        rule_type="absolute",
                        status=PolicyStatus.FAIL,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=total_critical,
                        threshold=thresh,
                        message=(
                            f"Total Critical findings count of {total_critical} exceeds maximum allowed limit of {thresh}."
                        ),
                    )
                )
            else:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name="max_total_critical",
                        rule_type="absolute",
                        status=PolicyStatus.PASS,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=total_critical,
                        threshold=thresh,
                        message=(
                            f"Total Critical findings count of {total_critical} meets maximum allowed limit of {thresh}."
                        ),
                    )
                )

        # ---------------------------------------------------------
        # C. CATEGORY RULES
        # ---------------------------------------------------------
        # 11. max_score per category (Absolute)
        for cat_key, cat_thresh in policy.categories.max_score.items():
            cat_actual = cat_scores.get(cat_key, 0.0)
            if cat_actual > cat_thresh:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name=f"max_category_score_{cat_key}",
                        rule_type="absolute",
                        status=PolicyStatus.FAIL,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=round(cat_actual, 2),
                        threshold=cat_thresh,
                        category=cat_key,
                        message=(
                            f"Category '{cat_key}' score of {cat_actual:.1f} exceeds maximum threshold of {cat_thresh:.1f}."
                        ),
                    )
                )
            else:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name=f"max_category_score_{cat_key}",
                        rule_type="absolute",
                        status=PolicyStatus.PASS,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=round(cat_actual, 2),
                        threshold=cat_thresh,
                        category=cat_key,
                        message=(
                            f"Category '{cat_key}' score of {cat_actual:.1f} meets maximum threshold of {cat_thresh:.1f}."
                        ),
                    )
                )

        # 12. max_delta per category (Delta)
        for cat_key, cat_thresh in policy.categories.max_delta.items():
            if not has_baseline:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name=f"max_category_delta_{cat_key}",
                        rule_type="delta",
                        status=PolicyStatus.NOT_APPLICABLE,
                        severity=PolicyRuleSeverity.FAIL,
                        actual_value=None,
                        threshold=cat_thresh,
                        category=cat_key,
                        message=f"Category delta rule for '{cat_key}' is not applicable without baseline comparison.",
                    )
                )
            else:
                cat_comp = comparison.category_comparisons.get(cat_key)  # type: ignore[union-attr]
                cat_delta = cat_comp.score_delta if (cat_comp and cat_comp.score_delta is not None) else 0.0
                if cat_delta > cat_thresh:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name=f"max_category_delta_{cat_key}",
                            rule_type="delta",
                            status=PolicyStatus.FAIL,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=round(cat_delta, 2),
                            threshold=cat_thresh,
                            category=cat_key,
                            message=(
                                f"Category '{cat_key}' increased by {cat_delta:+.1f} points, "
                                f"exceeding maximum allowed increase of {cat_thresh:.1f}."
                            ),
                        )
                    )
                else:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name=f"max_category_delta_{cat_key}",
                            rule_type="delta",
                            status=PolicyStatus.PASS,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=round(cat_delta, 2),
                            threshold=cat_thresh,
                            category=cat_key,
                            message=(
                                f"Category '{cat_key}' delta of {cat_delta:+.1f} meets maximum allowed delta of {cat_thresh:.1f}."
                            ),
                        )
                    )

        # 13. warn_delta per category (Delta)
        for cat_key, cat_thresh in policy.categories.warn_delta.items():
            if not has_baseline:
                all_rules.append(
                    PolicyRuleResult(
                        rule_name=f"warn_category_delta_{cat_key}",
                        rule_type="delta",
                        status=PolicyStatus.NOT_APPLICABLE,
                        severity=PolicyRuleSeverity.WARN,
                        actual_value=None,
                        threshold=cat_thresh,
                        category=cat_key,
                        message=f"Category warning delta for '{cat_key}' is not applicable without baseline.",
                    )
                )
            else:
                cat_comp = comparison.category_comparisons.get(cat_key)  # type: ignore[union-attr]
                cat_delta = cat_comp.score_delta if (cat_comp and cat_comp.score_delta is not None) else 0.0
                if cat_delta > cat_thresh:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name=f"warn_category_delta_{cat_key}",
                            rule_type="delta",
                            status=PolicyStatus.WARN,
                            severity=PolicyRuleSeverity.WARN,
                            actual_value=round(cat_delta, 2),
                            threshold=cat_thresh,
                            category=cat_key,
                            message=(
                                f"Category '{cat_key}' increased by {cat_delta:+.1f} points, "
                                f"exceeding warning delta threshold of {cat_thresh:.1f}."
                            ),
                        )
                    )
                else:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name=f"warn_category_delta_{cat_key}",
                            rule_type="delta",
                            status=PolicyStatus.PASS,
                            severity=PolicyRuleSeverity.WARN,
                            actual_value=round(cat_delta, 2),
                            threshold=cat_thresh,
                            category=cat_key,
                            message=(
                                f"Category '{cat_key}' delta of {cat_delta:+.1f} within warning threshold of {cat_thresh:.1f}."
                            ),
                        )
                    )

        # ---------------------------------------------------------
        # D. FORBIDDEN RULES
        # ---------------------------------------------------------
        if policy.rules.forbidden_rules:
            forbidden_set = set(policy.rules.forbidden_rules)
            if has_baseline:
                # In PR workflow, check newly introduced findings
                violating_items = [f for f in comparison.new_findings if f.rule_id in forbidden_set]  # type: ignore[union-attr]
                triggered_rules = sorted(list({f.rule_id for f in violating_items}))
                if violating_items:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="forbidden_rules",
                            rule_type="delta",
                            status=PolicyStatus.FAIL,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=triggered_rules,
                            threshold=sorted(list(forbidden_set)),
                            message=(
                                f"PR introduced {len(violating_items)} finding(s) violating forbidden rule(s): "
                                f"{', '.join(triggered_rules)}."
                            ),
                            finding_ids=[f.finding_id for f in violating_items],
                            rule_ids=triggered_rules,
                        )
                    )
                else:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="forbidden_rules",
                            rule_type="delta",
                            status=PolicyStatus.PASS,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=[],
                            threshold=sorted(list(forbidden_set)),
                            message="No forbidden rule findings were introduced in this PR.",
                            rule_ids=sorted(list(forbidden_set)),
                        )
                    )
            else:
                # In standalone scan, check all detected findings
                violating_findings = [f for f in findings_list if f.rule_id in forbidden_set]
                triggered_rules = sorted(list({f.rule_id for f in violating_findings}))
                if violating_findings:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="forbidden_rules",
                            rule_type="absolute",
                            status=PolicyStatus.FAIL,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=triggered_rules,
                            threshold=sorted(list(forbidden_set)),
                            message=(
                                f"Scan contains {len(violating_findings)} finding(s) violating forbidden rule(s): "
                                f"{', '.join(triggered_rules)}."
                            ),
                            finding_ids=[f.id for f in violating_findings],
                            rule_ids=triggered_rules,
                        )
                    )
                else:
                    all_rules.append(
                        PolicyRuleResult(
                            rule_name="forbidden_rules",
                            rule_type="absolute",
                            status=PolicyStatus.PASS,
                            severity=PolicyRuleSeverity.FAIL,
                            actual_value=[],
                            threshold=sorted(list(forbidden_set)),
                            message="No forbidden rule findings were detected in scan.",
                            rule_ids=sorted(list(forbidden_set)),
                        )
                    )

        # ---------------------------------------------------------
        # E. AGGREGATE DECISION
        # ---------------------------------------------------------
        violations = [r for r in all_rules if r.status == PolicyStatus.FAIL]
        warnings = [r for r in all_rules if r.status == PolicyStatus.WARN]
        passed_rules = [r for r in all_rules if r.status == PolicyStatus.PASS]
        not_applicable_rules = [r for r in all_rules if r.status == PolicyStatus.NOT_APPLICABLE]

        if violations:
            overall_status = PolicyStatus.FAIL
            passed = False
            summary = f"Policy evaluation FAILED: {len(violations)} blocking rule violation(s) detected."
        elif warnings:
            overall_status = PolicyStatus.WARN
            passed = True
            summary = f"Policy evaluation WARN: {len(warnings)} warning condition(s) exceeded."
        else:
            overall_status = PolicyStatus.PASS
            passed = True
            summary = "Policy evaluation PASSED: all evaluated rules satisfied."

        return PolicyEvaluation(
            policy_name=policy.name,
            policy_version=policy.version,
            status=overall_status,
            passed=passed,
            score=score_val,
            base_score=base_score_val,
            score_delta=score_delta_val,
            new_findings_count=new_findings_count_val,
            violations=violations,
            warnings=warnings,
            passed_rules=passed_rules,
            not_applicable_rules=not_applicable_rules,
            evaluated_at=datetime.now(UTC),
            summary=summary,
        )
