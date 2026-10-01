"""Category-level scoring logic for Entropy.

Calculates deterministic debt scores for individual categories while strictly
enforcing the separation between ANALYZED and NOT_ANALYZED categories.
Unimplemented categories never receive fabricated scores or fake findings.
"""

from __future__ import annotations

from app.models.domain.enums import DebtCategory, Severity
from app.models.domain.finding import Finding
from app.scoring.models import (
    CategoryAnalysisStatus,
    CategoryScoreBreakdown,
    RuleContribution,
)
from app.scoring.normalizer import ScoreNormalizer, normalizer
from app.scoring.weights import (
    CATEGORY_WEIGHTS,
    CONFIDENCE_WEIGHTS,
    SEVERITY_WEIGHTS,
)


class CategoryScorer:
    """Computes transparent, deterministic debt scores for a specific category."""

    def __init__(self, normalizer_instance: ScoreNormalizer | None = None) -> None:
        self.normalizer = normalizer_instance or normalizer

    def score_category(
        self,
        category: DebtCategory,
        findings: list[Finding],
        is_analyzed: bool,
        total_loc: int = 0,
        analyzed_files: int = 0,
    ) -> CategoryScoreBreakdown:
        """Score a single debt category.

        If `is_analyzed` is False, the category is marked `NOT_ANALYZED` and
        assigned a null score (`None`), completely preventing fabricated scores.
        """
        base_weight = CATEGORY_WEIGHTS.get(category, 0.0)

        # Unanalyzed Category: Never fabricate data
        if not is_analyzed:
            return CategoryScoreBreakdown(
                category=category,
                status=CategoryAnalysisStatus.NOT_ANALYZED,
                score=None,
                finding_count=0,
                severity_counts={s: 0 for s in Severity},
                weight=base_weight,
                weighted_score=0.0,
                raw_deduction=0.0,
                normalized_penalty=0.0,
                explanation=(
                    f"No static analyzer implemented for {category.display_name} yet (scheduled for future phase). "
                    f"Does not contribute to current Entropy score."
                ),
                top_rules=[],
            )

        # Analyzed Category: Calculate from real findings
        severity_counts = {s: 0 for s in Severity}
        raw_penalty = 0.0

        # Group by rule for rule-level contribution analysis
        rule_findings: dict[str, list[Finding]] = {}

        for f in findings:
            severity_counts[f.severity] += 1
            sev_pts = SEVERITY_WEIGHTS.get(f.severity, 0.0)
            conf_mult = CONFIDENCE_WEIGHTS.get(f.confidence, 1.0)
            raw_penalty += sev_pts * conf_mult

            if f.rule_id not in rule_findings:
                rule_findings[f.rule_id] = []
            rule_findings[f.rule_id].append(f)

        # Compute top contributing rules sorted by weighted impact
        top_rules: list[RuleContribution] = []
        for r_id, r_list in rule_findings.items():
            first_finding = r_list[0]
            rule_title = first_finding.title
            r_points = sum(
                SEVERITY_WEIGHTS.get(f.severity, 0.0) * CONFIDENCE_WEIGHTS.get(f.confidence, 1.0)
                for f in r_list
            )
            top_rules.append(
                RuleContribution(
                    rule_id=r_id,
                    rule_title=rule_title,
                    finding_count=len(r_list),
                    weighted_points=round(r_points, 2),
                )
            )
        top_rules.sort(key=lambda r: (r.weighted_points, r.finding_count), reverse=True)

        # Normalize score
        norm_result = self.normalizer.normalize_category_penalty(
            raw_penalty=raw_penalty,
            total_loc=total_loc,
            analyzed_files=analyzed_files,
        )

        category_score = norm_result.category_score

        if len(findings) == 0:
            explanation = (
                f"Zero debt findings detected in {category.display_name}. "
                f"Architecture is clean in this category (Score: 0.0/100)."
            )
        else:
            explanation = (
                f"Category {category.display_name} has {len(findings)} finding(s) "
                f"(Critical: {severity_counts[Severity.CRITICAL]}, "
                f"High: {severity_counts[Severity.HIGH]}, "
                f"Med: {severity_counts[Severity.MEDIUM]}, "
                f"Low: {severity_counts[Severity.LOW]}). "
                f"Raw penalty: {raw_penalty:.2f} pts; "
                f"Scale-normalized penalty: {norm_result.normalized_penalty:.2f} pts. "
                f"Category score: {category_score:.1f}/100."
            )

        return CategoryScoreBreakdown(
            category=category,
            status=CategoryAnalysisStatus.ANALYZED,
            score=category_score,
            finding_count=len(findings),
            severity_counts=severity_counts,
            weight=base_weight,
            weighted_score=0.0,  # Will be populated during overall aggregation
            raw_deduction=round(raw_penalty, 2),
            normalized_penalty=norm_result.normalized_penalty,
            explanation=explanation,
            top_rules=top_rules,
        )


category_scorer = CategoryScorer()
