"""Deterministic, explainable scoring engine for Silent Security Debt."""

import math

from app.models.domain.enums import DebtCategory, DebtScoreTier, Severity
from app.models.domain.finding import Finding
from app.models.domain.scoring import CategoryScoreBreakdown, DebtScoreResult
from app.scoring.weights import (
    CATEGORY_WEIGHTS,
    CONFIDENCE_MULTIPLIERS,
    SATURATION_FACTOR,
    SEVERITY_POINTS,
)


class ScoringEngine:
    """Computes transparent, explainable Silent Security Debt Scores (0-100).

    Strictly satisfies:
    1. Consumes findings rather than directly inspecting source code.
    2. Completely deterministic - identical findings yield identical scores.
    3. Fully auditable - every score includes mathematical step-by-step breakdown.
    4. Bounded: 0-20 Very Low, 21-40 Low, 41-60 Moderate, 61-80 High, 81-100 Very High.
    """

    def calculate_score(
        self,
        findings: list[Finding],
        total_loc: int = 0,
        analyzed_files: int = 0,
        skipped_files: int = 0,
    ) -> DebtScoreResult:
        """Calculate the comprehensive debt score from a list of findings."""
        # Group findings by category
        grouped_findings: dict[DebtCategory, list[Finding]] = {cat: [] for cat in DebtCategory}
        for finding in findings:
            if finding.category in grouped_findings:
                grouped_findings[finding.category].append(finding)

        category_breakdowns: dict[DebtCategory, CategoryScoreBreakdown] = {}
        audit_trail: list[str] = [
            f"Initialized scoring for {len(findings)} finding(s) across {analyzed_files} file(s) ({total_loc} LOC)."
        ]

        total_weighted_score = 0.0

        for category, cat_findings in grouped_findings.items():
            weight = CATEGORY_WEIGHTS.get(category, 0.0)

            # Count severities
            severity_counts = {s: 0 for s in Severity}
            raw_deduction = 0.0

            for f in cat_findings:
                severity_counts[f.severity] += 1
                base_points = SEVERITY_POINTS.get(f.severity, 1.0)
                conf_mult = CONFIDENCE_MULTIPLIERS.get(f.confidence, 1.0)
                raw_deduction += base_points * conf_mult

            # Calculate normalized category debt score (0.0 to 100.0)
            if raw_deduction <= 0:
                cat_score = 0.0
                explanation = (
                    f"No debt findings detected in {category.display_name}. Score: 0.0/100."
                )
            else:
                # Asymptotic curve: 100 * (1 - e^(-raw / K))
                cat_score = 100.0 * (1.0 - math.exp(-raw_deduction / SATURATION_FACTOR))
                cat_score = min(100.0, max(0.0, cat_score))
                explanation = (
                    f"Category {category.display_name} has {len(cat_findings)} finding(s) "
                    f"yielding raw penalty of {raw_deduction:.2f} pts "
                    f"(Critical: {severity_counts[Severity.CRITICAL]}, "
                    f"High: {severity_counts[Severity.HIGH]}, "
                    f"Med: {severity_counts[Severity.MEDIUM]}, "
                    f"Low: {severity_counts[Severity.LOW]}, "
                    f"Info: {severity_counts[Severity.INFO]}). "
                    f"Normalized score: {cat_score:.1f}/100."
                )

            weighted_contribution = cat_score * weight
            total_weighted_score += weighted_contribution

            breakdown = CategoryScoreBreakdown(
                category=category,
                score=round(cat_score, 1),
                finding_count=len(cat_findings),
                severity_counts=severity_counts,
                weight=weight,
                weighted_score=round(weighted_contribution, 2),
                raw_deduction=round(raw_deduction, 2),
                explanation=explanation,
            )
            category_breakdowns[category] = breakdown

            if len(cat_findings) > 0:
                audit_trail.append(
                    f"[{category.value}] Raw penalty: {raw_deduction:.2f} -> Score: {cat_score:.1f}/100 "
                    f"(weight {weight * 100:.0f}%, contribution: {weighted_contribution:.2f})"
                )

        final_score = int(round(total_weighted_score))
        final_score = max(0, min(100, final_score))
        tier = DebtScoreTier.from_score(final_score)

        audit_trail.append(
            f"Total aggregated debt score: {final_score}/100 ({tier.label}). "
            f"Calculated from sum of category scores weighted by their architectural risk factor."
        )

        formula_summary = (
            "Total Score = Round( Σ (Category_Score_i × Weight_i) ), where "
            "Category_Score = 100 × (1 - e^(-Raw_Penalty / 20.0)) and "
            "Raw_Penalty = Σ (Severity_Points × Confidence_Multiplier)"
        )

        return DebtScoreResult(
            total_score=final_score,
            tier=tier,
            category_scores=category_breakdowns,
            total_findings=len(findings),
            total_loc=total_loc,
            analyzed_files=analyzed_files,
            skipped_files=skipped_files,
            formula_summary=formula_summary,
            audit_trail=audit_trail,
            is_explainable=True,
        )


scoring_engine = ScoringEngine()
