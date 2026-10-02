"""Deterministic scan comparison and trend calculation service."""

from __future__ import annotations

import collections
import logging
from typing import TYPE_CHECKING

from app.comparison.models import (
    CategoryComparison,
    CategoryTrendPoint,
    ComparisonFindingItem,
    ComparisonSummary,
    FindingLifecycleStatus,
    RepositoryTrendResponse,
    RuleComparison,
    ScanComparisonResult,
    ScoreComparison,
    TrendPoint,
)
from app.models.domain.enums import DebtCategory, DebtScoreTier
from app.models.domain.finding import Finding
from app.models.domain.scan import RepositoryScanResult
from app.persistence.database import ScanDatabase, scan_db

if TYPE_CHECKING:
    pass

logger = logging.getLogger("entropy.comparison")

CATEGORY_DISPLAY_NAMES: dict[DebtCategory, str] = {
    DebtCategory.ERROR_HANDLING: "Error Handling Debt",
    DebtCategory.AUTHENTICATION_CONSISTENCY: "Authentication Consistency",
    DebtCategory.AUTHORIZATION_CONSISTENCY: "Authorization Consistency",
    DebtCategory.INPUT_VALIDATION: "Input Validation Consistency",
    DebtCategory.LOGGING_AND_SECRETS: "Logging & Secret Handling",
    DebtCategory.CODE_DUPLICATION: "Code Duplication & Boilerplate",
    DebtCategory.ARCHITECTURAL_CONSISTENCY: "Architectural Consistency",
}


class ComparisonService:
    """Deterministic comparison engine comparing two persisted repository scans."""

    def __init__(self, db: ScanDatabase | None = None) -> None:
        self.db = db or scan_db

    def compare_scans(
        self,
        current_scan: RepositoryScanResult,
        previous_scan: RepositoryScanResult,
    ) -> ScanComparisonResult:
        """Deterministically compare previous and current scans without executing analysis.

        Answers: 'How has this codebase's architectural/security debt changed between scans?'
        """
        repo_id = (
            current_scan.repository.repository_id
            or current_scan.repository.derive_repository_id(
                current_scan.repository.path, current_scan.repository.remote_url
            )
        )

        # 1. Finding Lifecycle Classification (Fingerprint matching)
        prev_findings = previous_scan.findings or []
        curr_findings = current_scan.findings or []

        prev_grouped: dict[str, list[Finding]] = collections.defaultdict(list)
        for f in prev_findings:
            prev_grouped[f.fingerprint].append(f)

        curr_grouped: dict[str, list[Finding]] = collections.defaultdict(list)
        for f in curr_findings:
            curr_grouped[f.fingerprint].append(f)

        all_fps = set(prev_grouped.keys()) | set(curr_grouped.keys())

        # Historical scan counts for persistence calculation
        history_scans = self.db.get_repository_scan_history(repo_id)
        fp_frequency: dict[str, int] = collections.defaultdict(int)
        fp_first_seen: dict[str, str] = {}
        for past_scan in history_scans:
            for f in past_scan.findings:
                fp_frequency[f.fingerprint] += 1
                if f.fingerprint not in fp_first_seen:
                    fp_first_seen[f.fingerprint] = past_scan.scan_id

        new_items: list[ComparisonFindingItem] = []
        resolved_items: list[ComparisonFindingItem] = []
        persistent_items: list[ComparisonFindingItem] = []

        for fp in sorted(all_fps):
            p_list = prev_grouped.get(fp, [])
            c_list = curr_grouped.get(fp, [])

            p_list.sort(key=lambda item: (item.line_start, item.line_end, item.id))
            c_list.sort(key=lambda item: (item.line_start, item.line_end, item.id))

            match_count = min(len(p_list), len(c_list))

            # Matched findings are persistent across both scans
            for i in range(match_count):
                f = c_list[i]
                persistent_items.append(
                    self._create_finding_item(
                        f=f,
                        lifecycle=FindingLifecycleStatus.PERSISTENT,
                        resolution_status=None,
                        first_seen_scan_id=fp_first_seen.get(fp, previous_scan.scan_id),
                        last_seen_scan_id=current_scan.scan_id,
                        seen_count=max(2, fp_frequency.get(fp, 2)),
                    )
                )

            # Excess findings in current scan are NEW
            for f in c_list[match_count:]:
                new_items.append(
                    self._create_finding_item(
                        f=f,
                        lifecycle=FindingLifecycleStatus.NEW,
                        resolution_status=None,
                        first_seen_scan_id=current_scan.scan_id,
                        last_seen_scan_id=current_scan.scan_id,
                        seen_count=max(1, fp_frequency.get(fp, 1)),
                    )
                )

            # Excess findings in previous scan are RESOLVED
            for f in p_list[match_count:]:
                resolved_items.append(
                    self._create_finding_item(
                        f=f,
                        lifecycle=FindingLifecycleStatus.RESOLVED,
                        resolution_status="No longer detected since previous scan",
                        first_seen_scan_id=fp_first_seen.get(fp, previous_scan.scan_id),
                        last_seen_scan_id=previous_scan.scan_id,
                        seen_count=max(1, fp_frequency.get(fp, 1)),
                    )
                )

        # Deterministic sorting
        new_items.sort(
            key=lambda item: (item.file, item.line_start, item.rule_id, item.finding_id)
        )
        resolved_items.sort(
            key=lambda item: (item.file, item.line_start, item.rule_id, item.finding_id)
        )
        persistent_items.sort(
            key=lambda item: (item.file, item.line_start, item.rule_id, item.finding_id)
        )

        # 2. Score Comparison
        prev_score = previous_scan.score.total_score if previous_scan.score else None
        curr_score = current_scan.score.total_score if current_scan.score else None
        score_delta = (
            (curr_score - prev_score)
            if (curr_score is not None and prev_score is not None)
            else None
        )
        prev_band = previous_scan.score.tier if previous_scan.score else None
        curr_band = current_scan.score.tier if current_scan.score else None

        if score_delta is not None and score_delta > 0:
            direction = "increased"
            explanation = f"Architectural/security debt score increased by {score_delta} points."
        elif score_delta is not None and score_delta < 0:
            direction = "decreased"
            explanation = (
                f"Architectural/security debt score decreased by {abs(score_delta)} points."
            )
        else:
            direction = "unchanged"
            explanation = "Architectural/security debt score remained unchanged."

        score_comp = ScoreComparison(
            previous_score=prev_score,
            current_score=curr_score,
            score_delta=score_delta,
            previous_band=prev_band,
            current_band=curr_band,
            direction=direction,
            explanation=explanation,
        )

        # 3. Category Comparison (Preserves NOT_ANALYZED explicitly)
        category_comparisons: dict[str, CategoryComparison] = {}
        for cat in DebtCategory:
            cat_key = cat.value
            prev_cat = previous_scan.score.category_scores.get(cat) if previous_scan.score else None
            curr_cat = current_scan.score.category_scores.get(cat) if current_scan.score else None

            prev_status = prev_cat.status.value if prev_cat else "not_analyzed"
            curr_status = curr_cat.status.value if curr_cat else "not_analyzed"

            prev_cat_score = prev_cat.score if (prev_cat and prev_status == "analyzed") else None
            curr_cat_score = curr_cat.score if (curr_cat and curr_status == "analyzed") else None

            # Invariant: If either scan is NOT_ANALYZED, delta is None (never convert to 0)
            if (
                prev_status == "analyzed"
                and curr_status == "analyzed"
                and prev_cat_score is not None
                and curr_cat_score is not None
            ):
                cat_delta = round(curr_cat_score - prev_cat_score, 1)
            else:
                cat_delta = None

            prev_f_cnt = (
                prev_cat.finding_count
                if prev_cat
                else len([f for f in prev_findings if f.category == cat])
            )
            curr_f_cnt = (
                curr_cat.finding_count
                if curr_cat
                else len([f for f in curr_findings if f.category == cat])
            )

            category_comparisons[cat_key] = CategoryComparison(
                category=cat,
                category_name=CATEGORY_DISPLAY_NAMES.get(cat, cat.value),
                previous_score=prev_cat_score,
                current_score=curr_cat_score,
                score_delta=cat_delta,
                previous_status=prev_status,
                current_status=curr_status,
                previous_finding_count=prev_f_cnt,
                current_finding_count=curr_f_cnt,
                finding_count_delta=curr_f_cnt - prev_f_cnt,
            )

        # 4. Dynamic Rule-Level Comparison
        rule_categories: dict[str, DebtCategory] = {}
        prev_rule_counts: dict[str, int] = collections.defaultdict(int)
        curr_rule_counts: dict[str, int] = collections.defaultdict(int)

        for f in prev_findings:
            prev_rule_counts[f.rule_id] += 1
            rule_categories[f.rule_id] = f.category

        for f in curr_findings:
            curr_rule_counts[f.rule_id] += 1
            rule_categories[f.rule_id] = f.category

        all_rules = sorted(set(prev_rule_counts.keys()) | set(curr_rule_counts.keys()))
        rule_comparisons: list[RuleComparison] = []
        for r_id in all_rules:
            p_cnt = prev_rule_counts.get(r_id, 0)
            c_cnt = curr_rule_counts.get(r_id, 0)
            rule_comparisons.append(
                RuleComparison(
                    rule_id=r_id,
                    category=rule_categories.get(r_id, DebtCategory.ERROR_HANDLING),
                    previous_count=p_cnt,
                    current_count=c_cnt,
                    delta=c_cnt - p_cnt,
                )
            )
        # Sort by largest absolute delta first, then rule_id
        rule_comparisons.sort(key=lambda rc: (-abs(rc.delta), rc.rule_id))

        # 5. Summary
        summary = ComparisonSummary(
            repository_id=repo_id,
            repo_name=current_scan.repository.name,
            previous_scan_id=previous_scan.scan_id,
            current_scan_id=current_scan.scan_id,
            previous_timestamp=previous_scan.started_at,
            current_timestamp=current_scan.started_at,
            previous_commit=previous_scan.repository.commit_hash,
            current_commit=current_scan.repository.commit_hash,
            previous_score=prev_score,
            current_score=curr_score,
            score_delta=score_delta,
            new_findings_count=len(new_items),
            resolved_findings_count=len(resolved_items),
            persistent_findings_count=len(persistent_items),
            total_current_findings=len(curr_findings),
        )

        return ScanComparisonResult(
            summary=summary,
            score_comparison=score_comp,
            category_comparisons=category_comparisons,
            rule_comparisons=rule_comparisons,
            new_findings=new_items,
            resolved_findings=resolved_items,
            persistent_findings=persistent_items,
        )

    def build_repository_trend(self, repository_id: str) -> RepositoryTrendResponse:
        """Construct chronological debt trend data for a repository."""
        snapshots = self.db.get_trend(repository_id)
        repo_name = snapshots[0].repo_name if snapshots else repository_id

        if len(snapshots) == 0:
            return RepositoryTrendResponse(
                repository_id=repository_id,
                repo_name=repo_name,
                points=[],
                category_trends={},
                total_scans=0,
                message="No scan history available",
            )

        if len(snapshots) == 1:
            s = snapshots[0]
            points = [
                TrendPoint(
                    scan_id=s.scan_id,
                    timestamp=s.started_at,
                    score=s.entropy_score or 0,
                    score_band=s.score_band or DebtScoreTier.VERY_LOW,
                    finding_count=s.finding_count,
                    commit_hash=s.commit_sha,
                    branch=s.branch,
                )
            ]
            return RepositoryTrendResponse(
                repository_id=repository_id,
                repo_name=repo_name,
                points=points,
                category_trends={},
                total_scans=1,
                message="Not enough historical data for a trend",
            )

        points: list[TrendPoint] = []
        for s in snapshots:
            points.append(
                TrendPoint(
                    scan_id=s.scan_id,
                    timestamp=s.started_at,
                    score=s.entropy_score or 0,
                    score_band=s.score_band or DebtScoreTier.VERY_LOW,
                    finding_count=s.finding_count,
                    commit_hash=s.commit_sha,
                    branch=s.branch,
                )
            )

        # Build category trends from full historical scans
        history_scans = self.db.get_repository_scan_history(repository_id)
        cat_trends: dict[str, list[CategoryTrendPoint]] = collections.defaultdict(list)
        for h_scan in history_scans:
            if h_scan.score and h_scan.score.category_scores:
                for cat, breakdown in h_scan.score.category_scores.items():
                    cat_trends[cat.value].append(
                        CategoryTrendPoint(
                            scan_id=h_scan.scan_id,
                            timestamp=h_scan.started_at,
                            score=breakdown.score if breakdown.status.value == "analyzed" else None,
                            status=breakdown.status.value,
                        )
                    )

        return RepositoryTrendResponse(
            repository_id=repository_id,
            repo_name=repo_name,
            points=points,
            category_trends=dict(cat_trends),
            total_scans=len(snapshots),
            message=None,
        )

    def _create_finding_item(
        self,
        f: Finding,
        lifecycle: FindingLifecycleStatus,
        resolution_status: str | None,
        first_seen_scan_id: str | None,
        last_seen_scan_id: str | None,
        seen_count: int | None,
    ) -> ComparisonFindingItem:
        """Helper to convert a Finding into a ComparisonFindingItem."""
        return ComparisonFindingItem(
            finding_id=f.id,
            fingerprint=f.fingerprint,
            category=f.category,
            rule_id=f.rule_id,
            severity=f.severity,
            confidence=f.confidence,
            file=f.file,
            line_start=f.line_start,
            line_end=f.line_end,
            symbol=f.symbol,
            title=f.title,
            description=f.description,
            lifecycle=lifecycle,
            resolution_status=resolution_status,
            first_seen_scan_id=first_seen_scan_id,
            last_seen_scan_id=last_seen_scan_id,
            seen_in_scans_count=seen_count,
        )


comparison_service = ComparisonService()
