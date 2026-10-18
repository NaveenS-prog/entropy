"""Scoring service coordinating repository metadata, analyzer findings, and entropy scoring."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.core.errors import RepositoryNotFoundError
from app.models.domain.enums import DebtCategory
from app.scoring.entropy_scorer import EntropyScorer, entropy_scorer
from app.scoring.models import (
    CategoryAnalysisStatus,
    CategoryCoverage,
    DebtScoreResult,
    ScoringCoverage,
)

if TYPE_CHECKING:
    from app.services.analysis_service import AnalysisService
    from app.services.repository_service import RepositoryService

logger = logging.getLogger("entropy.scoring.service")


class ScoringService:
    """Service orchestrating deterministic Entropy Debt Score computation."""

    def __init__(
        self,
        scorer: EntropyScorer | None = None,
        repo_service: RepositoryService | None = None,
        analy_service: AnalysisService | None = None,
    ) -> None:
        self.scorer = scorer or entropy_scorer
        self._repo_service = repo_service
        self._analy_service = analy_service

    @property
    def repo_service(self) -> RepositoryService:
        if self._repo_service is None:
            from app.services.repository_service import repository_service

            self._repo_service = repository_service
        return self._repo_service

    @property
    def analy_service(self) -> AnalysisService:
        if self._analy_service is None:
            from app.services.analysis_service import analysis_service

            self._analy_service = analysis_service
        return self._analy_service

    def calculate_scan_score(
        self,
        scan_id: str,
        force_recalculate: bool = False,
        analyzed_categories: set[DebtCategory] | None = None,
    ) -> DebtScoreResult:
        """Calculate and attach the Entropy Debt Score for a scan."""
        scan = self.repo_service.get_scan(scan_id)
        if not scan:
            raise RepositoryNotFoundError(f"Scan '{scan_id}' not found")
        if not scan.manifest:
            raise RepositoryNotFoundError(f"Scan '{scan_id}' has no repository manifest")

        # Return cached score if present and recalculation not forced
        if scan.score is not None and not force_recalculate:
            return scan.score

        # Ensure findings are generated
        findings = self.analy_service.analyze_scan(scan_id)

        # Codebase scale metrics from manifest
        manifest_repo = scan.manifest.repository
        manifest_files = scan.manifest.files
        total_loc = manifest_repo.total_source_loc
        analyzed_files = len([f for f in manifest_files if f.analysis_supported])
        skipped_files = manifest_repo.skipped_files

        # 1. Discover programming languages present in codebase
        present_langs_set: set[str] = set()
        for f in manifest_files:
            if f.language and str(f.language).lower() != "unknown":
                lang_str = f.language.value if hasattr(f.language, "value") else str(f.language)
                present_langs_set.add(lang_str.lower())

        if not present_langs_set and scan.manifest.languages:
            for lang_k in scan.manifest.languages.keys():
                if lang_k.lower() != "unknown":
                    present_langs_set.add(lang_k.lower())

        # 2. Map registered analyzers' supported languages per category
        cat_to_supported_langs: dict[DebtCategory, set[str]] = {}
        all_supported_langs: set[str] = set()
        for analyzer in self.analy_service.registry.get_all():
            langs = {
                (lang.value if hasattr(lang, "value") else str(lang)).lower()
                for lang in analyzer.supported_languages
            }
            cat_to_supported_langs.setdefault(analyzer.category, set()).update(langs)
            all_supported_langs.update(langs)

        # 3. Determine per-category language coverage
        cat_coverages: dict[DebtCategory, CategoryCoverage] = {}
        cat_explanations: dict[DebtCategory, str] = {}
        active_supported_cats: set[DebtCategory] = set()

        for category in DebtCategory:
            cat_supported = cat_to_supported_langs.get(category, set())
            # Category has supported files if present languages intersect supported languages
            # If no present languages were detected (e.g. empty manifest), fallback to presence of analyzers
            has_supported_file = (
                bool(cat_supported & present_langs_set)
                if present_langs_set
                else (category in cat_to_supported_langs)
            )

            sup_langs_sorted = sorted(list(cat_supported))
            pres_langs_sorted = sorted(list(present_langs_set))

            if has_supported_file:
                cat_coverages[category] = CategoryCoverage(
                    category=category,
                    status=CategoryAnalysisStatus.ANALYZED,
                    supported_languages=sup_langs_sorted,
                    present_languages=pres_langs_sorted,
                    is_analyzed=True,
                    explanation=None,
                )
                active_supported_cats.add(category)
            else:
                sup_display = ", ".join(lang.capitalize() for lang in sup_langs_sorted) if sup_langs_sorted else "None"
                expl = f"No supported-language files for this analyzer (supports: {sup_display})"
                cat_coverages[category] = CategoryCoverage(
                    category=category,
                    status=CategoryAnalysisStatus.NOT_ANALYZED,
                    supported_languages=sup_langs_sorted,
                    present_languages=pres_langs_sorted,
                    is_analyzed=False,
                    explanation=expl,
                )
                cat_explanations[category] = expl

        # 4. Compute LOC coverage percentage across all analyzers
        covered_loc = 0
        for f in manifest_files:
            flang = (f.language.value if hasattr(f.language, "value") else str(f.language)).lower()
            if flang in all_supported_langs:
                covered_loc += (f.line_count or 0)

        loc_cov_pct = round((covered_loc / total_loc) * 100.0, 1) if total_loc > 0 else 100.0

        # 5. Check if Auth or Authz categories are unanalyzed -> partial coverage
        auth_cov = cat_coverages.get(DebtCategory.AUTHENTICATION_CONSISTENCY)
        authz_cov = cat_coverages.get(DebtCategory.AUTHORIZATION_CONSISTENCY)
        is_partial = not (
            auth_cov and auth_cov.is_analyzed and authz_cov and authz_cov.is_analyzed
        )

        coverage = ScoringCoverage(
            categories=cat_coverages,
            present_languages=sorted(list(present_langs_set)),
            supported_languages=sorted(list(all_supported_langs)),
            total_loc=total_loc,
            covered_loc=covered_loc,
            loc_coverage_percentage=loc_cov_pct,
            is_partial=is_partial,
        )

        # 6. Restrict active categories to those supported by repository languages
        if analyzed_categories is not None:
            active_cats = analyzed_categories.intersection(active_supported_cats)
        else:
            active_cats = active_supported_cats

        # Suppressed findings MUST NOT contribute to score
        active_findings = [f for f in findings if not getattr(f, "is_suppressed", False)]

        # Compute deterministic score
        score_result = self.scorer.calculate_score(
            findings=active_findings,
            total_loc=total_loc,
            analyzed_files=analyzed_files,
            skipped_files=skipped_files,
            analyzed_categories=active_cats,
            coverage=coverage,
            category_explanations=cat_explanations,
        )

        # Persist on scan record
        scan.score = score_result
        self.repo_service.save_scan(scan)
        logger.info(
            "Computed Entropy Score for scan '%s': %d/100 (%s, status=%s) across %d finding(s)",
            scan_id,
            score_result.total_score,
            score_result.tier.value,
            score_result.status.value,
            len(findings),
        )
        return score_result

    def get_score(self, scan_id: str) -> DebtScoreResult:
        """Retrieve or compute the score for a specific scan."""
        return self.calculate_scan_score(scan_id)


scoring_service = ScoringService()
