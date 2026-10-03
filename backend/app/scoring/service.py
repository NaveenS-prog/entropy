"""Scoring service coordinating repository metadata, Phase 3 findings, and Phase 4 scoring."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.core.errors import RepositoryNotFoundError
from app.models.domain.enums import DebtCategory
from app.scoring.entropy_scorer import EntropyScorer, entropy_scorer
from app.scoring.models import DebtScoreResult

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

        # Ensure Phase 3 findings are generated
        findings = self.analy_service.analyze_scan(scan_id)

        # Codebase scale metrics from manifest
        manifest_repo = scan.manifest.repository
        total_loc = manifest_repo.total_source_loc
        analyzed_files = len([f for f in scan.manifest.files if f.analysis_supported])
        skipped_files = manifest_repo.skipped_files

        # Determine active analyzed categories from registered analyzers if not specified
        active_cats = (
            analyzed_categories
            if analyzed_categories is not None
            else {a.category for a in self.analy_service.registry.get_all()}
        )

        # Phase 15: Suppressed findings MUST NOT contribute to score
        active_findings = [f for f in findings if not getattr(f, "is_suppressed", False)]

        # Compute deterministic score
        score_result = self.scorer.calculate_score(
            findings=active_findings,
            total_loc=total_loc,
            analyzed_files=analyzed_files,
            skipped_files=skipped_files,
            analyzed_categories=active_cats,
        )

        # Persist on scan record
        scan.score = score_result
        self.repo_service.save_scan(scan)
        logger.info(
            "Computed Entropy Score for scan '%s': %d/100 (%s) across %d finding(s)",
            scan_id,
            score_result.total_score,
            score_result.tier.value,
            len(findings),
        )
        return score_result

    def get_score(self, scan_id: str) -> DebtScoreResult:
        """Retrieve or compute the score for a specific scan."""
        return self.calculate_scan_score(scan_id)


scoring_service = ScoringService()
