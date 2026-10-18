"""Phase 2 Unit Tests: Language Coverage Tracking & Partial Coverage Status.

Verifies:
1. In a JS/TS Express app with unprotected admin routes, Authentication and Authorization
   analyzers (which currently support only Python) are marked NOT_ANALYZED, with score None.
2. They are NEVER presented as "clean" (0.0).
3. The overall score result is marked with status PARTIAL (ScoringStatus.PARTIAL).
4. Coverage metadata provides per-category analysis status, supported vs present languages,
   and covered LOC percentage.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path

from app.models.domain.enums import (
    DebtCategory,
    SupportedLanguage,
)
from app.models.domain.manifest import (
    RepositoryManifest,
    RepositoryManifestSummary,
    SourceFileMetadata,
)
from app.models.domain.scan import RepositoryMetadata, RepositoryScanResult, ScanStatus
from app.scoring.models import CategoryAnalysisStatus, ScoringStatus
from app.scoring.service import scoring_service
from app.services.repository_service import repository_service


def test_express_unprotected_routes_reported_not_analyzed_never_clean():
    """An Express app without Python files must report Auth/Authz as NOT_ANALYZED, never clean (0.0)."""
    fixture_path = Path(__file__).parent.parent / "fixtures" / "auth" / "express" / "unprotected_express.js"
    content = fixture_path.read_text()

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir)
        app_file = repo_dir / "app.js"
        app_file.write_text(content)

        # Create scan record with manifest
        scan_id = "test-scan-express-coverage"
        manifest = RepositoryManifest(
            repository=RepositoryManifestSummary(
                name="express-unprotected-app",
                path=str(repo_dir),
                scan_timestamp=datetime.now(UTC),
                total_files=1,
                source_files=1,
                ignored_files=0,
                skipped_files=0,
                total_source_size=len(content),
                total_source_loc=len(content.splitlines()),
            ),
            languages={"javascript": 1},
            files=[
                SourceFileMetadata(
                    path="app.js",
                    language=SupportedLanguage.JAVASCRIPT,
                    size=len(content),
                    line_count=len(content.splitlines()),
                    analysis_supported=True,
                )
            ],
            skipped_files=[],
        )

        repo_meta = RepositoryMetadata(
            name="express-unprotected-app",
            path=str(repo_dir),
            total_files=1,
            scannable_files=1,
            total_loc=len(content.splitlines()),
        )

        scan_result = RepositoryScanResult(
            scan_id=scan_id,
            repository=repo_meta,
            status=ScanStatus.COMPLETED,
            manifest=manifest,
            findings=[],
            score=None,
            started_at=manifest.repository.scan_timestamp.isoformat(),
            analyzers_executed=[],
            errors=[],
        )
        repository_service.save_scan(scan_result)

        # Calculate score through scoring service
        score_result = scoring_service.calculate_scan_score(scan_id, force_recalculate=True)

        # 1. Overall status must be PARTIAL because auth/authz are not analyzed
        assert score_result.status == ScoringStatus.PARTIAL, f"Expected PARTIAL, got {score_result.status}"

        # 2. Coverage metadata must be populated
        assert score_result.coverage is not None
        assert score_result.coverage.is_partial is True
        assert "javascript" in score_result.coverage.present_languages
        assert score_result.coverage.loc_coverage_percentage > 0.0

        # 3. Authentication category MUST either be flagged or NOT_ANALYZED, NEVER clean (0.0)
        auth_breakdown = score_result.category_scores[DebtCategory.AUTHENTICATION_CONSISTENCY]
        if auth_breakdown.status == CategoryAnalysisStatus.NOT_ANALYZED:
            assert auth_breakdown.score is None, "Unanalyzed category must have score None, never 0.0"
            assert "No supported-language files" in auth_breakdown.explanation
            assert "Python" in auth_breakdown.explanation
        else:
            # If an analyzer flags findings in Phase 3, it must not be clean 0.0
            assert auth_breakdown.score is not None and auth_breakdown.score > 0.0

        # 4. Authorization category MUST either be flagged or NOT_ANALYZED, NEVER clean (0.0)
        authz_breakdown = score_result.category_scores[DebtCategory.AUTHORIZATION_CONSISTENCY]
        if authz_breakdown.status == CategoryAnalysisStatus.NOT_ANALYZED:
            assert authz_breakdown.score is None, "Unanalyzed category must have score None, never 0.0"
            assert "No supported-language files" in authz_breakdown.explanation
            assert "Python" in authz_breakdown.explanation
        else:
            assert authz_breakdown.score is not None and authz_breakdown.score > 0.0
