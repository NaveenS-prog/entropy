"""Unit tests for Phase 7 primary output and experimental score reporting.

Verifies:
- CLI text format puts Category Breakdown and Top Findings as primary outputs before Score.
- CLI text format marks Score as [EXPERIMENTAL] and displays coverage and scope exclusions.
- CLI JSON format includes experimental flag on score, top_findings, and categories.
- API models (DebtScoreResult, ScanSummaryResponse, ScanDetailResponse) expose is_experimental,
  categories, and top_findings.
"""

from datetime import UTC, datetime

from app.cli.main import format_scan_json_dict, format_scan_text
from app.models.domain.enums import Confidence, DebtCategory, DebtScoreTier, ScanStatus, Severity
from app.models.domain.finding import CodeEvidence, Finding
from app.models.domain.scan import RepositoryMetadata, RepositoryScanResult
from app.schemas.scan_schemas import ScanDetailResponse, ScanSummaryResponse
from app.scoring.models import (
    CategoryAnalysisStatus,
    CategoryScoreBreakdown,
    DebtScoreResult,
    ScoringCoverage,
)


def _make_dummy_scan() -> RepositoryScanResult:
    repo_meta = RepositoryMetadata(
        name="sample-repo",
        path="/path/to/sample-repo",
        total_files=10,
        scannable_files=7,
        total_loc=1200,
        excluded_files=3,
        excluded_loc=350,
    )

    finding1 = Finding(
        id="f-auth-001",
        rule_id="ENT-AUTH-001",
        title="Hardcoded Secret Key",
        description="JWT secret is hardcoded in auth.py",
        category=DebtCategory.AUTHENTICATION_CONSISTENCY,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file="app/auth.py",
        line_start=15,
        line_end=15,
        column_start=1,
        column_end=20,
        evidence=CodeEvidence(
            content='SECRET = "hardcoded"',
            line_start=15,
            line_end=15,
            highlight_lines=[15],
        ),
        impact="Compromises authentication tokens",
        recommendation="Use environment variables",
        fingerprint="fp-auth-001",
    )
    finding2 = Finding(
        id="f-err-001",
        rule_id="ENT-ERR-001",
        title="Broad Exception Handling",
        description="Catching broad Exception",
        category=DebtCategory.ERROR_HANDLING,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        file="app/handler.py",
        line_start=42,
        line_end=45,
        column_start=5,
        column_end=10,
        evidence=CodeEvidence(
            content="except Exception: pass",
            line_start=42,
            line_end=45,
            highlight_lines=[42],
        ),
        impact="Silently suppresses unexpected bugs",
        recommendation="Catch specific exceptions",
        fingerprint="fp-err-001",
    )

    category_scores = {
        DebtCategory.ERROR_HANDLING: CategoryScoreBreakdown(
            category=DebtCategory.ERROR_HANDLING,
            status=CategoryAnalysisStatus.ANALYZED,
            score=12.0,
            finding_count=1,
            weight=1.0,
            explanation="1 error handling finding detected",
        ),
        DebtCategory.AUTHENTICATION_CONSISTENCY: CategoryScoreBreakdown(
            category=DebtCategory.AUTHENTICATION_CONSISTENCY,
            status=CategoryAnalysisStatus.ANALYZED,
            score=45.0,
            finding_count=1,
            weight=1.0,
            explanation="1 critical auth finding detected",
        ),
    }

    coverage = ScoringCoverage(
        total_loc=1200,
        covered_loc=1200,
        loc_coverage_percentage=100.0,
        present_languages=["Python"],
        supported_languages=["Python"],
    )

    score_result = DebtScoreResult(
        total_score=28,
        score_density=28,
        tier=DebtScoreTier.LOW,
        category_scores=category_scores,
        total_findings=2,
        total_loc=1200,
        analyzed_files=7,
        coverage=coverage,
        formula_summary="Standard polynomial normalization",
    )

    return RepositoryScanResult(
        scan_id="test-scan-phase7",
        repository=repo_meta,
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(UTC),
        findings=[finding2, finding1],  # Intentionally out of order to test sorting
        score=score_result,
    )


def test_cli_text_primary_outputs_and_experimental_score():
    scan = _make_dummy_scan()
    text = format_scan_text(scan)

    # 1. Primary outputs: Category Breakdown and Top Findings must precede Score
    cat_pos = text.find("Category Breakdown")
    findings_pos = text.find("Top Findings")
    score_pos = text.find("Entropy Score")

    assert cat_pos != -1, "Category Breakdown must be present"
    assert findings_pos != -1, "Top Findings must be present"
    assert score_pos != -1, "Entropy Score must be present"

    assert cat_pos < score_pos, "Category Breakdown must precede Entropy Score"
    assert findings_pos < score_pos, "Top Findings must precede Entropy Score"

    # 2. Score must be marked [EXPERIMENTAL]
    assert "[EXPERIMENTAL]" in text

    # 3. Coverage and exclusions must be displayed next to / under score
    assert "Coverage: 100.0% LOC analyzed" in text
    assert "Scope Exclusions: 3 files (350 LOC excluded)" in text

    # 4. Top Findings must display sorted by severity (CRITICAL before MEDIUM)
    critical_pos = text.find("[CRITICAL] ENT-AUTH-001")
    medium_pos = text.find("[MEDIUM] ENT-ERR-001")
    assert critical_pos != -1
    assert medium_pos != -1
    assert critical_pos < medium_pos


def test_cli_json_experimental_flag_and_top_findings():
    scan = _make_dummy_scan()
    data = format_scan_json_dict(scan)

    # 1. Score section must have experimental flags
    assert data["score"]["experimental"] is True
    assert data["score"]["is_experimental"] is True

    # 2. Root structure includes categories and top_findings
    assert "categories" in data
    assert "top_findings" in data
    assert len(data["top_findings"]) == 2

    # Top finding should be the CRITICAL auth finding
    assert data["top_findings"][0]["rule_id"] == "ENT-AUTH-001"
    assert data["top_findings"][0]["severity"] == "critical"

    # Exclusions are correctly present
    assert data["files"]["excluded_files"] == 3
    assert data["files"]["excluded_loc"] == 350


def test_api_schemas_experimental_and_primary_outputs():
    scan = _make_dummy_scan()

    # 1. DebtScoreResult
    assert scan.score.is_experimental is True

    # 2. ScanSummaryResponse
    summary = ScanSummaryResponse(
        scan_id=scan.scan_id,
        repo_name=scan.repository.name,
        repo_path=scan.repository.path,
        status=scan.status,
        total_score=scan.score.total_score,
        tier=scan.score.tier,
        started_at=scan.started_at,
    )
    assert summary.is_experimental is True

    # 3. ScanDetailResponse auto-population
    detail = ScanDetailResponse(
        scan_id=scan.scan_id,
        repository=scan.repository,
        status=scan.status,
        findings=scan.findings,
        score=scan.score,
        started_at=scan.started_at,
    )
    assert detail.is_experimental is True
    assert "authentication_consistency" in detail.categories
    assert "error_handling" in detail.categories
    assert len(detail.top_findings) == 2
    assert detail.top_findings[0].rule_id == "ENT-AUTH-001"
    assert detail.top_findings[0].severity == Severity.CRITICAL
