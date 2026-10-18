"""Calibration ordering and score sensitivity tests.

Verifies:
1. Monotonicity of architectural quality: Clean App < Mildly Messy App < Insecure App.
2. Insecure Python FastAPI app lands in at least the MODERATE debt band (score >= 41).
3. Parity and consistency across languages where features are analyzed.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path

from app.models.domain.enums import DebtScoreTier, SupportedLanguage
from app.models.domain.manifest import (
    RepositoryManifest,
    RepositoryManifestSummary,
    SourceFileMetadata,
)
from app.models.domain.scan import RepositoryMetadata, RepositoryScanResult, ScanStatus
from app.scoring.models import DebtScoreResult
from app.scoring.service import scoring_service
from app.services.repository_service import repository_service

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _scan_single_file(file_path: Path, language: SupportedLanguage, scan_id: str) -> DebtScoreResult:
    """Helper to scan a single source file and compute its authoritative score."""
    content = file_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir)
        target_file = repo_dir / file_path.name
        target_file.write_text(content, encoding="utf-8")

        manifest = RepositoryManifest(
            repository=RepositoryManifestSummary(
                name=file_path.stem,
                path=str(repo_dir),
                scan_timestamp=datetime.now(UTC),
                total_files=1,
                source_files=1,
                ignored_files=0,
                skipped_files=0,
                total_source_size=len(content),
                total_source_loc=len(lines),
            ),
            languages={language.value: 1},
            files=[
                SourceFileMetadata(
                    path=file_path.name,
                    language=language,
                    size=len(content),
                    line_count=len(lines),
                    analysis_supported=True,
                )
            ],
            skipped_files=[],
        )

        repo_meta = RepositoryMetadata(
            name=file_path.stem,
            path=str(repo_dir),
            total_files=1,
            scannable_files=1,
            total_loc=len(lines),
        )

        scan_result = RepositoryScanResult(
            scan_id=scan_id,
            repository=repo_meta,
            status=ScanStatus.COMPLETED,
            manifest=manifest,
            findings=[],
            score=None,
            started_at=datetime.now(UTC).isoformat(),
            analyzers_executed=[],
            errors=[],
        )
        repository_service.save_scan(scan_result)

        return scoring_service.calculate_scan_score(scan_id, force_recalculate=True)


class TestCalibrationOrdering:
    """Validates calibration evidence and expected score ordering across application archetypes."""

    def test_python_apps_score_ordering(self):
        """Clean < Mildly Messy < Deliberately Insecure in Python."""
        clean_file = FIXTURES_DIR / "python" / "clean" / "main.py"
        messy_file = FIXTURES_DIR / "python" / "mildly_messy" / "main.py"
        insecure_file = FIXTURES_DIR / "python" / "insecure" / "main.py"

        clean_score = _scan_single_file(clean_file, SupportedLanguage.PYTHON, "calib-py-clean")
        messy_score = _scan_single_file(messy_file, SupportedLanguage.PYTHON, "calib-py-messy")
        insecure_score = _scan_single_file(insecure_file, SupportedLanguage.PYTHON, "calib-py-insecure")

        print("\n--- Python Calibration Results ---")
        print(f"Clean App:      Score = {clean_score.total_score} ({clean_score.tier.label})")
        print(f"Mildly Messy:   Score = {messy_score.total_score} ({messy_score.tier.label})")
        print(f"Insecure App:   Score = {insecure_score.total_score} ({insecure_score.tier.label})")

        # 1. Clean app must have lowest score (VERY_LOW)
        assert clean_score.total_score == 0
        assert clean_score.tier == DebtScoreTier.VERY_LOW

        # 2. Score strictly increases with defect severity
        assert clean_score.total_score < messy_score.total_score < insecure_score.total_score

        # 3. Deliberately insecure app MUST land in at least the MODERATE band (score >= 41)
        assert insecure_score.total_score >= 41, (
            f"Expected insecure app score >= 41 (MODERATE+), but got {insecure_score.total_score}"
        )
        assert insecure_score.tier in (
            DebtScoreTier.MODERATE,
            DebtScoreTier.HIGH,
            DebtScoreTier.VERY_HIGH,
        )

    def test_jsts_apps_score_ordering(self):
        """Clean < Mildly Messy < Deliberately Insecure in JS/TS."""
        clean_file = FIXTURES_DIR / "jsts" / "clean" / "app.js"
        messy_file = FIXTURES_DIR / "jsts" / "mildly_messy" / "app.js"
        insecure_file = FIXTURES_DIR / "jsts" / "insecure" / "app.js"

        clean_score = _scan_single_file(clean_file, SupportedLanguage.JAVASCRIPT, "calib-js-clean")
        messy_score = _scan_single_file(messy_file, SupportedLanguage.JAVASCRIPT, "calib-js-messy")
        insecure_score = _scan_single_file(insecure_file, SupportedLanguage.JAVASCRIPT, "calib-js-insecure")

        print("\n--- JS/TS Calibration Results ---")
        print(f"Clean App:      Score = {clean_score.total_score} ({clean_score.tier.label})")
        print(f"Mildly Messy:   Score = {messy_score.total_score} ({messy_score.tier.label})")
        print(f"Insecure App:   Score = {insecure_score.total_score} ({insecure_score.tier.label})")

        # 1. Zero debt for clean app
        assert clean_score.total_score == 0

        # 2. Score strictly increases with defect severity
        assert clean_score.total_score < messy_score.total_score < insecure_score.total_score

        # 3. Deliberately insecure app MUST land in at least the MODERATE band (score >= 41)
        assert insecure_score.total_score >= 41, (
            f"Expected insecure JS app score >= 41 (MODERATE+), but got {insecure_score.total_score}"
        )
        assert insecure_score.tier in (
            DebtScoreTier.MODERATE,
            DebtScoreTier.HIGH,
            DebtScoreTier.VERY_HIGH,
        )
