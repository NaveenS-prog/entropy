"""Regression tests for Phase 2 framework-level coverage and NestJS route detection.

Tests:
1. NestJS fixture without guards produces ENT-AUTH-001 and ENT-AUTHZ-001 findings.
2. NestJS with @UseGuards(AuthGuard) is clean for auth (no ENT-AUTH-001).
3. A Koa-only app yields NOT_ANALYZED + PARTIAL naming koa.
4. A library with no routes yields the "no HTTP routes detected" explanation, not a clean score.
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
from app.services.analysis_service import analysis_service
from app.services.repository_service import repository_service


def test_nestjs_without_guards_produces_auth_and_authz_findings():
    """NestJS controller without guards produces ENT-AUTH-001 and ENT-AUTHZ-001 findings."""
    code = (
        "import { Controller, Delete, Get, Post } from '@nestjs/common';\n"
        "\n"
        "@Controller('admin')\n"
        "export class AdminController {\n"
        "  @Delete('users/:id')\n"
        "  deleteUser() {}\n"
        "\n"
        "  @Get('export')\n"
        "  exportData() {}\n"
        "\n"
        "  @Post('refund')\n"
        "  refund() {}\n"
        "}\n"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir)
        ctrl_file = repo_dir / "admin.controller.ts"
        ctrl_file.write_text(code, encoding="utf-8")

        scan_id = "test-scan-nestjs-unguarded"
        manifest = RepositoryManifest(
            repository=RepositoryManifestSummary(
                scan_timestamp=datetime.now(UTC),
                name="nestjs-app",
                path=str(repo_dir),
                total_files=1,
                source_files=1,
                ignored_files=0,
                skipped_files=0,
                total_source_size=len(code),
                total_source_loc=len(code.splitlines()),
            ),
            languages={"typescript": 1},
            files=[
                SourceFileMetadata(
                    path="admin.controller.ts",
                    language=SupportedLanguage.TYPESCRIPT,
                    size=len(code),
                    line_count=len(code.splitlines()),
                    analysis_supported=True,
                )
            ],
            skipped_files=[],
        )

        repo_meta = RepositoryMetadata(
            name="nestjs-app",
            path=str(repo_dir),
            total_files=1,
            scannable_files=1,
            total_loc=len(code.splitlines()),
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

        findings = analysis_service.analyze_scan(scan_id)
        score_result = scoring_service.calculate_scan_score(scan_id, force_recalculate=True)

        auth_findings = [f for f in findings if f.rule_id == "ENT-AUTH-001"]
        authz_findings = [f for f in findings if f.rule_id == "ENT-AUTHZ-001"]

        assert len(auth_findings) == 3, f"Expected 3 ENT-AUTH-001 findings, got {len(auth_findings)}"
        assert len(authz_findings) == 3, f"Expected 3 ENT-AUTHZ-001 findings, got {len(authz_findings)}"

        assert score_result.category_scores[DebtCategory.AUTHENTICATION_CONSISTENCY].status == CategoryAnalysisStatus.ANALYZED
        assert score_result.category_scores[DebtCategory.AUTHORIZATION_CONSISTENCY].status == CategoryAnalysisStatus.ANALYZED

        assert score_result.coverage is not None
        assert "nestjs" in score_result.coverage.detected_frameworks
        assert score_result.coverage.total_routes_detected == 3


def test_nestjs_with_guards_is_clean_for_auth():
    """NestJS controller with @UseGuards(AuthGuard) is clean for auth (no ENT-AUTH-001)."""
    code = (
        "import { Controller, Delete, Get, Post, UseGuards } from '@nestjs/common';\n"
        "\n"
        "@UseGuards(AuthGuard)\n"
        "@Controller('admin')\n"
        "export class AdminController {\n"
        "  @Delete('users/:id')\n"
        "  deleteUser() {}\n"
        "\n"
        "  @Get('export')\n"
        "  exportData() {}\n"
        "\n"
        "  @Post('refund')\n"
        "  refund() {}\n"
        "}\n"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir)
        ctrl_file = repo_dir / "admin.controller.ts"
        ctrl_file.write_text(code, encoding="utf-8")

        scan_id = "test-scan-nestjs-guarded"
        manifest = RepositoryManifest(
            repository=RepositoryManifestSummary(
                scan_timestamp=datetime.now(UTC),
                name="nestjs-guarded-app",
                path=str(repo_dir),
                total_files=1,
                source_files=1,
                ignored_files=0,
                skipped_files=0,
                total_source_size=len(code),
                total_source_loc=len(code.splitlines()),
            ),
            languages={"typescript": 1},
            files=[
                SourceFileMetadata(
                    path="admin.controller.ts",
                    language=SupportedLanguage.TYPESCRIPT,
                    size=len(code),
                    line_count=len(code.splitlines()),
                    analysis_supported=True,
                )
            ],
            skipped_files=[],
        )

        repo_meta = RepositoryMetadata(
            name="nestjs-guarded-app",
            path=str(repo_dir),
            total_files=1,
            scannable_files=1,
            total_loc=len(code.splitlines()),
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

        findings = analysis_service.analyze_scan(scan_id)
        score_result = scoring_service.calculate_scan_score(scan_id, force_recalculate=True)

        auth_findings = [f for f in findings if f.rule_id == "ENT-AUTH-001"]
        assert len(auth_findings) == 0, f"Expected 0 ENT-AUTH-001 findings, got {len(auth_findings)}"

        # Admin routes still lack role checks -> ENT-AUTHZ-001 fires
        authz_findings = [f for f in findings if f.rule_id == "ENT-AUTHZ-001"]
        assert len(authz_findings) == 3

        auth_breakdown = score_result.category_scores[DebtCategory.AUTHENTICATION_CONSISTENCY]
        assert auth_breakdown.status == CategoryAnalysisStatus.ANALYZED
        assert auth_breakdown.score == 0.0


def test_koa_only_app_yields_not_analyzed_and_partial_naming_koa():
    """A Koa-only app yields NOT_ANALYZED + PARTIAL naming koa in explanation."""
    code = (
        "const Koa = require('koa');\n"
        "const app = new Koa();\n"
        "app.use(async ctx => {\n"
        "  ctx.body = 'Hello World';\n"
        "});\n"
        "app.listen(3000);\n"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir)
        app_file = repo_dir / "server.js"
        app_file.write_text(code, encoding="utf-8")

        scan_id = "test-scan-koa-app"
        manifest = RepositoryManifest(
            repository=RepositoryManifestSummary(
                scan_timestamp=datetime.now(UTC),
                name="koa-app",
                path=str(repo_dir),
                total_files=1,
                source_files=1,
                ignored_files=0,
                skipped_files=0,
                total_source_size=len(code),
                total_source_loc=len(code.splitlines()),
            ),
            languages={"javascript": 1},
            files=[
                SourceFileMetadata(
                    path="server.js",
                    language=SupportedLanguage.JAVASCRIPT,
                    size=len(code),
                    line_count=len(code.splitlines()),
                    analysis_supported=True,
                )
            ],
            skipped_files=[],
        )

        repo_meta = RepositoryMetadata(
            name="koa-app",
            path=str(repo_dir),
            total_files=1,
            scannable_files=1,
            total_loc=len(code.splitlines()),
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

        score_result = scoring_service.calculate_scan_score(scan_id, force_recalculate=True)

        assert score_result.status == ScoringStatus.PARTIAL
        assert score_result.coverage is not None
        assert score_result.coverage.is_partial is True
        assert "koa" in score_result.coverage.unsupported_frameworks

        auth_cov = score_result.category_scores[DebtCategory.AUTHENTICATION_CONSISTENCY]
        assert auth_cov.status == CategoryAnalysisStatus.NOT_ANALYZED
        assert auth_cov.score is None
        assert "koa detected, not supported" in (auth_cov.explanation or "")

        authz_cov = score_result.category_scores[DebtCategory.AUTHORIZATION_CONSISTENCY]
        assert authz_cov.status == CategoryAnalysisStatus.NOT_ANALYZED
        assert authz_cov.score is None
        assert "koa detected, not supported" in (authz_cov.explanation or "")


def test_library_with_no_routes_yields_no_http_routes_detected_explanation():
    """A library with no routes yields the 'no HTTP routes detected' explanation, not a clean score."""
    code = (
        "import express from 'express';\n"
        "\n"
        "export function calculateDiscount(price: number, discount: number): number {\n"
        "  return price * (1 - discount);\n"
        "}\n"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir)
        lib_file = repo_dir / "index.ts"
        lib_file.write_text(code, encoding="utf-8")

        scan_id = "test-scan-lib-no-routes"
        manifest = RepositoryManifest(
            repository=RepositoryManifestSummary(
                scan_timestamp=datetime.now(UTC),
                name="lib-no-routes",
                path=str(repo_dir),
                total_files=1,
                source_files=1,
                ignored_files=0,
                skipped_files=0,
                total_source_size=len(code),
                total_source_loc=len(code.splitlines()),
            ),
            languages={"typescript": 1},
            files=[
                SourceFileMetadata(
                    path="index.ts",
                    language=SupportedLanguage.TYPESCRIPT,
                    size=len(code),
                    line_count=len(code.splitlines()),
                    analysis_supported=True,
                )
            ],
            skipped_files=[],
        )

        repo_meta = RepositoryMetadata(
            name="lib-no-routes",
            path=str(repo_dir),
            total_files=1,
            scannable_files=1,
            total_loc=len(code.splitlines()),
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

        score_result = scoring_service.calculate_scan_score(scan_id, force_recalculate=True)

        assert score_result.status == ScoringStatus.PARTIAL
        assert score_result.coverage is not None
        assert score_result.coverage.is_partial is True
        assert score_result.coverage.total_routes_detected == 0

        auth_cov = score_result.category_scores[DebtCategory.AUTHENTICATION_CONSISTENCY]
        assert auth_cov.status == CategoryAnalysisStatus.NOT_ANALYZED
        assert auth_cov.score is None
        assert "no HTTP routes detected" in (auth_cov.explanation or "")

        authz_cov = score_result.category_scores[DebtCategory.AUTHORIZATION_CONSISTENCY]
        assert authz_cov.status == CategoryAnalysisStatus.NOT_ANALYZED
        assert authz_cov.score is None
        assert "no HTTP routes detected" in (authz_cov.explanation or "")
