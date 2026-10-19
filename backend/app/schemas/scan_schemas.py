"""Pydantic API DTO schemas for scans and repository ingestion."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator

from app.models.domain.enums import Confidence, DebtScoreTier, ScanStatus, Severity
from app.models.domain.finding import Finding
from app.models.domain.manifest import RepositoryManifest
from app.models.domain.scan import RepositoryMetadata
from app.models.domain.scoring import DebtScoreResult


class ScanCreateRequest(BaseModel):
    """Payload to trigger a repository scan."""

    path: str | None = Field(default=None, description="Path to local repository directory")
    repo_path: str | None = Field(default=None, description="Alias/legacy field for repository path")
    repo_name: str | None = Field(default=None, description="Optional custom display name for repository")
    include_tests: bool = Field(default=False, description="Opt back in to analyzing test and example files")

    @model_validator(mode="after")
    def validate_path_provided(self) -> "ScanCreateRequest":
        target = self.path or self.repo_path
        if not target or not target.strip():
            raise ValueError("Repository path must be provided via 'path' or 'repo_path'.")
        return self

    @property
    def target_path(self) -> str:
        target = self.path or self.repo_path
        assert target is not None
        return target.strip()


class ScanSummaryResponse(BaseModel):
    """Lightweight summary of a scan execution."""

    scan_id: str
    repo_name: str
    repo_path: str
    branch: str | None = None
    commit_hash: str | None = None
    status: ScanStatus
    total_score: int | None = None
    tier: DebtScoreTier | None = None
    is_experimental: bool = Field(default=True, description="Indicates the 0-100 score is experimental")
    total_findings: int = 0
    total_loc: int = 0
    analyzed_files: int = 0
    excluded_files: int = 0
    excluded_loc: int = 0
    started_at: datetime
    duration_ms: float | None = None


class ScanDetailResponse(BaseModel):
    """Comprehensive scan result including repository metadata, manifest, findings, and scores."""

    scan_id: str
    repository: RepositoryMetadata
    status: ScanStatus
    manifest: RepositoryManifest | None = None
    findings: list[Finding] = Field(default_factory=list)
    score: DebtScoreResult | None = None
    is_experimental: bool = Field(default=True, description="Indicates the 0-100 score is experimental")
    categories: dict[str, Any] = Field(default_factory=dict, description="Primary per-category breakdown")
    top_findings: list[Finding] = Field(default_factory=list, description="Primary top findings list")
    started_at: datetime
    completed_at: datetime | None = None
    duration_ms: float | None = None
    analyzers_executed: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def populate_primary_outputs(self) -> "ScanDetailResponse":
        if not self.categories and self.score and getattr(self.score, "category_scores", None):
            self.categories = {
                cat.value if hasattr(cat, "value") else str(cat): breakdown
                for cat, breakdown in self.score.category_scores.items()
            }
        if not self.top_findings and self.findings:
            sev_rank = {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
                Severity.INFO: 4,
            }
            conf_rank = {
                Confidence.HIGH: 0,
                Confidence.MEDIUM: 1,
                Confidence.LOW: 2,
            }
            sorted_f = sorted(
                self.findings,
                key=lambda f: (
                    sev_rank.get(f.severity, 99),
                    conf_rank.get(f.confidence, 99),
                    f.file,
                    f.line_start,
                ),
            )
            self.top_findings = sorted_f[:10]
        return self
