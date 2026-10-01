"""Pydantic API DTO schemas for scans and repository ingestion."""

from datetime import datetime

from pydantic import BaseModel, Field, model_validator

from app.models.domain.enums import DebtScoreTier, ScanStatus
from app.models.domain.finding import Finding
from app.models.domain.manifest import RepositoryManifest
from app.models.domain.scan import RepositoryMetadata
from app.models.domain.scoring import DebtScoreResult


class ScanCreateRequest(BaseModel):
    """Payload to trigger a repository scan."""

    path: str | None = Field(default=None, description="Path to local repository directory")
    repo_path: str | None = Field(default=None, description="Alias/legacy field for repository path")
    repo_name: str | None = Field(default=None, description="Optional custom display name for repository")

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
    total_findings: int = 0
    total_loc: int = 0
    analyzed_files: int = 0
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
    started_at: datetime
    completed_at: datetime | None = None
    duration_ms: float | None = None
    analyzers_executed: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
