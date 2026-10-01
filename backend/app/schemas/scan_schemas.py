"""Pydantic API DTO schemas for scans."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.domain.enums import DebtScoreTier, ScanStatus
from app.models.domain.finding import Finding
from app.models.domain.scan import RepositoryMetadata
from app.models.domain.scoring import DebtScoreResult


class ScanCreateRequest(BaseModel):
    """Payload to trigger a repository scan."""

    repo_path: str = Field(..., description="Absolute or relative path to local repository directory")
    repo_name: str | None = Field(default=None, description="Optional custom name for repository")


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
    """Comprehensive scan result including findings and score breakdown."""

    scan_id: str
    repository: RepositoryMetadata
    status: ScanStatus
    findings: list[Finding]
    score: DebtScoreResult | None = None
    started_at: datetime
    completed_at: datetime | None = None
    duration_ms: float | None = None
    analyzers_executed: list[str]
    errors: list[str]
