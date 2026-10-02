"""Domain models for persisted scan snapshots and pagination."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.domain.enums import DebtScoreTier, ScanStatus


class ScanSnapshot(BaseModel):
    """Lightweight historical snapshot of a completed or in-progress scan."""

    scan_id: str = Field(..., description="Unique scan identifier")
    repository_id: str = Field(..., description="Stable repository identity hash")
    repo_name: str = Field(..., description="Repository name or basename")
    repo_path: str = Field(..., description="Repository root path")
    branch: str | None = Field(default=None, description="Git branch name if available")
    commit_sha: str | None = Field(default=None, description="Head commit hash if available")
    status: ScanStatus = Field(..., description="Scan execution status")
    entropy_score: int | None = Field(
        default=None, description="Overall Entropy Debt Score (0-100)"
    )
    score_band: DebtScoreTier | None = Field(default=None, description="Score risk band")
    total_files: int = Field(default=0, ge=0)
    analyzed_files: int = Field(default=0, ge=0)
    total_loc: int = Field(default=0, ge=0)
    finding_count: int = Field(default=0, ge=0)
    analyzer_version: str = Field(default="0.1.0")
    scoring_version: str = Field(default="1.0.0")
    started_at: datetime = Field(..., description="UTC scan start timestamp")
    completed_at: datetime | None = Field(default=None, description="UTC scan completion timestamp")
    duration_ms: float | None = Field(default=None, description="Scan duration in milliseconds")


class PaginatedScanSnapshots(BaseModel):
    """Paginated list of historical scan snapshots."""

    items: list[ScanSnapshot] = Field(default_factory=list)
    total: int = Field(..., ge=0)
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
    total_pages: int = Field(..., ge=0)
