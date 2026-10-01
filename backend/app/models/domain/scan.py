"""Domain models for Repository Scan executions and aggregated results."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.domain.enums import ScanStatus
from app.models.domain.finding import Finding
from app.models.domain.manifest import RepositoryManifest
from app.models.domain.scoring import DebtScoreResult


class RepositoryMetadata(BaseModel):
    """Metadata describing the target repository under analysis."""

    name: str = Field(..., description="Repository name or directory basename")
    path: str = Field(..., description="Root path or identifier")
    branch: str | None = Field(default=None, description="Active git branch if available")
    commit_hash: str | None = Field(default=None, description="Head commit hash if available")
    total_files: int = Field(default=0, ge=0)
    scannable_files: int = Field(default=0, ge=0)
    total_loc: int = Field(default=0, ge=0)


class RepositoryScanResult(BaseModel):
    """Complete artifact representing a completed or in-progress scan."""

    scan_id: str = Field(..., description="Unique scan identifier")
    repository: RepositoryMetadata = Field(..., description="Repository context")
    status: ScanStatus = Field(..., description="Scan execution status")
    manifest: RepositoryManifest | None = Field(
        default=None,
        description="Repository manifest generated during ingestion",
    )
    findings: list[Finding] = Field(default_factory=list, description="All identified debt findings")
    score: DebtScoreResult | None = Field(
        default=None,
        description="Calculated debt score if analysis succeeded",
    )
    started_at: datetime = Field(..., description="UTC timestamp of scan start")
    completed_at: datetime | None = Field(
        default=None,
        description="UTC timestamp of completion",
    )
    duration_ms: float | None = Field(default=None, description="Execution duration in milliseconds")
    analyzers_executed: list[str] = Field(
        default_factory=list,
        description="IDs of all analyzers executed during the scan",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Non-fatal parsing or scanning errors encountered",
    )
