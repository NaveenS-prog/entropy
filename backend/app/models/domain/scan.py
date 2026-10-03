"""Domain models for Repository Scan executions and aggregated results."""

from datetime import datetime
from hashlib import sha256
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

from app.models.domain.enums import ScanStatus
from app.models.domain.finding import Finding
from app.models.domain.manifest import RepositoryManifest
from app.models.domain.scoring import DebtScoreResult


class RepositoryMetadata(BaseModel):
    """Metadata describing the target repository under analysis."""

    name: str = Field(..., description="Repository name or directory basename")
    path: str = Field(..., description="Root path or identifier")
    repository_id: str | None = Field(default=None, description="Stable identifier for repository history")
    project_id: str | None = Field(default=None, description="Optional explicit project identifier")
    remote_url: str | None = Field(default=None, description="Remote Git origin URL if available")
    branch: str | None = Field(default=None, description="Active git branch if available")
    commit_hash: str | None = Field(default=None, description="Head commit hash if available")
    is_dirty: bool | None = Field(default=None, description="Whether working tree has uncommitted modifications")
    total_files: int = Field(default=0, ge=0)
    scannable_files: int = Field(default=0, ge=0)
    total_loc: int = Field(default=0, ge=0)

    @staticmethod
    def derive_repository_id(path: str, remote_url: str | None = None) -> str:
        """Derive a stable, deterministic 16-character hex identifier for a repository."""
        target = (
            remote_url.strip().lower()
            if remote_url and remote_url.strip()
            else str(Path(path).resolve())
        )
        return sha256(target.encode("utf-8")).hexdigest()[:16]

    @model_validator(mode="after")
    def ensure_repository_id(self) -> "RepositoryMetadata":
        if not self.repository_id:
            self.repository_id = self.derive_repository_id(self.path, self.remote_url)
        return self


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
    config_hash: str | None = Field(
        default=None,
        description="Deterministic hash of the effective project configuration (.entropy.yml)",
    )
    project_id: str | None = Field(
        default=None,
        description="Project identifier the scan is associated with",
    )
    suppressed_findings_count: int = Field(
        default=0,
        description="Number of findings suppressed in this scan",
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
