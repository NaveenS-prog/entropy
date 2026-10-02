"""Domain models for GitHub Pull Request security and architectural debt workflows."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from app.policy.models import PolicyEvaluation


class PRAnalysisStatus(StrEnum):
    """Lifecycle status of a Pull Request debt analysis job."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class GitHubRepositoryInfo(BaseModel):
    """Normalized metadata for a GitHub repository."""

    owner: str
    name: str
    full_name: str
    clone_url: str | None = None
    default_branch: str = "main"


class GitHubPullRequestInfo(BaseModel):
    """Normalized metadata for a GitHub Pull Request."""

    number: int
    title: str
    url: str | None = None
    base_branch: str
    base_sha: str
    head_branch: str
    head_sha: str


class PRAnalysisRecord(BaseModel):
    """Persistent tracking record for a Pull Request analysis run."""

    id: str
    repository_id: str
    owner: str
    repo: str
    pr_number: int
    base_sha: str
    head_sha: str
    base_branch: str | None = None
    head_branch: str | None = None
    base_scan_id: str | None = None
    head_scan_id: str | None = None
    base_score: int | None = None
    head_score: int | None = None
    score_delta: int | None = None
    new_findings_count: int = 0
    resolved_findings_count: int = 0
    persistent_findings_count: int = 0
    status: PRAnalysisStatus = PRAnalysisStatus.QUEUED
    error_message: str | None = None
    check_run_id: int | None = None
    comment_id: int | None = None
    policy_status: str | None = None
    policy_evaluation: PolicyEvaluation | None = None
    is_current_head: bool = True
    created_at: datetime
    updated_at: datetime


class PRAnalysisTriggerRequest(BaseModel):
    """Request payload to manually trigger or simulate PR analysis."""

    base_sha: str | None = Field(default=None, description="Explicit base commit SHA")
    head_sha: str | None = Field(default=None, description="Explicit head commit SHA")
    base_branch: str | None = Field(default=None, description="Base branch name")
    head_branch: str | None = Field(default=None, description="Head branch name")
    source_path: str | None = Field(
        default=None,
        description="Local repository directory path (for offline/testing runs)",
    )
