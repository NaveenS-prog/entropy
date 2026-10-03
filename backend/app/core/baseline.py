"""Deterministic baseline models and comparison engine for Entropy (.entropy-baseline.json)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.domain.enums import DebtScoreTier, Severity
from app.models.domain.finding import Finding
from app.models.domain.scan import RepositoryScanResult


class BaselineFindingItem(BaseModel):
    """Metadata-only finding record stored in baseline (zero source code stored)."""

    model_config = ConfigDict(extra="forbid")

    fingerprint: str = Field(..., description="Stable hash tracking finding across commits")
    rule_id: str = Field(..., description="Rule ID that produced finding")
    file: str = Field(..., description="Relative file path")
    line_start: int = Field(..., description="Starting line")
    severity: str = Field(..., description="Severity level")
    category: str = Field(..., description="Debt category")
    id: str | None = Field(default=None, description="Deterministic finding ID")


class BaselineProjectInfo(BaseModel):
    """Project metadata stored in baseline."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Project name")
    id: str | None = Field(default=None, description="Project ID")


class BaselineScanMeta(BaseModel):
    """Scan and scoring metadata stored in baseline."""

    model_config = ConfigDict(extra="forbid")

    score: int = Field(..., ge=0, le=100, description="Entropy debt score at baseline")
    band: str = Field(..., description="Score band (very_low, low, etc.)")
    total_findings: int = Field(..., ge=0, description="Total active findings at baseline")
    created_at: str = Field(..., description="UTC ISO8601 timestamp")
    commit_sha: str | None = Field(default=None, description="HEAD commit SHA when baseline was created")
    config_hash: str | None = Field(default=None, description="Deterministic configuration hash")


class EntropyBaseline(BaseModel):
    """Full deterministic baseline model (.entropy-baseline.json)."""

    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, description="Baseline schema version")
    project: BaselineProjectInfo = Field(..., description="Project identity")
    scan: BaselineScanMeta = Field(..., description="Baseline scan metrics")
    findings: list[BaselineFindingItem] = Field(
        default_factory=list,
        description="List of finding items at baseline (metadata only, no source snippets)",
    )

    @classmethod
    def from_scan(
        cls,
        scan: RepositoryScanResult,
        project_name: str | None = None,
        project_id: str | None = None,
        config_hash: str | None = None,
        active_findings: list[Finding] | None = None,
    ) -> EntropyBaseline:
        """Construct baseline from a completed RepositoryScanResult."""
        proj_name = project_name or scan.repository.name
        proj_id = project_id or scan.repository.repository_id
        score_val = scan.score.total_score if scan.score else 0
        band_val = scan.score.tier.value if scan.score else "unknown"

        findings_to_store = active_findings if active_findings is not None else [
            f for f in scan.findings if not getattr(f, "is_suppressed", False)
        ]

        # Deterministically order findings by file, line_start, rule_id, fingerprint
        sorted_findings = sorted(
            findings_to_store,
            key=lambda f: (f.file, f.line_start, f.rule_id, f.fingerprint),
        )

        items = [
            BaselineFindingItem(
                fingerprint=f.fingerprint,
                rule_id=f.rule_id,
                file=f.file,
                line_start=f.line_start,
                severity=f.severity.value,
                category=f.category.value,
                id=f.id,
            )
            for f in sorted_findings
        ]

        return cls(
            version=1,
            project=BaselineProjectInfo(name=proj_name, id=proj_id),
            scan=BaselineScanMeta(
                score=score_val,
                band=band_val,
                total_findings=len(items),
                created_at=datetime.now(UTC).isoformat(),
                commit_sha=scan.repository.commit_hash,
                config_hash=config_hash,
            ),
            findings=items,
        )

    def to_json(self, indent: int = 2) -> str:
        """Export to deterministic JSON string."""
        return self.model_dump_json(indent=indent)


class BaselineComparisonResult(BaseModel):
    """Result of comparing current scan findings against an established baseline."""

    model_config = ConfigDict(extra="forbid")

    baseline_score: int
    current_score: int
    score_delta: int
    new_findings: list[Finding]
    resolved_findings: list[BaselineFindingItem]
    unchanged_findings: list[Finding]
    suppressed_findings: list[Finding]
    total_current: int

    @property
    def new_count(self) -> int:
        return len(self.new_findings)

    @property
    def resolved_count(self) -> int:
        return len(self.resolved_findings)

    @property
    def unchanged_count(self) -> int:
        return len(self.unchanged_findings)

    @property
    def suppressed_count(self) -> int:
        return len(self.suppressed_findings)

    def to_scan_comparison(
        self,
        current_scan: RepositoryScanResult,
        baseline: EntropyBaseline,
    ) -> Any:
        """Convert BaselineComparisonResult into a ScanComparisonResult for policy evaluation."""
        from app.comparison.models import (
            ComparisonFindingItem,
            ComparisonSummary,
            FindingLifecycleStatus,
            ScanComparisonResult,
            ScoreComparison,
        )
        from app.models.domain.enums import Confidence, DebtCategory

        new_items = [
            ComparisonFindingItem(
                finding_id=f.id,
                fingerprint=f.fingerprint,
                category=f.category,
                rule_id=f.rule_id,
                severity=f.severity,
                confidence=f.confidence,
                file=f.file,
                line_start=f.line_start,
                line_end=f.line_end,
                title=f.title,
                description=f.description,
                lifecycle=FindingLifecycleStatus.NEW,
                resolution_status=None,
                first_seen_scan_id=current_scan.scan_id,
                last_seen_scan_id=current_scan.scan_id,
                seen_in_scans_count=1,
            )
            for f in self.new_findings
        ]

        persistent_items = [
            ComparisonFindingItem(
                finding_id=f.id,
                fingerprint=f.fingerprint,
                category=f.category,
                rule_id=f.rule_id,
                severity=f.severity,
                confidence=f.confidence,
                file=f.file,
                line_start=f.line_start,
                line_end=f.line_end,
                title=f.title,
                description=f.description,
                lifecycle=FindingLifecycleStatus.PERSISTENT,
                resolution_status=None,
                first_seen_scan_id="baseline",
                last_seen_scan_id=current_scan.scan_id,
                seen_in_scans_count=2,
            )
            for f in self.unchanged_findings
        ]

        resolved_items = [
            ComparisonFindingItem(
                finding_id=item.id or item.fingerprint,
                fingerprint=item.fingerprint,
                category=DebtCategory(item.category),
                rule_id=item.rule_id,
                severity=Severity(item.severity),
                confidence=Confidence.HIGH,
                file=item.file,
                line_start=item.line_start,
                line_end=item.line_start,
                title=f"Resolved finding {item.rule_id}",
                description="Resolved since baseline",
                lifecycle=FindingLifecycleStatus.RESOLVED,
                resolution_status="No longer detected since baseline",
                first_seen_scan_id="baseline",
                last_seen_scan_id="baseline",
                seen_in_scans_count=1,
            )
            for item in self.resolved_findings
        ]

        direction = "unchanged"
        if self.score_delta > 0:
            direction = "increased"
        elif self.score_delta < 0:
            direction = "decreased"

        score_comp = ScoreComparison(
            previous_score=self.baseline_score,
            current_score=self.current_score,
            score_delta=self.score_delta,
            previous_band=DebtScoreTier(baseline.scan.band)
            if baseline.scan.band in [t.value for t in DebtScoreTier]
            else DebtScoreTier.VERY_LOW,
            current_band=current_scan.score.tier if current_scan.score else DebtScoreTier.VERY_LOW,
            direction=direction,
            explanation=f"Entropy Debt Score shifted by {self.score_delta:+d} points relative to baseline.",
        )

        base_dt = datetime.now(UTC)
        if "T" in baseline.scan.created_at:
            try:
                base_dt = datetime.fromisoformat(baseline.scan.created_at)
            except Exception:
                pass

        summary = ComparisonSummary(
            repository_id=current_scan.repository.repository_id or "local",
            repo_name=current_scan.repository.name,
            previous_scan_id="baseline",
            current_scan_id=current_scan.scan_id,
            previous_timestamp=base_dt,
            current_timestamp=current_scan.started_at,
            previous_commit=baseline.scan.commit_sha,
            current_commit=current_scan.repository.commit_hash,
            previous_score=self.baseline_score,
            current_score=self.current_score,
            score_delta=self.score_delta,
            new_findings_count=len(self.new_findings),
            resolved_findings_count=len(self.resolved_findings),
            persistent_findings_count=len(self.unchanged_findings),
            total_current_findings=len(self.new_findings) + len(self.unchanged_findings),
        )

        return ScanComparisonResult(
            summary=summary,
            score_comparison=score_comp,
            category_comparisons={},
            rule_comparisons=[],
            new_findings=new_items,
            resolved_findings=resolved_items,
            persistent_findings=persistent_items,
        )


def compare_with_baseline(
    current_scan: RepositoryScanResult,
    baseline: EntropyBaseline,
    current_findings: list[Finding] | None = None,
) -> BaselineComparisonResult:
    """Deterministically compare current scan against baseline using fingerprint set theory."""
    all_current = current_findings if current_findings is not None else current_scan.findings

    active_current: list[Finding] = []
    suppressed_current: list[Finding] = []
    for f in all_current:
        if getattr(f, "is_suppressed", False):
            f.status = "suppressed"
            suppressed_current.append(f)
        else:
            active_current.append(f)

    baseline_fps: dict[str, BaselineFindingItem] = {
        item.fingerprint: item for item in baseline.findings
    }
    current_fps: dict[str, Finding] = {
        f.fingerprint: f for f in active_current
    }

    new_items: list[Finding] = []
    unchanged_items: list[Finding] = []
    for f in active_current:
        if f.fingerprint in baseline_fps:
            f.status = "unchanged"
            unchanged_items.append(f)
        else:
            f.status = "new"
            new_items.append(f)

    resolved_items: list[BaselineFindingItem] = []
    for fp, item in baseline_fps.items():
        if fp not in current_fps:
            resolved_items.append(item)

    curr_score = current_scan.score.total_score if current_scan.score else 0
    delta = curr_score - baseline.scan.score

    # Deterministic sorting
    new_items.sort(key=lambda f: (f.file, f.line_start, f.id))
    unchanged_items.sort(key=lambda f: (f.file, f.line_start, f.id))
    resolved_items.sort(key=lambda item: (item.file, item.line_start, item.fingerprint))

    return BaselineComparisonResult(
        baseline_score=baseline.scan.score,
        current_score=curr_score,
        score_delta=delta,
        new_findings=new_items,
        resolved_findings=resolved_items,
        unchanged_findings=unchanged_items,
        suppressed_findings=suppressed_current,
        total_current=len(all_current),
    )


def load_baseline_file(baseline_path: Path | str) -> EntropyBaseline:
    """Load, parse, and validate .entropy-baseline.json safely."""
    path = Path(baseline_path)
    if not path.is_file():
        raise FileNotFoundError(f"Baseline file does not exist: {path}")

    # Prevent massive files / DOS
    size = path.stat().st_size
    if size > 50 * 1024 * 1024:
        raise ValueError(f"Baseline file is too large ({size} bytes, maximum 50MB)")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"Invalid JSON in baseline file '{path}': {exc}") from exc

    return EntropyBaseline.model_validate(raw)


def save_baseline_file(baseline: EntropyBaseline, baseline_path: Path | str) -> None:
    """Save baseline to file safely."""
    path = Path(baseline_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(baseline.to_json(indent=2), encoding="utf-8")
