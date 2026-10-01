"""Domain models for Entropy findings and source locations."""

from hashlib import sha256
from typing import Any

from pydantic import BaseModel, Field

from app.models.domain.enums import Confidence, DebtCategory, Severity


class SourceLocation(BaseModel):
    """Pinpoint source-code location for a finding."""

    file: str = Field(..., description="Repository-relative file path")
    line_start: int = Field(..., ge=1, description="1-indexed starting line")
    line_end: int = Field(..., ge=1, description="1-indexed ending line")
    col_start: int | None = Field(default=None, ge=0, description="0-indexed start column")
    col_end: int | None = Field(default=None, ge=0, description="0-indexed end column")


class CodeEvidence(BaseModel):
    """Contextual source code evidence proving the finding."""

    content: str = Field(..., description="Verbatim code snippet extract")
    line_start: int = Field(..., ge=1, description="Starting line of the snippet")
    line_end: int = Field(..., ge=1, description="Ending line of the snippet")
    highlight_lines: list[int] = Field(
        default_factory=list,
        description="Specific 1-indexed line numbers to highlight inside the snippet",
    )


class Finding(BaseModel):
    """Core domain finding representing an instance of Silent Security Debt.

    Meets all Product Definition Section 7 specifications:
    {id, category, rule_id, severity, confidence, file, line_start, line_end,
     symbol, title, description, evidence, impact, recommendation}
    """

    id: str = Field(..., description="Unique finding ID (UUID or deterministic fingerprint)")
    category: DebtCategory = Field(..., description="One of the 7 MVP debt categories")
    rule_id: str = Field(..., description="Identifier of the rule that produced this finding")
    severity: Severity = Field(..., description="Assessed risk severity")
    confidence: Confidence = Field(..., description="Confidence of detection accuracy")
    file: str = Field(..., description="Relative file path in repository")
    line_start: int = Field(..., ge=1, description="Starting line in source")
    line_end: int = Field(..., ge=1, description="Ending line in source")
    column_start: int | None = Field(default=None, description="0-indexed starting column")
    column_end: int | None = Field(default=None, description="0-indexed ending column")
    symbol: str | None = Field(
        default=None,
        description="Function, class, or symbol where the pattern occurs",
    )
    title: str = Field(..., description="Human-readable title summarizing the debt pattern")
    description: str = Field(
        ...,
        description="Detailed explanation of the observable pattern and its context",
    )
    evidence: CodeEvidence = Field(
        ...,
        description="Verbatim source code excerpt demonstrating the issue",
    )
    impact: str = Field(
        ...,
        description="Why this pattern creates future security or maintenance risk",
    )
    recommendation: str = Field(
        ...,
        description="Actionable developer recommendation to eliminate the debt",
    )
    fingerprint: str = Field(
        ...,
        description="Stable hash for tracking this debt item across commits/branches",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Analyzer-specific metadata (AST node types, syntactic markers, etc.)",
    )

    @classmethod
    def generate_deterministic_id(
        cls,
        rule_id: str,
        file: str,
        line_start: int,
        line_end: int,
        symbol: str | None,
        evidence_signature: str,
    ) -> str:
        """Generate a stable, deterministic 16-character hex ID."""
        raw = f"{rule_id}:{file}:{line_start}:{line_end}:{symbol or ''}:{evidence_signature}"
        return sha256(raw.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def generate_fingerprint(
        cls,
        rule_id: str,
        file: str,
        symbol: str | None,
        pattern_signature: str,
    ) -> str:
        """Generate a stable fingerprint independent of line shifts where possible."""
        raw = f"{rule_id}:{file}:{symbol or ''}:{pattern_signature}"
        return sha256(raw.encode("utf-8")).hexdigest()[:16]
