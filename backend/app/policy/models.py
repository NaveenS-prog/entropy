"""Domain models and schemas for the Entropy Policy Engine.

Enforces strict, deterministic evaluation of architectural and security debt.
Policy Engine is purely a consumer of static analysis, scoring, and comparison data.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.domain.enums import DebtCategory


class PolicyStatus(StrEnum):
    """Lifecycle evaluation status of a policy or rule."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"


class PolicyRuleSeverity(StrEnum):
    """Severity assigned to a policy rule failure."""

    FAIL = "fail"
    WARN = "warn"


class ScoreRulesConfig(BaseModel):
    """Rules evaluated against overall Entropy scores."""

    model_config = ConfigDict(extra="forbid")

    max_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Maximum absolute Entropy score allowed (0-100). Exceeding causes FAIL.",
    )
    max_delta: int | None = Field(
        default=None,
        ge=0,
        description="Maximum score increase allowed between base and head. Exceeding causes FAIL.",
    )
    warn_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Entropy score threshold triggering a warning.",
    )
    warn_delta: int | None = Field(
        default=None,
        ge=0,
        description="Score increase threshold triggering a warning.",
    )


class FindingRulesConfig(BaseModel):
    """Rules evaluated against finding counts and finding severities."""

    model_config = ConfigDict(extra="forbid")

    max_new: int | None = Field(
        default=None,
        ge=0,
        description="Maximum number of new findings introduced in a PR. Exceeding causes FAIL.",
    )
    max_new_high: int | None = Field(
        default=None,
        ge=0,
        description="Maximum number of new High-severity findings introduced. Exceeding causes FAIL.",
    )
    max_new_critical: int | None = Field(
        default=None,
        ge=0,
        description="Maximum number of new Critical-severity findings introduced. Exceeding causes FAIL.",
    )
    max_total: int | None = Field(
        default=None,
        ge=0,
        description="Maximum total findings allowed in scan. Exceeding causes FAIL.",
    )
    max_total_high: int | None = Field(
        default=None,
        ge=0,
        description="Maximum total High-severity findings allowed in scan.",
    )
    max_total_critical: int | None = Field(
        default=None,
        ge=0,
        description="Maximum total Critical-severity findings allowed in scan.",
    )


class CategoryRulesConfig(BaseModel):
    """Rules evaluated against individual debt categories."""

    model_config = ConfigDict(extra="forbid")

    max_score: dict[str, float] = Field(
        default_factory=dict,
        description="Maximum absolute category score (0-100) per category.",
    )
    max_delta: dict[str, float] = Field(
        default_factory=dict,
        description="Maximum category score increase allowed per category.",
    )
    warn_delta: dict[str, float] = Field(
        default_factory=dict,
        description="Category score increase threshold triggering a warning.",
    )

    @field_validator("max_score", "max_delta", "warn_delta")
    @classmethod
    def validate_categories(cls, v: dict[str, float]) -> dict[str, float]:
        """Validate that all category keys correspond to recognized DebtCategory members."""
        valid_cats = {cat.value for cat in DebtCategory}
        for cat_name, val in v.items():
            if cat_name not in valid_cats:
                raise ValueError(
                    f"Unknown category '{cat_name}'. Valid categories are: {sorted(valid_cats)}"
                )
            if val < 0:
                raise ValueError(f"Category threshold for '{cat_name}' cannot be negative: {val}")
        return v


class RuleSpecificRulesConfig(BaseModel):
    """Rules forbidding specific static analysis rule IDs."""

    model_config = ConfigDict(extra="forbid")

    forbidden_rules: list[str] = Field(
        default_factory=list,
        description="Rule IDs that must never be introduced (e.g. ['ENT-LOG-002', 'ENT-ERR-001']).",
    )

    @field_validator("forbidden_rules")
    @classmethod
    def validate_rule_ids(cls, v: list[str]) -> list[str]:
        """Ensure forbidden rule IDs are non-empty and well-formed."""
        for rule_id in v:
            if not isinstance(rule_id, str) or not rule_id.strip():
                raise ValueError("Forbidden rule ID must be a non-empty string.")
            cleaned = rule_id.strip()
            if not (cleaned.startswith("ENT-") and len(cleaned) >= 8):
                raise ValueError(
                    f"Invalid rule ID format '{rule_id}'. Rule IDs must start with 'ENT-'."
                )
        return [r.strip() for r in v]


class PolicyConfig(BaseModel):
    """Declarative, deterministic policy configuration."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(default="default", description="Human-readable policy name")
    description: str = Field(
        default="Default Entropy Architectural and Security Debt Policy",
        description="Policy purpose description",
    )
    enabled: bool = Field(default=True, description="Whether this policy is actively evaluated")
    version: str = Field(default="1.0.0", description="Policy version identifier")
    score: ScoreRulesConfig = Field(default_factory=ScoreRulesConfig)
    findings: FindingRulesConfig = Field(default_factory=FindingRulesConfig)
    categories: CategoryRulesConfig = Field(default_factory=CategoryRulesConfig)
    rules: RuleSpecificRulesConfig = Field(default_factory=RuleSpecificRulesConfig)


class PolicyRuleResult(BaseModel):
    """Outcome of evaluating a single policy rule."""

    rule_name: str = Field(..., description="Name of the evaluated rule (e.g. 'max_score')")
    rule_type: str = Field(..., description="'absolute' or 'delta'")
    status: PolicyStatus = Field(..., description="Outcome: PASS, WARN, FAIL, or NOT_APPLICABLE")
    severity: PolicyRuleSeverity = Field(
        default=PolicyRuleSeverity.FAIL,
        description="Severity if violated: FAIL or WARN",
    )
    actual_value: Any = Field(..., description="Measured value from scan or comparison")
    threshold: Any = Field(..., description="Configured policy limit")
    message: str = Field(..., description="Explainable description of the evaluation outcome")
    category: str | None = Field(default=None, description="Affected category if category-specific")
    finding_ids: list[str] = Field(
        default_factory=list,
        description="Associated finding IDs if applicable",
    )
    rule_ids: list[str] = Field(
        default_factory=list,
        description="Associated analyzer rule IDs if applicable",
    )


class PolicyEvaluation(BaseModel):
    """Complete explainable result of evaluating a scan or comparison against a policy."""

    policy_name: str
    policy_version: str
    status: PolicyStatus = Field(
        ...,
        description="Overall evaluation status: FAIL (any violation), WARN (any warning), or PASS",
    )
    passed: bool = Field(
        ...,
        description="True if policy satisfied (PASS or WARN), False if FAIL",
    )
    score: int = Field(..., description="Entropy Debt Score of analyzed scan")
    base_score: int | None = Field(default=None, description="Base score if baseline comparison was present")
    score_delta: int | None = Field(default=None, description="Score delta if baseline comparison was present")
    new_findings_count: int | None = Field(
        default=None,
        description="Count of new findings introduced if baseline comparison was present",
    )
    violations: list[PolicyRuleResult] = Field(
        default_factory=list,
        description="Rules that produced FAIL status",
    )
    warnings: list[PolicyRuleResult] = Field(
        default_factory=list,
        description="Rules that produced WARN status",
    )
    passed_rules: list[PolicyRuleResult] = Field(
        default_factory=list,
        description="Rules that evaluated successfully",
    )
    not_applicable_rules: list[PolicyRuleResult] = Field(
        default_factory=list,
        description="Delta rules skipped due to missing baseline",
    )
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of evaluation",
    )
    summary: str = Field(..., description="Summary explanation of policy decision")
