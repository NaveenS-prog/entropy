"""Domain models for SilentGuard Rule definitions."""

from pydantic import BaseModel, Field

from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage


class RuleDefinition(BaseModel):
    """Metadata specification for a static analysis rule."""

    rule_id: str = Field(..., description="Unique rule identifier, e.g., 'ERR-001'")
    category: DebtCategory = Field(..., description="Debt category")
    title: str = Field(..., description="Brief title")
    description: str = Field(..., description="Comprehensive explanation of what the rule detects")
    default_severity: Severity = Field(..., description="Default severity assigned to findings")
    default_confidence: Confidence = Field(..., description="Default confidence of detection")
    languages: list[SupportedLanguage] = Field(
        default_factory=lambda: [SupportedLanguage.PYTHON],
        description="Supported programming languages",
    )
    impact_template: str = Field(
        ...,
        description="Template explaining the accumulated security/maintenance risk",
    )
    recommendation_template: str = Field(
        ...,
        description="Template prescribing the clean architectural pattern",
    )
    rationale: str = Field(
        ...,
        description="Why this is considered silent security debt rather than active vulnerability",
    )
