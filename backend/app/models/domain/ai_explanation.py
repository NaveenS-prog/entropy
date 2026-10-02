"""Domain models for Phase 7 AI Explanation & Remediation Layer.

ENGINEERING CONSTITUTION NOTE:
AI is strictly an advisory, explanatory, and remediation assistance layer.
Static analysis rules alone generate findings and determine debt scores.
AI MUST NEVER invent findings, alter severity, alter confidence, or modify entropy scores.
"""

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class AIExplanation(BaseModel):
    """Structured AI-generated architectural explanation for a finding."""

    finding_id: str = Field(..., description="Unique ID of the deterministic finding being explained")
    summary: str = Field(..., description="Executive summary of the debt pattern")
    why_it_matters: str = Field(..., description="Detailed security or architectural hazard justification")
    evidence_explanation: str = Field(..., description="Contextual explanation grounded strictly in the finding evidence")
    architectural_impact: str = Field(..., description="Long-term maintenance and technical debt impact")
    remediation: str = Field(..., description="Actionable step-by-step guidance to remediate the issue")
    suggested_pattern: str = Field(..., description="Recommended idiomatic pattern or architecture")
    confidence: str = Field(
        default="medium",
        description="Confidence of the AI explanation (independent from deterministic finding confidence)",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when the explanation was generated",
    )
    model: str = Field(..., description="Model identifier used to produce the explanation")
    prompt_version: str = Field(..., description="Prompt version identifier")
    disclaimer: str = Field(
        default="AI-generated explanation — advisory only. Does not alter deterministic findings or scores.",
        description="Mandatory advisory disclaimer",
    )


class AIExplanationContext(BaseModel):
    """Controlled, minimal context extracted from a deterministic finding to provide to the LLM."""

    rule_id: str
    category: str
    severity: str
    confidence: str
    message: str
    file_path: str
    line_start: int
    line_end: int
    evidence: str
    source_snippet: str | None = None
    fingerprint: str | None = None

