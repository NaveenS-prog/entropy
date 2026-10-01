"""AI explanation interfaces and deterministic baseline explainer.

ENGINEERING CONSTITUTION NOTE:
AI is strictly an explanatory and refactoring assistance layer.
Static analysis rules alone generate findings and determine debt scores.
AI MUST NEVER invent or fabricate findings.
"""

from abc import ABC, abstractmethod

from pydantic import BaseModel, Field

from app.models.domain.finding import Finding


class FindingExplanation(BaseModel):
    """Detailed contextual architectural explanation for a finding."""

    finding_id: str
    architectural_context: str = Field(..., description="Why this pattern accumulates debt over time")
    maintenance_risk: str = Field(..., description="Potential long-term maintenance hazard")
    suggested_action: str = Field(..., description="Recommended remediation strategy")


class RefactoringSuggestion(BaseModel):
    """AI-assisted refactoring plan for a finding."""

    finding_id: str
    before_code: str
    suggested_code: str
    rationale: str


class BaseFindingExplainer(ABC):
    """Abstract interface for explaining findings and generating refactorings."""

    @abstractmethod
    def explain(self, finding: Finding) -> FindingExplanation:
        """Provide architectural explanation for a finding."""
        pass

    @abstractmethod
    def suggest_refactor(self, finding: Finding) -> RefactoringSuggestion:
        """Provide a refactored code example for a finding."""
        pass


class DeterministicBaselineExplainer(BaseFindingExplainer):
    """Deterministic, local baseline explainer.

    Produces reliable, grounded explanations derived directly from rule definitions
    and code evidence without hallucinating or making external LLM calls.
    """

    def explain(self, finding: Finding) -> FindingExplanation:
        return FindingExplanation(
            finding_id=finding.id,
            architectural_context=(
                f"In {finding.file} around line {finding.line_start}, the pattern '{finding.title}' "
                f"demonstrates {finding.category.display_name}. {finding.description}"
            ),
            maintenance_risk=finding.impact,
            suggested_action=finding.recommendation,
        )

    def suggest_refactor(self, finding: Finding) -> RefactoringSuggestion:
        before = finding.evidence.content.strip()
        return RefactoringSuggestion(
            finding_id=finding.id,
            before_code=before,
            suggested_code="# Refactor to handle specific exceptions and log failure context\n" + before,
            rationale=finding.recommendation,
        )
