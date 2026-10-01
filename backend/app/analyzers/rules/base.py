"""Base rule interface for static analysis rules."""

from abc import ABC, abstractmethod

from app.analyzers.context import PythonASTContext
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition


class BaseRule(ABC):
    """Abstract base class for individual static analysis rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Stable unique identifier, e.g. 'ENT-ERR-001'."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable title/name of the rule."""
        pass

    @property
    @abstractmethod
    def category(self) -> DebtCategory:
        """The architectural debt category."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Detailed description of the pattern."""
        pass

    @property
    @abstractmethod
    def default_severity(self) -> Severity:
        """Default severity for emitted findings."""
        pass

    @property
    @abstractmethod
    def default_confidence(self) -> Confidence:
        """Default confidence for emitted findings."""
        pass

    @property
    def languages(self) -> list[SupportedLanguage]:
        """Languages this rule applies to."""
        return [SupportedLanguage.PYTHON]

    @property
    def impact(self) -> str:
        """Explanation of accumulated maintenance or security risk."""
        return ""

    @property
    def recommendation(self) -> str:
        """Actionable remediation guidance."""
        return ""

    @property
    def definition(self) -> RuleDefinition:
        """Return the RuleDefinition representation of this rule."""
        return RuleDefinition(
            rule_id=self.rule_id,
            category=self.category,
            title=self.name,
            description=self.description,
            default_severity=self.default_severity,
            default_confidence=self.default_confidence,
            languages=self.languages,
            impact_template=self.impact,
            recommendation_template=self.recommendation,
            rationale=self.description,
        )

    @abstractmethod
    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        """Analyze a single file using its AST context."""
        pass
