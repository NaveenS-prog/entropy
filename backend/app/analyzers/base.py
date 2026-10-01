"""Base analyzer interface and analysis execution context."""

from abc import ABC, abstractmethod

from app.analyzers.context import AnalysisContext, PythonASTContext
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition


class BaseAnalyzer(ABC):
    """Abstract base class for all Entropy static analyzers.

    Every analyzer is self-contained, modular, and yields structured Finding objects.
    """

    @property
    @abstractmethod
    def analyzer_id(self) -> str:
        """Unique machine-readable analyzer ID, e.g. 'error_handling_analyzer'."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable display name."""
        pass

    @property
    @abstractmethod
    def category(self) -> DebtCategory:
        """The MVP DebtCategory this analyzer contributes to."""
        pass

    @property
    @abstractmethod
    def supported_languages(self) -> set[SupportedLanguage]:
        """Languages this analyzer is capable of analyzing."""
        pass

    @property
    @abstractmethod
    def rules(self) -> list[RuleDefinition]:
        """List of all rules declared and enforced by this analyzer."""
        pass

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Execute deterministic static analysis across the repository context.

        Returns:
            list[Finding]: Concrete findings discovered during analysis.
        """
        pass


__all__ = ["AnalysisContext", "BaseAnalyzer", "PythonASTContext"]
