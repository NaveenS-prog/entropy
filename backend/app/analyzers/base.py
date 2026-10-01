"""Base analyzer interface and analysis execution context."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile


@dataclass
class AnalysisContext:
    """Read-only analysis context passed to all analyzers during a scan.

    Provides analyzers access to all parsed files, syntax trees, and codebase metrics.
    """

    repo_path: Path
    parsed_files: list[ParsedFile]
    total_loc: int
    scanned_file_count: int
    metadata: dict[str, str] = field(default_factory=dict)

    def get_files_for_language(self, language: SupportedLanguage) -> list[ParsedFile]:
        """Filter parsed files by language."""
        return [f for f in self.parsed_files if f.language == language and f.is_valid]

    def get_file(self, relative_path: str) -> ParsedFile | None:
        """Lookup a parsed file by relative path."""
        for f in self.parsed_files:
            if f.relative_path == relative_path:
                return f
        return None


class BaseAnalyzer(ABC):
    """Abstract base class for all SilentGuard analyzers.

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
