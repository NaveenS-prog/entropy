"""Base parser interface and ParsedFile representation."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.models.domain.enums import SupportedLanguage
from app.models.domain.finding import CodeEvidence
from app.repository.discoverer import DiscoveredFile


@dataclass
class ParsedFile:
    """In-memory representation of a parsed source file."""

    absolute_path: Path
    relative_path: str
    language: SupportedLanguage
    source_code: str
    lines: list[str]
    ast_root: Any | None = None
    parse_errors: list[str] = field(default_factory=list)
    structure: Any | None = None
    unit: Any | None = None

    @property
    def is_valid(self) -> bool:
        """True if the file was parsed successfully without fatal syntax errors."""
        return self.ast_root is not None and len(self.parse_errors) == 0

    @classmethod
    def from_unit(cls, unit: Any) -> "ParsedFile":
        """Construct a ParsedFile instance wrapping a Phase 2 ParsedPythonUnit."""
        return cls(
            absolute_path=unit.absolute_path,
            relative_path=unit.file_path,
            language=unit.language,
            source_code=unit.source_code,
            lines=unit.lines,
            ast_root=unit.ast_root,
            parse_errors=unit.errors,
            structure=unit.structure,
            unit=unit,
        )

    def get_line_count(self) -> int:
        return len(self.lines)

    def extract_snippet(
        self,
        line_start: int,
        line_end: int,
        context_before: int = 1,
        context_after: int = 1,
    ) -> CodeEvidence:
        """Extract a verbatim source snippet around line_start and line_end."""
        total = len(self.lines)
        # Ensure 1-indexed boundaries
        start = max(1, line_start - context_before)
        end = min(total, line_end + context_after)

        snippet_lines = self.lines[start - 1 : end]
        snippet_content = "".join(snippet_lines)

        highlight_lines = list(range(line_start, line_end + 1))

        return CodeEvidence(
            content=snippet_content,
            line_start=start,
            line_end=end,
            highlight_lines=highlight_lines,
        )


class BaseParser(ABC):
    """Abstract interface for language-specific AST/CST parsers.

    Enables seamless transition from Python AST to Tree-sitter for multi-language support.
    """

    @abstractmethod
    def can_parse(self, language: SupportedLanguage) -> bool:
        """Check if this parser handles the given language."""
        pass

    @abstractmethod
    def parse(self, discovered_file: DiscoveredFile) -> ParsedFile:
        """Parse source file into AST representation, handling syntax errors gracefully."""
        pass
