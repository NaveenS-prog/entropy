"""Resilient Python AST parser integrating PythonParser with the BaseParser interface."""

from app.models.domain.enums import SupportedLanguage
from app.parser.base import BaseParser, ParsedFile
from app.parser.python.parser import PythonParser
from app.repository.discoverer import DiscoveredFile


class PythonAstParser(BaseParser):
    """Adapter bridging the production PythonParser into the BaseParser interface."""

    def __init__(self, parser: PythonParser | None = None) -> None:
        self._parser = parser or PythonParser()

    def can_parse(self, language: SupportedLanguage) -> bool:
        return self._parser.can_parse(language)

    def parse(self, discovered_file: DiscoveredFile) -> ParsedFile:
        """Parse Python source file into an AST root and normalized structure."""
        unit = self._parser.parse_discovered(discovered_file)
        return ParsedFile(
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
