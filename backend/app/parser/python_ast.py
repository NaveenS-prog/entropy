"""Resilient Python AST parser."""

import ast

from app.models.domain.enums import SupportedLanguage
from app.parser.base import BaseParser, ParsedFile
from app.repository.discoverer import DiscoveredFile


class PythonAstParser(BaseParser):
    """Parses Python source code into Python standard AST representations."""

    def can_parse(self, language: SupportedLanguage) -> bool:
        return language == SupportedLanguage.PYTHON

    def parse(self, discovered_file: DiscoveredFile) -> ParsedFile:
        """Parse Python source file into an AST root, recording any syntax failures."""
        try:
            with open(discovered_file.absolute_path, encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception as e:
            return ParsedFile(
                absolute_path=discovered_file.absolute_path,
                relative_path=discovered_file.relative_path,
                language=SupportedLanguage.PYTHON,
                source_code="",
                lines=[],
                ast_root=None,
                parse_errors=[f"Failed to read file: {e}"],
            )

        lines = source.splitlines(keepends=True)

        try:
            tree = ast.parse(source, filename=discovered_file.relative_path)
            return ParsedFile(
                absolute_path=discovered_file.absolute_path,
                relative_path=discovered_file.relative_path,
                language=SupportedLanguage.PYTHON,
                source_code=source,
                lines=lines,
                ast_root=tree,
                parse_errors=[],
            )
        except SyntaxError as e:
            err_msg = f"SyntaxError at line {e.lineno}, col {e.offset}: {e.msg}"
            return ParsedFile(
                absolute_path=discovered_file.absolute_path,
                relative_path=discovered_file.relative_path,
                language=SupportedLanguage.PYTHON,
                source_code=source,
                lines=lines,
                ast_root=None,
                parse_errors=[err_msg],
            )
        except Exception as e:
            return ParsedFile(
                absolute_path=discovered_file.absolute_path,
                relative_path=discovered_file.relative_path,
                language=SupportedLanguage.PYTHON,
                source_code=source,
                lines=lines,
                ast_root=None,
                parse_errors=[f"Unexpected AST parse error: {e}"],
            )
