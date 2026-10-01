"""Resilient, deterministic Python AST parser."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from app.models.domain.enums import SupportedLanguage
from app.parser.python.models import (
    ParsedPythonUnit,
    ParseStatus,
    PythonModuleStructure,
    SourceLocation,
)
from app.parser.python.visitor import PythonAstVisitor
from app.repository.discoverer import DiscoveredFile

# PEP 263 encoding declaration pattern
CODING_COOKIE_REGEX = re.compile(rb"^[ \t\f]*#.*?coding[:=][ \t]*([-_.a-zA-Z0-9]+)")


class PythonParser:
    """Production-grade Python AST parser for static code analysis.

    Features:
    - Pure static AST extraction using standard library `ast`.
    - Zero code execution guarantee: never imports, executes, or evals code.
    - Resilient error handling: syntax and encoding errors produce structured failure units without crashing.
    - Accurate line, column, and span preservation.
    - Support for empty Python files as valid empty modules.
    - PEP 263 source encoding detection.
    """

    def can_parse(self, language: SupportedLanguage | str) -> bool:
        """Check if this parser handles the given language."""
        if isinstance(language, str):
            return language.lower() == SupportedLanguage.PYTHON.value
        return language == SupportedLanguage.PYTHON

    def parse_source(
        self,
        source: str,
        file_path: str = "<unknown>",
        absolute_path: Path | None = None,
    ) -> ParsedPythonUnit:
        """Parse raw Python source string into a ParsedPythonUnit."""
        lines = source.splitlines(keepends=True)
        line_count = len(lines)
        size_bytes = len(source.encode("utf-8", errors="ignore"))
        abs_path = absolute_path or Path(file_path)

        # Empty files are valid Python modules with zero statements
        is_empty = len(source.strip()) == 0

        try:
            tree = ast.parse(source, filename=file_path)
            visitor = PythonAstVisitor(file_path=file_path)
            structure = visitor.extract(tree)

            return ParsedPythonUnit(
                file_path=file_path,
                absolute_path=abs_path,
                language=SupportedLanguage.PYTHON,
                source_code=source,
                lines=lines,
                size_bytes=size_bytes,
                line_count=line_count,
                ast_root=tree,
                status=ParseStatus.SUCCESS,
                structure=structure,
                errors=[],
                error_location=None,
                is_empty=is_empty,
            )
        except SyntaxError as e:
            err_line = e.lineno or 1
            err_col = e.offset
            err_msg = f"SyntaxError at line {err_line}, col {err_col}: {e.msg}"
            err_loc = SourceLocation(
                line_start=err_line,
                line_end=err_line,
                col_offset=err_col,
                end_col_offset=None,
            )
            return ParsedPythonUnit(
                file_path=file_path,
                absolute_path=abs_path,
                language=SupportedLanguage.PYTHON,
                source_code=source,
                lines=lines,
                size_bytes=size_bytes,
                line_count=line_count,
                ast_root=None,
                status=ParseStatus.SYNTAX_ERROR,
                structure=None,
                errors=[err_msg],
                error_location=err_loc,
                is_empty=False,
            )
        except Exception as e:
            return ParsedPythonUnit(
                file_path=file_path,
                absolute_path=abs_path,
                language=SupportedLanguage.PYTHON,
                source_code=source,
                lines=lines,
                size_bytes=size_bytes,
                line_count=line_count,
                ast_root=None,
                status=ParseStatus.SYNTAX_ERROR,
                structure=None,
                errors=[f"Unexpected AST parse error: {e}"],
                error_location=None,
                is_empty=False,
            )

    def parse_file(
        self,
        file_path: Path | str,
        relative_path: str | None = None,
        language: SupportedLanguage = SupportedLanguage.PYTHON,
    ) -> ParsedPythonUnit:
        """Read and parse a file from disk, detecting encoding and handling errors gracefully."""
        path = Path(file_path)
        rel_path = relative_path or path.name

        # Reject non-Python files
        if language != SupportedLanguage.PYTHON:
            return ParsedPythonUnit(
                file_path=rel_path,
                absolute_path=path,
                language=language,
                source_code="",
                lines=[],
                size_bytes=0,
                line_count=0,
                ast_root=None,
                status=ParseStatus.UNSUPPORTED_LANGUAGE,
                structure=None,
                errors=[
                    f"Language '{language.value}' detected but analyzer unavailable for Python parser"
                ],
                error_location=None,
                is_empty=False,
            )

        # Read raw bytes safely
        try:
            raw_bytes = path.read_bytes()
        except Exception as e:
            return ParsedPythonUnit(
                file_path=rel_path,
                absolute_path=path,
                language=SupportedLanguage.PYTHON,
                source_code="",
                lines=[],
                size_bytes=0,
                line_count=0,
                ast_root=None,
                status=ParseStatus.READ_ERROR,
                structure=None,
                errors=[f"Failed to read file from filesystem: {e}"],
                error_location=None,
                is_empty=False,
            )

        size_bytes = len(raw_bytes)

        # Handle 0-byte file immediately
        if size_bytes == 0:
            return ParsedPythonUnit(
                file_path=rel_path,
                absolute_path=path,
                language=SupportedLanguage.PYTHON,
                source_code="",
                lines=[],
                size_bytes=0,
                line_count=0,
                ast_root=ast.Module(body=[], type_ignores=[]),
                status=ParseStatus.SUCCESS,
                structure=PythonModuleStructure(file_path=rel_path),
                errors=[],
                error_location=None,
                is_empty=True,
            )

        # Detect source encoding (PEP 263 check in first two lines)
        encoding = self._detect_encoding(raw_bytes)

        try:
            source_text = raw_bytes.decode(encoding)
        except UnicodeDecodeError as e:
            return ParsedPythonUnit(
                file_path=rel_path,
                absolute_path=path,
                language=SupportedLanguage.PYTHON,
                source_code="",
                lines=[],
                size_bytes=size_bytes,
                line_count=0,
                ast_root=None,
                status=ParseStatus.ENCODING_ERROR,
                structure=None,
                errors=[
                    f"Encoding error: Unable to decode file '{rel_path}' using encoding '{encoding}': {e}"
                ],
                error_location=None,
                is_empty=False,
            )

        unit = self.parse_source(source_text, file_path=rel_path, absolute_path=path)
        unit.size_bytes = size_bytes
        return unit

    def parse_discovered(self, discovered_file: DiscoveredFile) -> ParsedPythonUnit:
        """Parse a DiscoveredFile from Phase 1 file discovery."""
        return self.parse_file(
            file_path=discovered_file.absolute_path,
            relative_path=discovered_file.relative_path,
            language=discovered_file.language,
        )

    # -------------------------------------------------------------------------
    # Encoding Detection Helper
    # -------------------------------------------------------------------------

    @staticmethod
    def _detect_encoding(raw_bytes: bytes) -> str:
        """Detect encoding respecting PEP 263 coding cookie, defaulting to utf-8."""
        # Check first two lines for PEP 263 coding declaration
        first_two_lines = raw_bytes.splitlines()[:2]
        for line in first_two_lines:
            match = CODING_COOKIE_REGEX.match(line)
            if match:
                try:
                    decl = match.group(1).decode("ascii").lower()
                    # Normalize common aliases
                    if decl in ("utf8", "utf-8"):
                        return "utf-8"
                    if decl in ("latin1", "latin-1", "iso-8859-1"):
                        return "latin-1"
                    return decl
                except Exception:
                    pass

        # Default standard for Python 3
        return "utf-8"
