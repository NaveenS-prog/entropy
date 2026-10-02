"""JavaScript and TypeScript AST parser powered by Tree-sitter."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import tree_sitter
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts

from app.models.domain.enums import SupportedLanguage
from app.parser.base import BaseParser, ParsedFile
from app.parser.jsts.models import JSSourceLocation, ParsedJSTSUnit
from app.parser.jsts.visitor import JSTSAstVisitor
from app.parser.python.models import ParseStatus
from app.repository.discoverer import DiscoveredFile

logger = logging.getLogger("entropy.parser.jsts")


class JSTSParser(BaseParser):
    """Safe, static-only parser for JavaScript, TypeScript, JSX, and TSX files.

    Strictly reads and parses file contents in memory using Tree-sitter.
    Guarantees zero code execution: target files are never loaded into Node,
    evaluated, or imported.
    """

    def __init__(self) -> None:
        # Initialize Tree-sitter language grammars
        self._js_language = tree_sitter.Language(tsjs.language())
        self._ts_language = tree_sitter.Language(tsts.language_typescript())
        self._tsx_language = tree_sitter.Language(tsts.language_tsx())

        # Thread-safe parser instances
        self._js_parser = tree_sitter.Parser(self._js_language)
        self._ts_parser = tree_sitter.Parser(self._ts_language)
        self._tsx_parser = tree_sitter.Parser(self._tsx_language)

    def can_parse(self, language: SupportedLanguage) -> bool:
        """Return True for JavaScript and TypeScript languages."""
        return language in (SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT)

    def _select_parser(self, path_str: str, language: SupportedLanguage) -> tree_sitter.Parser:
        """Select specialized Tree-sitter parser based on file extension."""
        suffix = Path(path_str).suffix.lower()
        if suffix == ".tsx":
            return tree_sitter.Parser(self._tsx_language)
        if suffix in (".ts", ".mts", ".cts") or language == SupportedLanguage.TYPESCRIPT:
            return tree_sitter.Parser(self._ts_language)
        # Default to JS (which also supports JSX)
        return tree_sitter.Parser(self._js_language)

    def parse_file(
        self,
        file_path: Path,
        relative_path: str,
        language: SupportedLanguage,
    ) -> ParsedJSTSUnit:
        """Parse source file into normalized ParsedJSTSUnit with graceful error handling."""
        # 1. Read source bytes safely
        try:
            source_bytes = file_path.read_bytes()
        except OSError as err:
            logger.warning("Failed to read file '%s': %s", relative_path, err)
            return ParsedJSTSUnit(
                file_path=relative_path,
                absolute_path=file_path,
                language=language,
                status=ParseStatus.READ_ERROR,
                errors=[f"Read error: {err}"],
            )

        # 2. Decode source text
        try:
            source_code = source_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                source_code = source_bytes.decode("latin-1")
                source_bytes = source_code.encode("utf-8")
            except Exception as err:
                logger.warning("Encoding error in file '%s': %s", relative_path, err)
                return ParsedJSTSUnit(
                    file_path=relative_path,
                    absolute_path=file_path,
                    language=language,
                    status=ParseStatus.ENCODING_ERROR,
                    errors=[f"Encoding error: {err}"],
                )

        lines = source_code.splitlines(keepends=True)
        line_count = len(lines)
        size_bytes = len(source_bytes)

        # 3. Parse AST using Tree-sitter
        parser = self._select_parser(relative_path, language)
        try:
            tree = parser.parse(source_bytes)
        except Exception as err:
            logger.warning("Tree-sitter parse failure for '%s': %s", relative_path, err)
            return ParsedJSTSUnit(
                file_path=relative_path,
                absolute_path=file_path,
                language=language,
                source_code=source_code,
                lines=lines,
                size_bytes=size_bytes,
                line_count=line_count,
                status=ParseStatus.SYNTAX_ERROR,
                errors=[f"Syntax error: {err}"],
            )

        # 4. Check for severe parse syntax errors
        # In Tree-sitter, broken syntax leaves ERROR nodes. If the root node has error and child count is 1 with ERROR,
        # or error is severe, mark as SYNTAX_ERROR.
        has_fatal_syntax_error = False
        error_msgs: list[str] = []
        error_loc: JSSourceLocation | None = None

        if tree.root_node.has_error:
            # Locate first error node
            error_node = self._find_first_error(tree.root_node)
            if error_node:
                sp = error_node.start_point
                ep = error_node.end_point
                loc = JSSourceLocation(
                    line_start=sp[0] + 1,
                    line_end=ep[0] + 1,
                    col_start=sp[1],
                    col_end=ep[1],
                )
                error_loc = loc
                msg = f"Syntax error near line {loc.line_start}, column {loc.col_start}"
                error_msgs.append(msg)
                # Severe syntax error: top-level ERROR child or unparseable broken module
                if any(c.type == "ERROR" for c in tree.root_node.children) or (
                    tree.root_node.child_count <= 2 and any(c.has_error for c in tree.root_node.children)
                ):
                    has_fatal_syntax_error = True

        status = ParseStatus.SYNTAX_ERROR if has_fatal_syntax_error else ParseStatus.SUCCESS

        # 5. Extract structural models
        structure = None
        if status == ParseStatus.SUCCESS:
            try:
                visitor = JSTSAstVisitor(
                    file_path=relative_path,
                    language=language,
                    source_bytes=source_bytes,
                )
                structure = visitor.extract(tree.root_node)
            except Exception as exc:
                logger.warning("Failed extracting structure for '%s': %s", relative_path, exc)
                error_msgs.append(f"Structural extraction failure: {exc}")

        return ParsedJSTSUnit(
            file_path=relative_path,
            absolute_path=file_path,
            language=language,
            source_code=source_code,
            lines=lines,
            size_bytes=size_bytes,
            line_count=line_count,
            tree=tree,
            status=status,
            structure=structure,
            errors=error_msgs,
            error_location=error_loc,
        )

    def parse(self, discovered_file: DiscoveredFile) -> ParsedFile:
        """BaseParser implementation bridging to ParsedFile."""
        unit = self.parse_file(
            file_path=discovered_file.absolute_path,
            relative_path=discovered_file.relative_path,
            language=discovered_file.language,
        )
        return ParsedFile(
            absolute_path=unit.absolute_path,
            relative_path=unit.file_path,
            language=unit.language,
            source_code=unit.source_code,
            lines=unit.lines,
            ast_root=unit.tree.root_node if unit.tree else None,
            parse_errors=unit.errors,
            structure=unit.structure,
            unit=unit,
        )

    def _find_first_error(self, node: Any) -> Any | None:
        """Find the first ERROR or MISSING node in AST."""
        if node.type in ("ERROR", "MISSING"):
            return node
        for child in node.children:
            if child.has_error:
                found = self._find_first_error(child)
                if found:
                    return found
        return None
