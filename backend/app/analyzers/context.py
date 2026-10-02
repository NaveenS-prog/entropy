"""Analysis execution contexts for repository and Python AST inspection."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.analyzers.jsts_context import JSTSASTContext
from app.models.domain.enums import SupportedLanguage
from app.models.domain.finding import CodeEvidence
from app.models.domain.manifest import RepositoryManifest
from app.parser.base import ParsedFile
from app.parser.jsts.models import ParsedJSTSUnit
from app.parser.python.models import (
    Assignment,
    CallExpression,
    ClassDefinition,
    ControlFlowConstruct,
    Decorator,
    ExceptionHandler,
    FunctionDefinition,
    ImportItem,
    ParsedPythonUnit,
    ParseStatus,
    PythonModuleStructure,
    RaiseStatement,
    ReturnStatement,
    SourceLocation,
)
from app.parser.python.visitor import PythonAstVisitor


class PythonASTContext:
    """Analyzer-friendly context for querying an individual parsed Python source file.

    Pre-indexes structural elements so future rules never need to perform
    redundant full-AST traversals.
    """

    def __init__(self, unit: ParsedPythonUnit) -> None:
        self.unit = unit
        self.file_path = unit.file_path
        self.absolute_path = unit.absolute_path
        self.structure: PythonModuleStructure = unit.structure or PythonModuleStructure(
            file_path=unit.file_path
        )
        self.source_code = unit.source_code
        self.lines = unit.lines

        # Index lookups
        self._functions_by_name: dict[str, FunctionDefinition] = {}
        self._functions_by_qname: dict[str, FunctionDefinition] = {}
        self._classes_by_name: dict[str, ClassDefinition] = {}
        self._classes_by_qname: dict[str, ClassDefinition] = {}
        self._func_ranges: list[tuple[int, int, FunctionDefinition]] = []
        self._class_ranges: list[tuple[int, int, ClassDefinition]] = []

        self._build_indexes()

    def _build_indexes(self) -> None:
        """Build efficient lookup caches for functions, classes, and scopes."""
        for func in self.structure.functions:
            self._functions_by_name[func.name] = func
            self._functions_by_qname[func.qualified_name] = func
            self._func_ranges.append((func.location.line_start, func.location.line_end, func))

        for cls in self.structure.classes:
            self._classes_by_name[cls.name] = cls
            self._classes_by_qname[cls.qualified_name] = cls
            self._class_ranges.append((cls.location.line_start, cls.location.line_end, cls))

        # Sort ranges by innermost span (narrowest first) for accurate enclosing queries
        self._func_ranges.sort(key=lambda item: (item[1] - item[0]))
        self._class_ranges.sort(key=lambda item: (item[1] - item[0]))

    @property
    def is_valid(self) -> bool:
        return self.unit.is_valid

    @property
    def ast_root(self) -> ast.Module | None:
        return self.unit.ast_root

    # -------------------------------------------------------------------------
    # Enclosing Scope Lookups
    # -------------------------------------------------------------------------

    def get_enclosing_function(
        self, target: int | ast.AST | SourceLocation
    ) -> FunctionDefinition | None:
        """Find the innermost enclosing function containing the target line or node."""
        line = self._resolve_line_number(target)
        if line is None:
            return None

        for start, end, func in self._func_ranges:
            if start <= line <= end:
                return func
        return None

    def get_enclosing_class(
        self, target: int | ast.AST | SourceLocation
    ) -> ClassDefinition | None:
        """Find the innermost enclosing class containing the target line or node."""
        line = self._resolve_line_number(target)
        if line is None:
            return None

        for start, end, cls in self._class_ranges:
            if start <= line <= end:
                return cls
        return None

    @staticmethod
    def _resolve_line_number(target: int | ast.AST | SourceLocation) -> int | None:
        if isinstance(target, int):
            return target
        if isinstance(target, SourceLocation):
            return target.line_start
        if hasattr(target, "lineno"):
            return target.lineno
        return None

    # -------------------------------------------------------------------------
    # Structural Queries
    # -------------------------------------------------------------------------

    def get_imports(self) -> list[ImportItem]:
        """Return all imports declared in this file."""
        return list(self.structure.imports)

    def get_import(self, name_or_module: str) -> ImportItem | None:
        """Find an import matching the imported name, alias, or module."""
        for imp in self.structure.imports:
            if (
                imp.name == name_or_module
                or imp.alias == name_or_module
                or imp.module == name_or_module
            ):
                return imp
        return None

    def has_import(self, name_or_module: str) -> bool:
        """Check whether a specific module or name is imported."""
        return self.get_import(name_or_module) is not None

    def get_classes(self) -> list[ClassDefinition]:
        """Return all classes defined in this file."""
        return list(self.structure.classes)

    def get_class(self, name_or_qname: str) -> ClassDefinition | None:
        """Look up a class by its simple or qualified name."""
        return self._classes_by_qname.get(name_or_qname) or self._classes_by_name.get(name_or_qname)

    def get_functions(self) -> list[FunctionDefinition]:
        """Return all functions and methods defined in this file."""
        return list(self.structure.functions)

    def get_function(self, name_or_qname: str) -> FunctionDefinition | None:
        """Look up a function by its simple or qualified name."""
        return self._functions_by_qname.get(name_or_qname) or self._functions_by_name.get(
            name_or_qname
        )

    def get_calls(self, callable_name: str | None = None) -> list[CallExpression]:
        """Return all function/method calls in this file, optionally filtered by name."""
        if callable_name is None:
            return list(self.structure.all_calls)
        return [c for c in self.structure.all_calls if c.callable_name == callable_name]

    def get_calls_in_function(self, function_name: str) -> list[CallExpression]:
        """Return all calls within a specific function or method."""
        return [c for c in self.structure.all_calls if c.enclosing_function == function_name]

    def get_exception_handlers(
        self, enclosing_func: str | None = None
    ) -> list[ExceptionHandler]:
        """Return all exception handlers (except blocks), optionally filtered by function."""
        if enclosing_func is None:
            return list(self.structure.all_handlers)
        return [h for h in self.structure.all_handlers if h.enclosing_function == enclosing_func]

    def get_bare_exception_handlers(self) -> list[ExceptionHandler]:
        """Return all bare except handlers (except:)."""
        return [h for h in self.structure.all_handlers if h.is_bare]

    def get_raises(self, enclosing_func: str | None = None) -> list[RaiseStatement]:
        """Return all raise statements, optionally filtered by function."""
        if enclosing_func is None:
            return list(self.structure.all_raises)
        return [r for r in self.structure.all_raises if r.enclosing_function == enclosing_func]

    def get_returns(self, enclosing_func: str | None = None) -> list[ReturnStatement]:
        """Return all return statements, optionally filtered by function."""
        if enclosing_func is None:
            return list(self.structure.all_returns)
        return [r for r in self.structure.all_returns if r.enclosing_function == enclosing_func]

    def get_decorators(self, name: str | None = None) -> list[Decorator]:
        """Return all decorators across all classes and functions."""
        results: list[Decorator] = []
        for cls in self.structure.classes:
            results.extend(cls.decorators)
        for fn in self.structure.functions:
            results.extend(fn.decorators)
        if name is not None:
            return [d for d in results if d.name == name]
        return results

    def get_assignments(self, target_name: str | None = None) -> list[Assignment]:
        """Return all assignments, optionally filtered by target variable name."""
        all_assigns: list[Assignment] = []
        all_assigns.extend(self.structure.global_assignments)
        for cls in self.structure.classes:
            all_assigns.extend(cls.class_assignments)
        for fn in self.structure.functions:
            all_assigns.extend(fn.assignments)
        if target_name is not None:
            return [a for a in all_assigns if target_name in a.targets]
        return all_assigns

    def get_control_flows(self, kind: str | None = None) -> list[ControlFlowConstruct]:
        """Return all control flow constructs (if, for, while, with, assert, try)."""
        if kind is None:
            return list(self.structure.all_control_flows)
        return [cf for cf in self.structure.all_control_flows if cf.kind == kind]

    # -------------------------------------------------------------------------
    # Source Code Access
    # -------------------------------------------------------------------------

    def get_source_line(self, line_number: int) -> str:
        """Get 1-indexed verbatim line of source code."""
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1].rstrip("\r\n")
        return ""

    def get_source_range(self, line_start: int, line_end: int) -> str:
        """Get a range of 1-indexed lines as a contiguous string."""
        total = len(self.lines)
        start = max(1, line_start)
        end = min(total, line_end)
        return "".join(self.lines[start - 1 : end])

    def extract_snippet(
        self,
        line_start: int,
        line_end: int,
        context_before: int = 1,
        context_after: int = 1,
    ) -> CodeEvidence:
        """Extract a highlighted CodeEvidence snippet around the target lines."""
        return self.unit.extract_snippet(
            line_start=line_start,
            line_end=line_end,
            context_before=context_before,
            context_after=context_after,
        )


@dataclass
class AnalysisContext:
    """Repository-level analysis context passed to static analyzers.

    Maintains backwards compatibility with Phase 0/1 ParsedFile collections
    while providing Phase 2 PythonASTContext indexed queries.
    """

    repo_path: Path
    parsed_files: list[ParsedFile]
    total_loc: int
    scanned_file_count: int
    manifest: RepositoryManifest | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # Internal lazy-loaded context caches
    _python_contexts: dict[str, PythonASTContext] = field(
        default_factory=dict, init=False, repr=False
    )
    _jsts_contexts: dict[str, JSTSASTContext] = field(
        default_factory=dict, init=False, repr=False
    )

    def __post_init__(self) -> None:
        self._index_python_contexts()
        self._index_jsts_contexts()

    @classmethod
    def from_python_units(
        cls,
        repo_path: Path,
        units: list[ParsedPythonUnit],
        manifest: RepositoryManifest | None = None,
        jsts_units: list[ParsedJSTSUnit] | None = None,
    ) -> AnalysisContext:
        """Construct AnalysisContext from ParsedPythonUnits and optional ParsedJSTSUnits."""
        parsed_files = [ParsedFile.from_unit(u) for u in units]
        if jsts_units:
            parsed_files.extend([ParsedFile.from_unit(u) for u in jsts_units])
        total_loc = sum(u.line_count for u in units) + (
            sum(u.line_count for u in jsts_units) if jsts_units else 0
        )
        total_scanned = len(units) + (len(jsts_units) if jsts_units else 0)
        return cls(
            repo_path=repo_path,
            parsed_files=parsed_files,
            total_loc=total_loc,
            scanned_file_count=total_scanned,
            manifest=manifest,
        )

    def _index_python_contexts(self) -> None:
        for pf in self.parsed_files:
            if pf.language == SupportedLanguage.PYTHON:
                if isinstance(pf.unit, ParsedPythonUnit):
                    self._python_contexts[pf.relative_path] = PythonASTContext(pf.unit)
                elif pf.is_valid and pf.ast_root is not None:
                    # Construct minimal unit from legacy ParsedFile if needed
                    visitor = PythonAstVisitor(file_path=pf.relative_path)
                    struct = (
                        visitor.extract(pf.ast_root)
                        if isinstance(pf.ast_root, ast.Module)
                        else PythonModuleStructure(file_path=pf.relative_path)
                    )
                    unit = ParsedPythonUnit(
                        file_path=pf.relative_path,
                        absolute_path=pf.absolute_path,
                        language=SupportedLanguage.PYTHON,
                        source_code=pf.source_code,
                        lines=pf.lines,
                        size_bytes=len(pf.source_code.encode("utf-8", errors="ignore")),
                        line_count=len(pf.lines),
                        ast_root=pf.ast_root,
                        status=ParseStatus.SUCCESS,
                        structure=struct,
                        errors=pf.parse_errors,
                    )
                    self._python_contexts[pf.relative_path] = PythonASTContext(unit)

    def _index_jsts_contexts(self) -> None:
        for pf in self.parsed_files:
            if pf.language in (SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT):
                if isinstance(pf.unit, ParsedJSTSUnit):
                    self._jsts_contexts[pf.relative_path] = JSTSASTContext(pf.unit)

    def get_files_for_language(self, language: SupportedLanguage) -> list[ParsedFile]:
        """Filter parsed files by language."""
        return [f for f in self.parsed_files if f.language == language and f.is_valid]

    def get_file(self, relative_path: str) -> ParsedFile | None:
        """Lookup a parsed file by relative path."""
        for f in self.parsed_files:
            if f.relative_path == relative_path:
                return f
        return None

    def get_python_context(self, relative_path: str) -> PythonASTContext | None:
        """Retrieve pre-indexed PythonASTContext for a specific Python file."""
        return self._python_contexts.get(relative_path)

    def get_all_python_contexts(self) -> list[PythonASTContext]:
        """Return all indexed Python file contexts."""
        return list(self._python_contexts.values())

    def get_valid_python_contexts(self) -> list[PythonASTContext]:
        """Return all valid, successfully parsed Python file contexts."""
        return [ctx for ctx in self._python_contexts.values() if ctx.is_valid]

    def get_failed_python_files(self) -> list[ParsedFile]:
        """Return all Python files that failed parsing due to syntax or encoding errors."""
        return [
            f
            for f in self.parsed_files
            if f.language == SupportedLanguage.PYTHON and not f.is_valid
        ]

    def get_jsts_context(self, relative_path: str) -> JSTSASTContext | None:
        """Retrieve pre-indexed JSTSASTContext for a specific JS/TS file."""
        return self._jsts_contexts.get(relative_path)

    def get_all_jsts_contexts(self) -> list[JSTSASTContext]:
        """Return all indexed JS/TS file contexts."""
        return list(self._jsts_contexts.values())

    def get_valid_jsts_contexts(self) -> list[JSTSASTContext]:
        """Return all valid, successfully parsed JS/TS file contexts."""
        return [ctx for ctx in self._jsts_contexts.values() if ctx.is_valid]

    def get_failed_jsts_files(self) -> list[ParsedFile]:
        """Return all JS/TS files that failed parsing due to syntax or read errors."""
        return [
            f
            for f in self.parsed_files
            if f.language in (SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT)
            and not f.is_valid
        ]
