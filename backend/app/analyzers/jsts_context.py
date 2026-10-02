"""Analyzer-friendly context for querying parsed JavaScript and TypeScript files."""

from __future__ import annotations

from typing import Any

from app.models.domain.finding import CodeEvidence
from app.parser.jsts.models import (
    JSAssignment,
    JSCall,
    JSCatch,
    JSClass,
    JSExport,
    JSFunction,
    JSImport,
    JSReturn,
    JSRoute,
    JSTSModuleStructure,
    ParsedJSTSUnit,
)


class JSTSASTContext:
    """Pre-indexed, queryable context for a single JS/TS source file."""

    def __init__(self, unit: ParsedJSTSUnit) -> None:
        self.unit = unit
        self.file_path = unit.file_path
        self.absolute_path = unit.absolute_path
        self.language = unit.language
        self.structure: JSTSModuleStructure = unit.structure or JSTSModuleStructure(
            file_path=unit.file_path,
            language=unit.language,
        )
        self.source_code = unit.source_code
        self.lines = unit.lines

        # Index lookups
        self._functions_by_name: dict[str, JSFunction] = {}
        self._functions_by_qname: dict[str, JSFunction] = {}
        self._classes_by_name: dict[str, JSClass] = {}
        self._build_indexes()

    def _build_indexes(self) -> None:
        for fn in self.structure.functions:
            self._functions_by_name[fn.name] = fn
            self._functions_by_qname[fn.qualified_name] = fn

        for cls in self.structure.classes:
            self._classes_by_name[cls.name] = cls

    @property
    def is_valid(self) -> bool:
        return self.unit.is_valid

    @property
    def tree(self) -> Any | None:
        return self.unit.tree

    def get_imports(self) -> list[JSImport]:
        """Return all imports declared in this file."""
        return list(self.structure.imports)

    def has_import(self, module_name: str) -> bool:
        """Check whether a module or package is imported."""
        target = module_name.lower()
        return any(target in imp.module.lower() for imp in self.structure.imports)

    def get_exports(self) -> list[JSExport]:
        """Return all exports."""
        return list(self.structure.exports)

    def get_functions(self) -> list[JSFunction]:
        """Return all functions and methods."""
        return list(self.structure.functions)

    def get_function(self, name_or_qname: str) -> JSFunction | None:
        """Look up function by simple or qualified name."""
        return self._functions_by_qname.get(name_or_qname) or self._functions_by_name.get(name_or_qname)

    def get_classes(self) -> list[JSClass]:
        """Return all classes."""
        return list(self.structure.classes)

    def get_class(self, name: str) -> JSClass | None:
        """Look up class by name."""
        return self._classes_by_name.get(name)

    def get_calls(self, callee_name: str | None = None) -> list[JSCall]:
        """Return calls, optionally filtered by callee string."""
        if callee_name is None:
            return list(self.structure.all_calls)
        return [c for c in self.structure.all_calls if c.callee == callee_name]

    def get_exception_handlers(self) -> list[JSCatch]:
        """Return all catch blocks."""
        return list(self.structure.all_handlers)

    def get_assignments(self, target_name: str | None = None) -> list[JSAssignment]:
        """Return all variable assignments, optionally filtered by target identifier."""
        if target_name is None:
            return list(self.structure.all_assignments)
        return [a for a in self.structure.all_assignments if a.target == target_name]

    def get_returns(self) -> list[JSReturn]:
        """Return all return statements."""
        return list(self.structure.all_returns)

    def get_routes(self) -> list[JSRoute]:
        """Return all extracted routes."""
        return list(self.structure.routes)

    def get_frameworks(self) -> set[str]:
        """Return all detected frameworks for this file."""
        return set(self.structure.frameworks)

    def has_framework(self, name: str) -> bool:
        """Check if a specific framework is active."""
        return name.lower() in {f.lower() for f in self.structure.frameworks}

    def get_source_line(self, line_number: int) -> str:
        """Get 1-indexed verbatim line of source code."""
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1].rstrip("\r\n")
        return ""

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
