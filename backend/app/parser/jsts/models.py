"""Normalized structural models for JavaScript and TypeScript AST analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.models.domain.enums import SupportedLanguage
from app.models.domain.finding import CodeEvidence
from app.parser.python.models import ParseStatus


@dataclass(frozen=True)
class JSSourceLocation:
    """Accurate source code location coordinates for JS/TS."""

    line_start: int  # 1-indexed
    line_end: int  # 1-indexed
    col_start: int = 0  # 0-indexed
    col_end: int = 0  # 0-indexed


@dataclass
class JSImport:
    """Represents an imported module and symbols."""

    module: str
    symbols: list[tuple[str, str | None]] = field(default_factory=list)  # [(imported, alias)]
    is_require: bool = False
    is_default: bool = False
    is_namespace: bool = False
    location: JSSourceLocation = field(default_factory=lambda: JSSourceLocation(1, 1))


@dataclass
class JSExport:
    """Represents an exported symbol or declaration."""

    name: str
    is_default: bool = False
    location: JSSourceLocation = field(default_factory=lambda: JSSourceLocation(1, 1))


@dataclass
class JSCall:
    """Represents a function or method call expression."""

    callee: str
    caller_object: str | None = None
    method_name: str | None = None
    arguments: list[str] = field(default_factory=list)
    location: JSSourceLocation = field(default_factory=lambda: JSSourceLocation(1, 1))
    enclosing_function: str | None = None


@dataclass
class JSCatch:
    """Represents a catch clause in a try statement."""

    param_name: str | None = None
    has_body: bool = True
    statement_count: int = 0
    is_empty: bool = True
    has_rethrow: bool = False
    has_logging: bool = False
    returns_fallback: bool = False
    fallback_value: str | None = None
    has_comment: bool = False
    comment_text: str | None = None
    location: JSSourceLocation = field(default_factory=lambda: JSSourceLocation(1, 1))
    enclosing_function: str | None = None


@dataclass
class JSReturn:
    """Represents a return statement."""

    value_text: str | None = None
    is_fallback_literal: bool = False
    location: JSSourceLocation = field(default_factory=lambda: JSSourceLocation(1, 1))
    enclosing_function: str | None = None


@dataclass
class JSAssignment:
    """Represents a variable declaration, assignment, or property initializer."""

    target: str
    value_text: str
    value_type: str  # "string", "number", "identifier", "call", "binary", etc.
    is_env_access: bool = False
    env_var_name: str | None = None
    fallback_text: str | None = None
    location: JSSourceLocation = field(default_factory=lambda: JSSourceLocation(1, 1))
    enclosing_function: str | None = None


@dataclass
class JSFunction:
    """Structural metadata for a JS/TS function, arrow function, or method."""

    name: str
    qualified_name: str
    file_path: str
    location: JSSourceLocation
    is_async: bool = False
    is_arrow: bool = False
    is_method: bool = False
    parameters: list[str] = field(default_factory=list)
    statement_count: int = 0
    node_count: int = 0
    enclosing_class: str | None = None
    calls: list[JSCall] = field(default_factory=list)
    handlers: list[JSCatch] = field(default_factory=list)
    returns: list[JSReturn] = field(default_factory=list)
    assignments: list[JSAssignment] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    body_text: str = ""
    ast_signature: str = ""  # Structural signature for duplication analysis


@dataclass
class JSClass:
    """Structural metadata for a JS/TS class."""

    name: str
    file_path: str
    location: JSSourceLocation
    base_classes: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    methods: list[JSFunction] = field(default_factory=list)


@dataclass
class JSRoute:
    """Extracted web framework route definition."""

    framework: str  # "express", "fastify", "nestjs", "nextjs"
    http_method: str  # "GET", "POST", "PUT", "DELETE", "PATCH", "ALL"
    path: str
    handler_name: str | None
    middleware: list[str] = field(default_factory=list)
    location: JSSourceLocation = field(default_factory=lambda: JSSourceLocation(1, 1))


@dataclass
class JSTSModuleStructure:
    """Normalized structural summary of a parsed JavaScript/TypeScript module."""

    file_path: str
    language: SupportedLanguage
    imports: list[JSImport] = field(default_factory=list)
    exports: list[JSExport] = field(default_factory=list)
    classes: list[JSClass] = field(default_factory=list)
    functions: list[JSFunction] = field(default_factory=list)
    all_calls: list[JSCall] = field(default_factory=list)
    all_handlers: list[JSCatch] = field(default_factory=list)
    all_assignments: list[JSAssignment] = field(default_factory=list)
    all_returns: list[JSReturn] = field(default_factory=list)
    routes: list[JSRoute] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)


@dataclass
class ParsedJSTSUnit:
    """High-level analysis representation of a parsed JS/TS source file."""

    file_path: str
    absolute_path: Path
    language: SupportedLanguage
    source_code: str = ""
    lines: list[str] = field(default_factory=list)
    size_bytes: int = 0
    line_count: int = 0
    tree: Any | None = None
    status: ParseStatus = ParseStatus.SUCCESS
    structure: JSTSModuleStructure | None = None
    errors: list[str] = field(default_factory=list)
    error_location: JSSourceLocation | None = None

    @property
    def is_valid(self) -> bool:
        """True if file parsed successfully without fatal syntax or read errors."""
        return self.status == ParseStatus.SUCCESS and self.tree is not None

    @property
    def ast_root(self) -> Any | None:
        """Return Tree-sitter root AST node if available."""
        return self.tree.root_node if self.tree is not None else None

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
        if total == 0:
            return CodeEvidence(
                content="",
                line_start=1,
                line_end=1,
                highlight_lines=[],
            )

        start = max(1, line_start - context_before)
        end = min(total, line_end + context_after)

        snippet_lines = self.lines[start - 1 : end]
        snippet_content = "".join(snippet_lines)
        highlight_lines = list(range(line_start, min(total, line_end) + 1))

        return CodeEvidence(
            content=snippet_content,
            line_start=start,
            line_end=end,
            highlight_lines=highlight_lines,
        )

    def to_summary_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dictionary for API/inspection endpoints."""
        return {
            "file_path": self.file_path,
            "language": self.language.value,
            "status": self.status.value,
            "line_count": self.line_count,
            "size_bytes": self.size_bytes,
            "is_valid": self.is_valid,
            "is_empty": self.line_count == 0 or len(self.source_code.strip()) == 0,
            "errors": self.errors,
            "imports_count": len(self.structure.imports) if self.structure else 0,
            "exports_count": len(self.structure.exports) if self.structure else 0,
            "classes_count": len(self.structure.classes) if self.structure else 0,
            "functions_count": len(self.structure.functions) if self.structure else 0,
            "calls_count": len(self.structure.all_calls) if self.structure else 0,
            "handlers_count": len(self.structure.all_handlers) if self.structure else 0,
            "routes_count": len(self.structure.routes) if self.structure else 0,
        }

