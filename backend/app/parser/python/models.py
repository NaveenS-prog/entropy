"""Normalized structural models for the Python AST analysis engine."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from app.models.domain.enums import SupportedLanguage
from app.models.domain.finding import CodeEvidence


class ParseStatus(StrEnum):
    """Status outcomes for a Python file parse attempt."""

    SUCCESS = "SUCCESS"
    SYNTAX_ERROR = "SYNTAX_ERROR"
    ENCODING_ERROR = "ENCODING_ERROR"
    READ_ERROR = "READ_ERROR"
    UNSUPPORTED_LANGUAGE = "UNSUPPORTED_LANGUAGE"


@dataclass(frozen=True)
class SourceLocation:
    """Accurate source code location coordinates."""

    line_start: int
    line_end: int
    col_offset: int | None = None
    end_col_offset: int | None = None

    @classmethod
    def from_node(cls, node: ast.AST) -> SourceLocation:
        """Create SourceLocation from any AST node that has line information."""
        line_start = getattr(node, "lineno", 1)
        line_end = getattr(node, "end_lineno", line_start)
        col_offset = getattr(node, "col_offset", None)
        end_col_offset = getattr(node, "end_col_offset", None)
        return cls(
            line_start=line_start,
            line_end=line_end,
            col_offset=col_offset,
            end_col_offset=end_col_offset,
        )


@dataclass
class ImportItem:
    """Represents a normalized import statement."""

    module: str | None
    name: str
    alias: str | None
    is_from: bool
    level: int
    location: SourceLocation


@dataclass
class Parameter:
    """Represents a parameter in a function or method signature."""

    name: str
    annotation: str | None
    default_value: str | None
    kind: str  # posonly, arg, vararg, kwonly, kwarg
    location: SourceLocation | None = None


@dataclass
class Decorator:
    """Represents a decorator applied to a class, function, or method."""

    expression: str
    name: str
    arguments: list[str] = field(default_factory=list)
    keyword_arguments: dict[str, str] = field(default_factory=dict)
    location: SourceLocation = field(default_factory=lambda: SourceLocation(1, 1))


@dataclass
class CallExpression:
    """Represents a function or method invocation."""

    callable_name: str
    expression: str
    arg_count: int
    positional_args: list[str]
    keyword_args: list[str]
    location: SourceLocation
    enclosing_function: str | None = None
    enclosing_class: str | None = None


@dataclass
class ExceptionHandler:
    """Represents an except block in a try statement."""

    exception_types: list[str]
    name: str | None
    is_bare: bool
    has_body: bool
    body_statement_count: int
    has_pass_only: bool
    location: SourceLocation
    enclosing_function: str | None = None
    enclosing_class: str | None = None


@dataclass
class RaiseStatement:
    """Represents a raise statement."""

    exception_type: str | None
    expression: str | None
    has_cause: bool
    cause_type: str | None
    location: SourceLocation
    enclosing_function: str | None = None
    enclosing_class: str | None = None


@dataclass
class ReturnStatement:
    """Represents a return statement."""

    has_value: bool
    value_representation: str | None
    location: SourceLocation
    enclosing_function: str | None = None


@dataclass
class Assignment:
    """Represents a variable, attribute, or subscript assignment."""

    targets: list[str]
    value_representation: str | None
    value_type: str
    is_augmented: bool
    operator: str | None
    location: SourceLocation
    enclosing_function: str | None = None
    enclosing_class: str | None = None


@dataclass
class ControlFlowConstruct:
    """Represents a control-flow block (if, for, while, with, assert, try)."""

    kind: str
    location: SourceLocation
    has_else: bool = False
    is_async: bool = False
    condition_or_target: str | None = None
    enclosing_function: str | None = None


@dataclass
class FunctionDefinition:
    """Structural metadata for a function or method."""

    name: str
    qualified_name: str
    file_path: str
    location: SourceLocation
    is_async: bool = False
    is_method: bool = False
    decorators: list[Decorator] = field(default_factory=list)
    parameters: list[Parameter] = field(default_factory=list)
    return_annotation: str | None = None
    docstring: str | None = None
    statement_count: int = 0
    nested_functions: list[str] = field(default_factory=list)
    calls: list[CallExpression] = field(default_factory=list)
    handlers: list[ExceptionHandler] = field(default_factory=list)
    raises: list[RaiseStatement] = field(default_factory=list)
    returns: list[ReturnStatement] = field(default_factory=list)
    assignments: list[Assignment] = field(default_factory=list)
    control_flows: list[ControlFlowConstruct] = field(default_factory=list)


@dataclass
class ClassDefinition:
    """Structural metadata for a class."""

    name: str
    qualified_name: str
    file_path: str
    location: SourceLocation
    decorators: list[Decorator] = field(default_factory=list)
    base_classes: list[str] = field(default_factory=list)
    docstring: str | None = None
    methods: list[FunctionDefinition] = field(default_factory=list)
    class_assignments: list[Assignment] = field(default_factory=list)
    nested_classes: list[str] = field(default_factory=list)


@dataclass
class PythonModuleStructure:
    """Comprehensive, normalized structural summary of a parsed Python module."""

    file_path: str
    docstring: str | None = None
    imports: list[ImportItem] = field(default_factory=list)
    classes: list[ClassDefinition] = field(default_factory=list)
    functions: list[FunctionDefinition] = field(default_factory=list)
    global_assignments: list[Assignment] = field(default_factory=list)
    all_calls: list[CallExpression] = field(default_factory=list)
    all_handlers: list[ExceptionHandler] = field(default_factory=list)
    all_raises: list[RaiseStatement] = field(default_factory=list)
    all_returns: list[ReturnStatement] = field(default_factory=list)
    all_control_flows: list[ControlFlowConstruct] = field(default_factory=list)


@dataclass
class ParsedPythonUnit:
    """High-level analysis representation of a parsed Python source file."""

    file_path: str
    absolute_path: Path
    language: SupportedLanguage = SupportedLanguage.PYTHON
    source_code: str = ""
    lines: list[str] = field(default_factory=list)
    size_bytes: int = 0
    line_count: int = 0
    ast_root: ast.Module | None = None
    status: ParseStatus = ParseStatus.SUCCESS
    structure: PythonModuleStructure | None = None
    errors: list[str] = field(default_factory=list)
    error_location: SourceLocation | None = None
    is_empty: bool = False

    @property
    def is_valid(self) -> bool:
        """True if file parsed successfully without syntax, encoding, or read errors."""
        return self.status == ParseStatus.SUCCESS and self.ast_root is not None

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
            "is_empty": self.is_empty,
            "errors": self.errors,
            "imports_count": len(self.structure.imports) if self.structure else 0,
            "classes_count": len(self.structure.classes) if self.structure else 0,
            "functions_count": len(self.structure.functions) if self.structure else 0,
            "calls_count": len(self.structure.all_calls) if self.structure else 0,
            "handlers_count": len(self.structure.all_handlers) if self.structure else 0,
            "raises_count": len(self.structure.all_raises) if self.structure else 0,
        }
