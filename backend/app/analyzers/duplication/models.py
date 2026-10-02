"""Domain and structural models for Code Duplication & Boilerplate Debt analysis."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.parser.python.models import SourceLocation


@dataclass(frozen=True)
class FunctionSignature:
    """Normalized structural representation of a Python function or method."""

    name: str
    qualified_name: str
    file_path: str
    location: SourceLocation
    statement_count: int
    node_count: int
    exact_hash: str
    structural_tokens: tuple[str, ...]
    control_flow_shape: tuple[str, ...]
    source_code: str
    is_async: bool = False
    is_method: bool = False
    parameter_count: int = 0
    call_names: tuple[str, ...] = ()
    operators: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        """Deterministic identifier for this function signature."""
        return f"{self.file_path}:{self.location.line_start}:{self.name}"


@dataclass
class DuplicationCluster:
    """A deterministic cluster of structurally identical or highly similar functions."""

    cluster_id: str
    representative: FunctionSignature
    members: list[FunctionSignature]
    similarity: float
    is_exact: bool
    is_cross_file: bool
    normalized_size: int
    files: set[str] = field(default_factory=set)

    @property
    def occurrence_count(self) -> int:
        return len(self.members)


@dataclass
class BoilerplatePattern:
    """A repeated structural boilerplate pattern occurring across functions or files."""

    pattern_id: str
    pattern_type: str  # e.g. "try_except_fallback", "validate_transform_return"
    representative: FunctionSignature
    occurrences: list[tuple[FunctionSignature, SourceLocation]]
    frequency: int
    files: set[str]
