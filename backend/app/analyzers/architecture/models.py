"""Domain models and data structures for Phase 9 Architectural Consistency Analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from app.parser.python.models import (
    CallExpression,
    ClassDefinition,
    FunctionDefinition,
    ImportItem,
)


class ArchitecturalLayer(StrEnum):
    """Observable architectural layers inferred from repository evidence."""

    API = "api"  # Routes, controllers, endpoints, handlers
    SERVICE = "service"  # Business logic, domain services, application workflows
    REPOSITORY = "repository"  # Persistence, database queries, ORM repositories
    MODEL = "model"  # Schemas, DTOs, domain models, entity definitions
    CONFIG = "config"  # Configuration, environment settings, application parameters
    SECURITY = "security"  # Authentication, authorization, cryptography, token management
    UTILITY = "utility"  # Shared helpers, formatting, math, data structures
    UNKNOWN = "unknown"  # Unclassified module


class ArchitecturalResponsibility(StrEnum):
    """Orthogonal architectural responsibility dimensions."""

    ROUTING_HTTP = "routing_http"  # Handles HTTP requests/responses, path operations
    PERSISTENCE_DB = "persistence_db"  # Performs database CRUD, queries, session handling
    AUTH_SECURITY = "auth_security"  # Validates credentials, tokens, permissions
    CONFIG_MANAGEMENT = "config_management"  # Reads environment, manages configuration settings
    BUSINESS_LOGIC = "business_logic"  # Domain computations, workflows, operations
    SYSTEM_IO = "system_io"  # Raw socket, OS process, or disk file operations


@dataclass
class ModuleNode:
    """Statically observable representation of an individual Python module."""

    file_path: str  # Repo-relative path, e.g. "backend/app/services/user.py"
    module_name: str  # Canonical module path, e.g. "backend.app.services.user"
    package_name: str  # Package containing the module, e.g. "backend.app.services"
    package_depth: int  # Depth in directory hierarchy
    loc: int  # Lines of code
    is_package_init: bool  # True if __init__.py

    imports: list[ImportItem] = field(default_factory=list)
    local_dependencies: set[str] = field(default_factory=set)  # Set of target module_names within repo
    external_dependencies: set[str] = field(default_factory=set)  # Third-party / stdlib imports
    imported_symbols: dict[str, str] = field(default_factory=dict)  # symbol -> source module

    classes: list[ClassDefinition] = field(default_factory=list)
    functions: list[FunctionDefinition] = field(default_factory=list)
    public_symbols: list[str] = field(default_factory=list)
    calls: list[CallExpression] = field(default_factory=list)

    inferred_layer: ArchitecturalLayer = ArchitecturalLayer.UNKNOWN
    layer_confidence: float = 0.0
    is_composition_root: bool = False
    responsibilities: set[ArchitecturalResponsibility] = field(default_factory=set)
    responsibility_evidence: dict[ArchitecturalResponsibility, list[str]] = field(default_factory=dict)

    source_code: str = ""


@dataclass
class DependencyCycle:
    """Represents a statically observable circular import dependency."""

    cycle_path: list[str]  # Canonical ordered list of module_names forming cycle, e.g. [A, B, C, A]
    length: int
    cycle_id: str  # Deterministic SHA256 identifier

    @property
    def canonical_repr(self) -> str:
        return " -> ".join(self.cycle_path)


@dataclass
class ArchitectureModel:
    """Complete repository-wide architecture representation."""

    modules: dict[str, ModuleNode] = field(default_factory=dict)  # module_name -> ModuleNode
    modules_by_path: dict[str, ModuleNode] = field(default_factory=dict)  # file_path -> ModuleNode
    package_hierarchy: dict[str, set[str]] = field(default_factory=dict)  # package -> set of subpackages/modules

    # Layer distributions
    modules_by_layer: dict[ArchitecturalLayer, list[str]] = field(default_factory=dict)

    # Dominant patterns observed
    has_centralized_config: bool = False
    centralized_config_modules: list[str] = field(default_factory=list)
    dominant_layer_flow: str | None = None
