"""Domain and structural models for Security Analyzers (Authentication & Authorization)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from app.models.domain.enums import Confidence
from app.parser.python.models import SourceLocation

if TYPE_CHECKING:
    from app.parser.python.models import ClassDefinition, FunctionDefinition


class WebFramework(StrEnum):
    """Supported Python web application frameworks for route detection."""

    FASTAPI = "fastapi"
    FLASK = "flask"
    DJANGO = "django"
    GENERIC = "generic"
    UNKNOWN = "unknown"


class AuthMechanismType(StrEnum):
    """Normalized mechanisms through which authentication is verified."""

    DEPENDENCY = "dependency"
    DECORATOR = "decorator"
    GUARD_CALL = "guard_call"
    MIDDLEWARE_REFERENCE = "middleware_reference"
    KNOWN_AUTH_HELPER = "known_auth_helper"


class AuthzMechanismType(StrEnum):
    """Normalized mechanisms through which authorization is verified."""

    ROLE_CHECK = "role_check"
    PERMISSION_CHECK = "permission_check"
    OWNERSHIP_CHECK = "ownership_check"
    POLICY_CHECK = "policy_check"
    AUTHORIZATION_DECORATOR = "authorization_decorator"
    AUTHORIZATION_HELPER = "authorization_helper"


@dataclass(frozen=True)
class AuthenticationEvidence:
    """Normalized internal representation of observable authentication evidence."""

    mechanism_type: AuthMechanismType
    source_location: SourceLocation
    endpoint: str
    guard_name: str
    evidence_kind: str
    confidence: Confidence
    details: str = ""


@dataclass(frozen=True)
class AuthorizationEvidence:
    """Normalized internal representation of observable authorization evidence."""

    mechanism_type: AuthzMechanismType
    source_location: SourceLocation
    endpoint: str
    role_or_permission: str | None
    evidence_kind: str
    confidence: Confidence
    details: str = ""


@dataclass
class EndpointDefinition:
    """Normalized representation of a statically identified web endpoint / route."""

    symbol: str
    file_path: str
    location: SourceLocation
    http_methods: list[str]
    route_path: str | None
    framework: WebFramework
    is_security_sensitive: bool
    sensitivity_reasons: list[str] = field(default_factory=list)
    is_public: bool = False
    public_reasons: list[str] = field(default_factory=list)
    auth_evidence: list[AuthenticationEvidence] = field(default_factory=list)
    authz_evidence: list[AuthorizationEvidence] = field(default_factory=list)
    route_group: str = ""
    enclosing_class: str | None = None
    function_def: FunctionDefinition | None = None
    class_def: ClassDefinition | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def has_authentication(self) -> bool:
        """Whether any recognizable authentication evidence is present."""
        return len(self.auth_evidence) > 0

    @property
    def has_authorization(self) -> bool:
        """Whether any recognizable authorization evidence is present."""
        return len(self.authz_evidence) > 0

    @property
    def display_route(self) -> str:
        """Formatted representation of HTTP method and route path."""
        methods_str = "/".join(self.http_methods) if self.http_methods else "ANY"
        path_str = self.route_path or f"[{self.symbol}]"
        return f"{methods_str} {path_str}"
