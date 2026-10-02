"""Security analyzers subpackage for authentication and authorization consistency."""

from app.analyzers.security.auth.authentication import AuthenticationConsistencyAnalyzer
from app.analyzers.security.auth.authorization import AuthorizationConsistencyAnalyzer
from app.analyzers.security.auth.rules import (
    DuplicatedAuthenticationRule,
    DuplicatedAuthorizationRule,
    InconsistentAuthenticationRule,
    InconsistentAuthorizationRule,
    PotentiallyMissingAuthorizationRule,
    PotentiallyUnprotectedEndpointRule,
)

__all__ = [
    "AuthenticationConsistencyAnalyzer",
    "AuthorizationConsistencyAnalyzer",
    "DuplicatedAuthenticationRule",
    "DuplicatedAuthorizationRule",
    "InconsistentAuthenticationRule",
    "InconsistentAuthorizationRule",
    "PotentiallyMissingAuthorizationRule",
    "PotentiallyUnprotectedEndpointRule",
]
