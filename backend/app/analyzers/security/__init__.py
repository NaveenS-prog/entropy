"""Security analyzers module."""

from typing import Any

__all__ = [
    "AuthenticationConsistencyAnalyzer",
    "AuthorizationConsistencyAnalyzer",
    "InputValidationConsistencyAnalyzer",
    "LoggingAndSecretsAnalyzer",
]


def __getattr__(name: str) -> Any:
    if name == "AuthenticationConsistencyAnalyzer":
        from app.analyzers.security.auth.authentication import (
            AuthenticationConsistencyAnalyzer,
        )

        return AuthenticationConsistencyAnalyzer
    if name == "AuthorizationConsistencyAnalyzer":
        from app.analyzers.security.auth.authorization import (
            AuthorizationConsistencyAnalyzer,
        )

        return AuthorizationConsistencyAnalyzer
    if name == "LoggingAndSecretsAnalyzer":
        from app.analyzers.security.logging_secrets import LoggingAndSecretsAnalyzer

        return LoggingAndSecretsAnalyzer
    if name == "InputValidationConsistencyAnalyzer":
        from app.analyzers.security.validation import InputValidationConsistencyAnalyzer

        return InputValidationConsistencyAnalyzer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
