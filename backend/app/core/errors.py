"""Domain exceptions for SilentGuard."""


class SilentGuardError(Exception):
    """Base exception for all domain errors within SilentGuard."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class RepositoryError(SilentGuardError):
    """Raised when repository access, cloning, or traversal fails."""


class RepositoryNotFoundError(RepositoryError):
    """Raised when the specified repository or directory cannot be found."""


class ParsingError(SilentGuardError):
    """Raised when file source parsing encounters fatal errors."""


class AnalyzerError(SilentGuardError):
    """Raised during analyzer registration or execution failure."""


class ScoringError(SilentGuardError):
    """Raised when scoring calculation fails due to invalid parameters or empty inputs."""
