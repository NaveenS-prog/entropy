"""Domain exceptions for Entropy."""


class EntropyError(Exception):
    """Base exception for all domain errors within Entropy."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


# Backwards compatibility alias
SilentGuardError = EntropyError


class RepositoryError(EntropyError):
    """Raised when repository access, cloning, or traversal fails."""


class RepositoryNotFoundError(RepositoryError):
    """Raised when the specified repository or directory cannot be found."""


class RepositoryNotADirectoryError(RepositoryError):
    """Raised when the repository path points to a file rather than a directory."""


class RepositoryPermissionError(RepositoryError):
    """Raised when permission is denied while accessing the repository path."""


class RepositorySecurityError(RepositoryError):
    """Raised when path traversal or insecure symlink behavior is detected."""


class RepositoryLimitExceededError(RepositoryError):
    """Raised when repository exceeds maximum configured files or size limit."""


class ParsingError(EntropyError):
    """Raised when file source parsing encounters fatal errors."""


class AnalyzerError(EntropyError):
    """Raised during analyzer registration or execution failure."""


class ScoringError(EntropyError):
    """Raised when scoring calculation fails due to invalid parameters or empty inputs."""
