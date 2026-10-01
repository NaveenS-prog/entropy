"""Repository input sources abstraction and security validation."""

import os
from abc import ABC, abstractmethod
from pathlib import Path

from app.core.errors import (
    RepositoryNotADirectoryError,
    RepositoryNotFoundError,
    RepositoryPermissionError,
    RepositorySecurityError,
)


class RepositorySource(ABC):
    """Abstract base class for repository ingestion sources.

    Designed to support LocalRepositorySource now and future sources
    (such as GitUrlRepositorySource or ArchiveUploadSource) without modifying the scanner.
    """

    @abstractmethod
    def validate(self) -> None:
        """Validate the repository source and permissions."""
        ...

    @abstractmethod
    def get_root_path(self) -> Path:
        """Return the local root directory path containing repository source files."""
        ...

    @abstractmethod
    def get_name(self) -> str:
        """Return a display name for the repository."""
        ...


class LocalRepositorySource(RepositorySource):
    """Local filesystem repository source with strict security validation."""

    def __init__(self, path: str | Path, name: str | None = None):
        if not path or not str(path).strip():
            raise RepositoryNotFoundError("Repository path cannot be empty.")
        self.raw_path = str(path).strip()
        self.custom_name = name
        self._resolved_path: Path | None = None

    def validate(self) -> None:
        """Strictly validate the repository path against path traversal and access failures."""
        try:
            resolved = Path(self.raw_path).expanduser().resolve()
        except Exception as e:
            raise RepositorySecurityError(f"Invalid repository path format: {e}") from e

        if not resolved.exists():
            raise RepositoryNotFoundError(f"Repository path does not exist: {resolved}")

        if not resolved.is_dir():
            raise RepositoryNotADirectoryError(f"Repository path is not a directory: {resolved}")

        # Check read access permissions
        if not os.access(resolved, os.R_OK):
            raise RepositoryPermissionError(f"Permission denied: Unable to read directory {resolved}")

        self._resolved_path = resolved

    def get_root_path(self) -> Path:
        """Return the fully validated, resolved local path."""
        if self._resolved_path is None:
            self.validate()
        assert self._resolved_path is not None
        return self._resolved_path

    def get_name(self) -> str:
        """Return repository display name (custom name or directory basename)."""
        if self.custom_name:
            return self.custom_name
        return self.get_root_path().name or "unnamed-repo"
