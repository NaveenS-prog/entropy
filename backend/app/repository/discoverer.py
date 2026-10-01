"""Repository file discovery and ingestion."""

import os
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import RepositoryNotFoundError
from app.models.domain.enums import SupportedLanguage
from app.repository.language import detect_language, is_scannable_file

EXCLUDED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "venv",
    ".venv",
    "ENV",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    "out",
    "dist",
    "build",
    ".idea",
    ".vscode",
    "target",
    ".gradle",
    "vendor",
}

EXCLUDED_FILE_PATTERNS = {
    ".min.js",
    ".min.css",
    ".map",
    ".lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
}


@dataclass
class DiscoveredFile:
    """Represents a discovered source file in the repository."""

    absolute_path: Path
    relative_path: str
    language: SupportedLanguage
    size_bytes: int
    line_count: int


class RepositoryDiscoverer:
    """Discovers source files within a repository directory."""

    def __init__(self, max_file_size_bytes: int = 2 * 1024 * 1024):
        self.max_file_size_bytes = max_file_size_bytes

    def discover(self, root_path: Path | str) -> list[DiscoveredFile]:
        """Walk root_path and return all scannable source files."""
        root = Path(root_path).resolve()
        if not root.exists() or not root.is_dir():
            raise RepositoryNotFoundError(f"Repository directory does not exist: {root}")

        discovered: list[DiscoveredFile] = []

        for dirpath, dirnames, filenames in os.walk(root):
            # Prune excluded directories in-place
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRECTORIES and not d.startswith(".")]

            for filename in filenames:
                # Check excluded suffixes / patterns
                if any(filename.endswith(pat) for pat in EXCLUDED_FILE_PATTERNS):
                    continue

                full_path = Path(dirpath) / filename
                if not is_scannable_file(full_path):
                    continue

                try:
                    stat = full_path.stat()
                    if stat.st_size > self.max_file_size_bytes:
                        continue

                    # Read file to count LOC and confirm readability
                    with open(full_path, encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()
                        line_count = len(lines)

                    rel_path = full_path.relative_to(root).as_posix()
                    language = detect_language(full_path)

                    discovered.append(
                        DiscoveredFile(
                            absolute_path=full_path,
                            relative_path=rel_path,
                            language=language,
                            size_bytes=stat.st_size,
                            line_count=line_count,
                        )
                    )
                except (OSError, PermissionError):
                    # Fail gracefully on unreadable files without crashing the scan
                    continue

        # Sort files deterministically by relative path
        discovered.sort(key=lambda f: f.relative_path)
        return discovered
