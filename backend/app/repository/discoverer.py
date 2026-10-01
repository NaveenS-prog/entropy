"""Repository file discovery and ingestion."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from app.core.errors import (
    RepositoryLimitExceededError,
    RepositoryNotADirectoryError,
    RepositoryNotFoundError,
    RepositoryPermissionError,
)
from app.models.domain.enums import SupportedLanguage
from app.models.domain.manifest import SkippedFileRecord
from app.repository.binary import is_binary_content, is_binary_extension
from app.repository.config import ScannerConfig
from app.repository.gitignore import GitIgnoreMatcher
from app.repository.language import (
    detect_language,
    get_analysis_skip_reason,
    is_analysis_supported,
)

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
    analysis_supported: bool = True
    skip_reason: str | None = None


@dataclass
class DiscoveryResult:
    """Complete summary of repository discovery traversal."""

    root_path: Path
    source_files: list[DiscoveredFile] = field(default_factory=list)
    skipped_files: list[SkippedFileRecord] = field(default_factory=list)
    ignored_files_count: int = 0
    total_files_inspected: int = 0
    total_source_bytes: int = 0
    total_source_loc: int = 0


class RepositoryDiscoverer:
    """Discovers source files within a repository directory."""
    """Discovers source files within a repository directory with robust security safeguards."""

    def __init__(self, config: ScannerConfig | int | None = None):
        if isinstance(config, int):
            self.config = ScannerConfig(max_file_size_bytes=config)
        else:
            self.config = config or ScannerConfig()

    def discover(self, root_path: Path | str) -> list[DiscoveredFile]:
        """Walk root_path and return all scannable source files."""
        return self.discover_repository(root_path).source_files

    def discover_repository(self, root_path: Path | str) -> DiscoveryResult:
        """Walk root_path safely and return complete discovery metrics and source files."""
        root = Path(root_path).resolve()
        if not root.exists():
            raise RepositoryNotFoundError(f"Repository directory does not exist: {root}")
        if not root.is_dir():
            raise RepositoryNotADirectoryError(f"Repository path is not a directory: {root}")
        if not os.access(root, os.R_OK):
            raise RepositoryPermissionError(f"Permission denied: Unable to read {root}")

        discovered: list[DiscoveredFile] = []
        result = DiscoveryResult(root_path=root)
        total_repo_bytes = 0

        # Load gitignore matcher if enabled
        gitignore = (
            GitIgnoreMatcher.from_root(root)
            if self.config.respect_gitignore
            else GitIgnoreMatcher()
        )

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # 1. Prune excluded directories in-place
            filtered_dirs = []
            for d in dirnames:
                dir_full = Path(dirpath) / d
                rel_dir = dir_full.relative_to(root).as_posix()

                if d in self.config.ignored_directories or (d.startswith(".") and d != "."):
                    result.ignored_files_count += 1
                    continue

                if self.config.respect_gitignore and gitignore.is_ignored(rel_dir, is_dir=True):
                    result.ignored_files_count += 1
                    continue

                filtered_dirs.append(d)
            dirnames[:] = filtered_dirs

            # Check if nested .gitignore exists in this directory
            if self.config.respect_gitignore and ".gitignore" in filenames:
                nested_git = Path(dirpath) / ".gitignore"
                rel_base = Path(dirpath).relative_to(root).as_posix()
                gitignore.parse_file(nested_git, base_rel_dir=rel_base if rel_base != "." else "")

            for filename in filenames:
                result.total_files_inspected += 1
                if result.total_files_inspected > self.config.max_file_count:
                    raise RepositoryLimitExceededError(
                        f"Repository exceeded maximum file limit of {self.config.max_file_count} files"
                    )

                full_path = Path(dirpath) / filename
                rel_path = full_path.relative_to(root).as_posix()

                # 2. Check symlink safety
                if full_path.is_symlink():
                    if not self.config.follow_symlinks:
                        result.skipped_files.append(
                            SkippedFileRecord(path=rel_path, size=0, reason="symlink_ignored")
                        )
                        continue
                    try:
                        resolved_symlink = full_path.resolve()
                        if not resolved_symlink.is_relative_to(root):
                            result.skipped_files.append(
                                SkippedFileRecord(
                                    path=rel_path,
                                    size=0,
                                    reason="symlink_points_outside_repository",
                                )
                            )
                            continue
                    except Exception:
                        result.skipped_files.append(
                            SkippedFileRecord(path=rel_path, size=0, reason="invalid_symlink")
                        )
                        continue

                # 3. Check excluded patterns and .gitignore
                if any(filename.endswith(pat) for pat in self.config.ignored_file_patterns):
                    result.ignored_files_count += 1
                    continue

                if self.config.respect_gitignore and gitignore.is_ignored(rel_path, is_dir=False):
                    result.ignored_files_count += 1
                    continue

                # 4. Check binary extension
                if is_binary_extension(full_path, self.config.binary_extensions):
                    try:
                        file_sz = full_path.stat().st_size
                    except OSError:
                        file_sz = 0
                    result.skipped_files.append(
                        SkippedFileRecord(path=rel_path, size=file_sz, reason="binary_file")
                    )
                    continue

                # 5. Check file size limits
                try:
                    stat = full_path.stat()
                except PermissionError:
                    result.skipped_files.append(
                        SkippedFileRecord(path=rel_path, size=0, reason="permission_denied")
                    )
                    continue
                except OSError:
                    result.skipped_files.append(
                        SkippedFileRecord(path=rel_path, size=0, reason="unreadable_file")
                    )
                    continue

                total_repo_bytes += stat.st_size
                if total_repo_bytes > self.config.max_repo_size_bytes:
                    raise RepositoryLimitExceededError(
                        f"Repository exceeded maximum size limit of {self.config.max_repo_size_bytes} bytes"
                    )

                if stat.st_size > self.config.max_file_size_bytes:
                    result.skipped_files.append(
                        SkippedFileRecord(
                            path=rel_path,
                            size=stat.st_size,
                            reason="file_size_exceeds_limit",
                        )
                    )
                    continue

                # 6. Check binary content
                if is_binary_content(full_path):
                    result.skipped_files.append(
                        SkippedFileRecord(
                            path=rel_path,
                            size=stat.st_size,
                            reason="binary_content_detected",
                        )
                    )
                    continue

                # 7. Check programming language
                language = detect_language(full_path)
                if language == SupportedLanguage.UNKNOWN:
                    # Non-code or unsupported file extension (e.g. .txt, .md, .yml)
                    continue

                # 8. Check readability and encoding
                try:
                    with open(full_path, encoding="utf-8") as f:
                        lines = f.readlines()
                        line_count = len(lines)
                except UnicodeDecodeError:
                    result.skipped_files.append(
                        SkippedFileRecord(
                            path=rel_path,
                            size=stat.st_size,
                            reason="unsupported_encoding_or_unreadable",
                        )
                    )
                    continue
                except PermissionError:
                    result.skipped_files.append(
                        SkippedFileRecord(
                            path=rel_path,
                            size=stat.st_size,
                            reason="permission_denied",
                        )
                    )
                    continue
                except OSError:
                    result.skipped_files.append(
                        SkippedFileRecord(
                            path=rel_path,
                            size=stat.st_size,
                            reason="unreadable_file",
                        )
                    )
                    continue

                analysis_supported = is_analysis_supported(language)
                skip_reason = get_analysis_skip_reason(language)

                discovered = DiscoveredFile(
                    absolute_path=full_path,
                    relative_path=rel_path,
                    language=language,
                    size_bytes=stat.st_size,
                    line_count=line_count,
                    analysis_supported=analysis_supported,
                    skip_reason=skip_reason,
                )

                result.source_files.append(discovered)
                result.total_source_bytes += stat.st_size
                result.total_source_loc += line_count

        result.source_files.sort(key=lambda f: f.relative_path)
        result.skipped_files.sort(key=lambda f: f.path)
        return result
    