import fnmatch
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

DEFAULT_EXCLUDED_PATHS: list[str] = [
    "test",
    "tests",
    "__tests__",
    "spec",
    "e2e",
    "integration",
    "examples",
    "example",
    "bench",
    "benchmarks",
    "benchmark",
    "docs",
    "docs_src",
    "fixtures",
    "__mocks__",
    "vendor",
    "third_party",
    "node_modules",
    "dist",
    "build",
    "*.test.*",
    "*.spec.*",
    "test_*.py",
    "*_test.py",
    "*_test.go",
    "*Test.java",
    "*Tests.java",
    "*TestCase.java",
    "*_test.c",
    "*_test.cpp",
    "*_test.rs",
    "*Test.php",
    "*.stories.*",
]


def is_scope_excluded(rel_path: str, excluded_patterns: list[str] | None = None) -> bool:
    """Determine whether a relative path should be excluded based on default scope rules."""
    patterns = excluded_patterns if excluded_patterns is not None else DEFAULT_EXCLUDED_PATHS
    posix_path = PurePosixPath(rel_path.replace("\\", "/"))
    dir_parts = set(posix_path.parts[:-1])
    filename = posix_path.name

    for pattern in patterns:
        if "*" in pattern:
            if fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(posix_path.as_posix(), pattern):
                return True
        else:
            if pattern in dir_parts or filename == pattern:
                return True
    return False


@dataclass
class ScannerConfig:
    """Configurable boundaries, limits, and ignore rules for repository scanning."""

    max_file_size_bytes: int = 2 * 1024 * 1024  # 2MB
    max_file_count: int = 50_000               # 50,000 files
    max_repo_size_bytes: int = 500 * 1024 * 1024  # 500MB
    respect_gitignore: bool = True
    follow_symlinks: bool = False
    include_tests: bool = False
    excluded_paths: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDED_PATHS))
    custom_exclude_patterns: list[str] = field(default_factory=list)
    analyzable_languages: set[Any] | None = None

    ignored_directories: set[str] = field(
        default_factory=lambda: {
            ".git",
            ".hg",
            ".svn",
            "node_modules",
            "venv",
            ".venv",
            "env",
            "ENV",
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            ".mypy_cache",
            "dist",
            "build",
            "coverage",
            ".next",
            "target",
            "vendor",
            ".idea",
            ".vscode",
            ".gradle",
            "out",
            ".turbo",
            ".cache",
            "__generated__",
        }
    )

    ignored_file_patterns: set[str] = field(
        default_factory=lambda: {
            ".min.js",
            ".min.css",
            ".generated.js",
            ".generated.ts",
            ".map",
            ".lock",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "poetry.lock",
            "Pipfile.lock",
        }
    )

    binary_extensions: set[str] = field(
        default_factory=lambda: {
            # Images
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".ico",
            ".webp",
            ".svg",
            ".bmp",
            ".tiff",
            # Audio & Video
            ".mp4",
            ".mov",
            ".avi",
            ".mkv",
            ".mp3",
            ".wav",
            ".ogg",
            # Archives & Compressed
            ".zip",
            ".tar",
            ".gz",
            ".bz2",
            ".7z",
            ".rar",
            ".xz",
            # Binaries, Executables & Bytecode
            ".pyc",
            ".pyo",
            ".so",
            ".dll",
            ".dylib",
            ".exe",
            ".bin",
            ".class",
            ".o",
            ".a",
            ".wasm",
            # Documents & Databases
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".sqlite",
            ".sqlite3",
            ".db",
        }
    )
