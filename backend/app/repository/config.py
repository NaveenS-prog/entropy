"""Configuration for repository file discovery, ingestion, and security boundaries."""

from dataclasses import dataclass, field


@dataclass
class ScannerConfig:
    """Configurable boundaries, limits, and ignore rules for repository scanning."""

    max_file_size_bytes: int = 2 * 1024 * 1024  # 2MB
    max_file_count: int = 50_000               # 50,000 files
    max_repo_size_bytes: int = 500 * 1024 * 1024  # 500MB
    respect_gitignore: bool = True
    follow_symlinks: bool = False

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
        }
    )

    ignored_file_patterns: set[str] = field(
        default_factory=lambda: {
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
