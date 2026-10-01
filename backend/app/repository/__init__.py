"""Repository ingestion and analysis package."""

from app.repository.config import ScannerConfig
from app.repository.discoverer import DiscoveredFile, DiscoveryResult, RepositoryDiscoverer
from app.repository.git_service import GitService
from app.repository.gitignore import GitIgnoreMatcher, GitIgnoreRule
from app.repository.language import detect_language, is_scannable_file
from app.repository.manifest import ManifestBuilder
from app.repository.scanner import RepositoryScanner
from app.repository.sources import LocalRepositorySource, RepositorySource

__all__ = [
    "ScannerConfig",
    "RepositoryDiscoverer",
    "DiscoveredFile",
    "DiscoveryResult",
    "GitService",
    "GitIgnoreMatcher",
    "GitIgnoreRule",
    "detect_language",
    "is_scannable_file",
    "ManifestBuilder",
    "RepositoryScanner",
    "RepositorySource",
    "LocalRepositorySource",
]
