"""Repository static analysis scanner orchestrating safe ingestion without code execution."""

import time
from datetime import UTC, datetime
from uuid import uuid4

from app.core.logging import logger
from app.models.domain.enums import ScanStatus
from app.models.domain.scan import RepositoryMetadata, RepositoryScanResult
from app.repository.config import ScannerConfig
from app.repository.discoverer import RepositoryDiscoverer
from app.repository.git_service import GitService
from app.repository.manifest import ManifestBuilder
from app.repository.sources import RepositorySource


class RepositoryScanner:
    """Safely inspects a repository and generates a structured RepositoryManifest.

    INVARIANT:
    The scanner NEVER executes code from the repository.
    No package managers, setup scripts, executables, or build commands are run.
    """

    def __init__(self, config: ScannerConfig | None = None):
        self.config = config or ScannerConfig()
        self.discoverer = RepositoryDiscoverer(self.config)

    def scan(self, source: RepositorySource) -> RepositoryScanResult:
        """Execute safe ingestion and manifest generation for a repository source."""
        scan_id = str(uuid4())
        started_at = datetime.now(UTC)
        start_time = time.perf_counter()

        # 1. Validate repository source and access permissions
        source.validate()
        root_path = source.get_root_path()
        repo_name = source.get_name()

        logger.info("Starting safe repository scan %s for '%s' at %s", scan_id, repo_name, root_path)

        # 2. File discovery & language classification
        discovery = self.discoverer.discover_repository(root_path)

        # 3. Non-destructive Git metadata retrieval
        branch = GitService.get_current_branch(root_path)
        commit = GitService.get_head_commit(root_path)
        remote_url = GitService.get_remote_url(root_path)

        # 4. Build manifest
        manifest = ManifestBuilder.build(
            repo_name=repo_name,
            root_path=root_path,
            discovery=discovery,
            timestamp=started_at,
        )

        repo_meta = RepositoryMetadata(
            name=repo_name,
            path=str(root_path),
            remote_url=remote_url,
            branch=branch,
            commit_hash=commit,
            total_files=discovery.total_files_inspected,
            scannable_files=len(discovery.source_files),
            total_loc=discovery.total_source_loc,
        )

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        completed_at = datetime.now(UTC)

        scan_result = RepositoryScanResult(
            scan_id=scan_id,
            repository=repo_meta,
            status=ScanStatus.COMPLETED,
            manifest=manifest,
            findings=[],  # Phase 1: No fake security findings
            score=None,   # Phase 1: No scoring yet
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=round(duration_ms, 2),
            analyzers_executed=[],
            errors=[],
        )

        logger.info(
            "Scan %s completed in %.2f ms. Discovered %d source files across %d languages.",
            scan_id,
            duration_ms,
            len(manifest.files),
            len(manifest.languages),
        )

        return scan_result
