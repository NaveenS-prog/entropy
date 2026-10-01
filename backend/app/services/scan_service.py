"""Scan orchestration service coordinating discovery, parsing, analysis, and scoring."""

import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from app.analyzers.base import AnalysisContext
from app.analyzers.registry import AnalyzerRegistry, default_registry
from app.core.errors import RepositoryNotFoundError
from app.core.logging import logger
from app.models.domain.enums import ScanStatus, SupportedLanguage
from app.models.domain.scan import RepositoryMetadata, RepositoryScanResult
from app.parser.base import BaseParser, ParsedFile
from app.parser.python_ast import PythonAstParser
from app.repository.discoverer import RepositoryDiscoverer
from app.repository.git_service import GitService
from app.repository.manifest import ManifestBuilder
from app.scoring.engine import ScoringEngine, scoring_engine
from app.services.repository_service import _scans_store


class ScanService:
    """End-to-end scanner coordinator implementing the Entropy Core User Flow:

    Repository ingestion -> File discovery -> Language detection -> Source-code parsing ->
    Static analysis -> Pattern detection -> Finding generation -> Debt scoring.
    """

    def __init__(
        self,
        registry: AnalyzerRegistry | None = None,
        scoring: ScoringEngine | None = None,
    ):
        self.registry = registry or default_registry
        self.scoring = scoring or scoring_engine
        self.discoverer = RepositoryDiscoverer()
        self.parsers: list[BaseParser] = [PythonAstParser()]
        # Shared scan store
        self._scans: dict[str, RepositoryScanResult] = _scans_store

    def get_parser_for_language(self, language: SupportedLanguage) -> BaseParser | None:
        """Find a compatible parser for the language."""
        for parser in self.parsers:
            if parser.can_parse(language):
                return parser
        return None

    def execute_scan(
        self,
        repo_path: Path | str,
        repo_name: str | None = None,
    ) -> RepositoryScanResult:
        """Run a full, deterministic scan over a local repository or directory."""
        path = Path(repo_path).resolve()
        if not path.exists():
            raise RepositoryNotFoundError(f"Target repository not found: {path}")

        scan_id = str(uuid4())
        name = repo_name or path.name
        started_at = datetime.now(UTC)
        start_time = time.perf_counter()

        logger.info("Initiating scan %s for repo: %s", scan_id, path)

        # 1. Discover files & manifest
        discovery = self.discoverer.discover_repository(path)
        discovered_files = discovery.source_files
        total_loc = discovery.total_source_loc

        # 2. Git metadata
        branch = GitService.get_current_branch(path)
        commit = GitService.get_head_commit(path)

        manifest = ManifestBuilder.build(
            repo_name=name,
            root_path=path,
            discovery=discovery,
            timestamp=started_at,
        )

        repo_meta = RepositoryMetadata(
            name=name,
            path=str(path),
            branch=branch,
            commit_hash=commit,
            total_files=discovery.total_files_inspected,
            scannable_files=len(discovered_files),
            total_loc=total_loc,
        )

        scan_record = RepositoryScanResult(
            scan_id=scan_id,
            repository=repo_meta,
            status=ScanStatus.PARSING,
            manifest=manifest,
            findings=[],
            score=None,
            started_at=started_at,
            analyzers_executed=[a.analyzer_id for a in self.registry.get_all()],
            errors=[],
        )
        self._scans[scan_id] = scan_record

        # 3. Parse source files
        parsed_files: list[ParsedFile] = []
        errors: list[str] = []

        for df in discovered_files:
            parser = self.get_parser_for_language(df.language)
            if parser is None:
                # Unsupported language - fail gracefully without crashing
                continue

            parsed = parser.parse(df)
            parsed_files.append(parsed)
            if parsed.parse_errors:
                errors.extend(parsed.parse_errors)

        # 4. Assemble context & run analyzers
        scan_record.status = ScanStatus.ANALYZING
        context = AnalysisContext(
            repo_path=path,
            parsed_files=parsed_files,
            total_loc=total_loc,
            scanned_file_count=len(parsed_files),
        )

        findings = self.registry.run_all(context)
        scan_record.findings = findings

        # 5. Score findings
        scan_record.status = ScanStatus.SCORING
        score_result = self.scoring.calculate_score(
            findings=findings,
            total_loc=total_loc,
            analyzed_files=len(parsed_files),
            skipped_files=len(discovered_files) - len(parsed_files),
        )
        scan_record.score = score_result

        # 6. Finalize
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        scan_record.completed_at = datetime.now(UTC)
        scan_record.duration_ms = round(duration_ms, 2)
        scan_record.errors = errors
        scan_record.status = ScanStatus.COMPLETED

        self._scans[scan_id] = scan_record
        logger.info(
            "Scan %s completed in %.2f ms. Score: %d (%s), Findings: %d",
            scan_id,
            duration_ms,
            score_result.total_score,
            score_result.tier.value,
            len(findings),
        )
        return scan_record

    def get_scan(self, scan_id: str) -> RepositoryScanResult | None:
        """Retrieve a stored scan result by its ID."""
        return self._scans.get(scan_id)

    def list_scans(self) -> list[RepositoryScanResult]:
        """List all completed scans ordered by most recent first."""
        return sorted(self._scans.values(), key=lambda s: s.started_at, reverse=True)


scan_service = ScanService()
