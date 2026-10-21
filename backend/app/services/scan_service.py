"""Scan orchestration service coordinating discovery, parsing, analysis, and scoring."""

from pathlib import Path

from app.analyzers.registry import AnalyzerRegistry, default_registry
from app.models.domain.enums import SupportedLanguage
from app.models.domain.scan import RepositoryScanResult
from app.parser.base import BaseParser
from app.parser.jsts.parser import JSTSParser
from app.parser.python_ast import PythonAstParser
from app.persistence.database import scan_db
from app.repository.discoverer import RepositoryDiscoverer
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
        self.parsers: list[BaseParser] = [PythonAstParser(), JSTSParser()]
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
        include_tests: bool = False,
    ) -> RepositoryScanResult:
        """Run a full, deterministic scan delegating to the production scanner and scoring engine."""
        from app.scoring.service import scoring_service
        from app.services.analysis_service import analysis_service
        from app.services.repository_service import repository_service

        path_str = str(repo_path)
        scan = repository_service.execute_scan(
            repo_path=path_str,
            repo_name=repo_name,
            check_allowed_roots=False,
            include_tests=include_tests,
        )
        analysis_service.analyze_scan(scan.scan_id)
        scoring_service.calculate_scan_score(scan.scan_id)
        final_scan = repository_service.get_scan(scan.scan_id) or scan
        self._scans[final_scan.scan_id] = final_scan
        return final_scan

    def get_scan(self, scan_id: str) -> RepositoryScanResult | None:
        """Retrieve a stored scan result by its ID."""
        scan = self._scans.get(scan_id)
        if not scan:
            scan = scan_db.get_scan(scan_id)
            if scan:
                self._scans[scan_id] = scan
        return scan

    def list_scans(self) -> list[RepositoryScanResult]:
        """List all completed scans ordered by most recent first."""
        return sorted(self._scans.values(), key=lambda s: s.started_at, reverse=True)


scan_service = ScanService()
