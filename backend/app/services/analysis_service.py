"""Analysis service coordinating Phase 2 AST context building and Phase 3 debt analyzers."""

from __future__ import annotations

import logging
from pathlib import Path

from app.analyzers.base import AnalysisContext
from app.analyzers.registry import AnalyzerRegistry, default_registry
from app.core.errors import RepositoryNotFoundError
from app.models.domain.enums import DebtCategory, Severity
from app.models.domain.finding import Finding
from app.services.repository_service import RepositoryService, repository_service

logger = logging.getLogger("entropy.services.analysis")


class AnalysisService:
    """Service orchestrating architectural debt analysis on repository scans."""

    def __init__(
        self,
        registry: AnalyzerRegistry | None = None,
        repo_service: RepositoryService | None = None,
    ) -> None:
        self.registry = registry or default_registry
        self.repo_service = repo_service or repository_service

    def analyze_scan(
        self,
        scan_id: str,
        category: DebtCategory | None = None,
        severity: Severity | None = None,
        rule_id: str | None = None,
        file_filter: str | None = None,
        force_reanalyze: bool = False,
    ) -> list[Finding]:
        """Analyze a scan by scan_id using Phase 2 AST context and Phase 3 analyzers."""
        scan = self.repo_service.get_scan(scan_id)
        if not scan:
            raise RepositoryNotFoundError(f"Scan '{scan_id}' not found")
        if not scan.manifest:
            raise RepositoryNotFoundError(f"Scan '{scan_id}' has no repository manifest")

        # Run analysis if not already cached or if forced
        if not scan.analyzers_executed or force_reanalyze:
            logger.info("Executing Phase 3 debt analyzers for scan '%s'", scan_id)
            root_path = Path(scan.repository.path)
            python_units = self.repo_service.parse_python_files(scan_id)

            context = AnalysisContext.from_python_units(
                repo_path=root_path,
                units=python_units,
                manifest=scan.manifest,
            )

            findings = self.registry.analyze(context)
            scan.findings = findings
            scan.analyzers_executed = [a.analyzer_id for a in self.registry.get_all()]
            self.repo_service.save_scan(scan)
            logger.info(
                "Scan '%s' analysis complete: %d finding(s) discovered across %d Python file(s)",
                scan_id,
                len(findings),
                len(python_units),
            )
        else:
            findings = scan.findings

        # Apply deterministic filters
        results = findings
        if category:
            results = [f for f in results if f.category == category]
        if severity:
            results = [f for f in results if f.severity == severity]
        if rule_id:
            results = [f for f in results if f.rule_id == rule_id]
        if file_filter:
            results = [f for f in results if file_filter.lower() in f.file.lower()]

        return results

    def get_finding(self, scan_id: str, finding_id: str) -> Finding | None:
        """Fetch a specific finding by ID from a scan."""
        findings = self.analyze_scan(scan_id)
        return next((f for f in findings if f.id == finding_id), None)


analysis_service = AnalysisService()
