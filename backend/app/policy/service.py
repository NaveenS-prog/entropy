"""Policy service orchestrating policy retrieval, evaluation, and persistence."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.comparison.models import ScanComparisonResult
from app.models.domain.scan import RepositoryScanResult
from app.policy.evaluator import PolicyEvaluator
from app.policy.models import PolicyConfig, PolicyEvaluation
from app.policy.parser import (
    get_default_policy,
    parse_policy_dict,
    parse_policy_file,
    parse_policy_yaml,
)

if TYPE_CHECKING:
    from app.comparison.service import ComparisonService
    from app.persistence.database import ScanDatabase
    from app.services.repository_service import RepositoryService

logger = logging.getLogger("entropy.policy")


class PolicyService:
    """Service providing policy evaluation against scans, comparisons, and PR workflows."""

    def __init__(
        self,
        db: ScanDatabase | None = None,
        comp_svc: ComparisonService | None = None,
        repo_svc: RepositoryService | None = None,
    ) -> None:
        self._db = db
        self._comp_svc = comp_svc
        self._repo_svc = repo_svc

    @property
    def db(self) -> ScanDatabase:
        if self._db is None:
            from app.persistence.database import scan_db

            self._db = scan_db
        return self._db

    @property
    def comp_svc(self) -> ComparisonService:
        if self._comp_svc is None:
            from app.comparison.service import comparison_service

            self._comp_svc = comparison_service
        return self._comp_svc

    @property
    def repo_svc(self) -> RepositoryService:
        if self._repo_svc is None:
            from app.services.repository_service import repository_service

            self._repo_svc = repository_service
        return self._repo_svc

    def get_default_policy(self) -> PolicyConfig:
        """Retrieve the default system policy."""
        return get_default_policy()

    def resolve_policy(
        self,
        policy_source: PolicyConfig | dict[str, Any] | str | Path | None = None,
    ) -> PolicyConfig:
        """Resolve policy configuration from model, dict, file path, or YAML string."""
        if policy_source is None:
            return self.get_default_policy()
        if isinstance(policy_source, PolicyConfig):
            return policy_source
        if isinstance(policy_source, dict):
            return parse_policy_dict(policy_source)
        if isinstance(policy_source, Path) or (
            isinstance(policy_source, str) and Path(policy_source).is_file()
        ):
            return parse_policy_file(policy_source)
        if isinstance(policy_source, str):
            return parse_policy_yaml(policy_source)
        raise ValueError(f"Unsupported policy source type: {type(policy_source)}")

    def evaluate_scan_obj(
        self,
        scan: RepositoryScanResult,
        policy: PolicyConfig | None = None,
    ) -> PolicyEvaluation:
        """Evaluate a concrete RepositoryScanResult against a policy."""
        cfg = policy or self.get_default_policy()
        return PolicyEvaluator.evaluate(policy=cfg, current_scan=scan)

    def evaluate_comparison_obj(
        self,
        comparison: ScanComparisonResult,
        policy: PolicyConfig | None = None,
    ) -> PolicyEvaluation:
        """Evaluate a concrete ScanComparisonResult against a policy."""
        cfg = policy or self.get_default_policy()
        return PolicyEvaluator.evaluate(policy=cfg, comparison=comparison)

    def evaluate_scan(
        self,
        scan_id: str,
        policy: PolicyConfig | None = None,
    ) -> PolicyEvaluation:
        """Load a scan by ID and evaluate it against a policy."""
        scan = self.repo_svc.get_scan(scan_id)
        if not scan:
            raise ValueError(f"Scan '{scan_id}' not found.")
        return self.evaluate_scan_obj(scan, policy=policy)

    def evaluate_comparison(
        self,
        current_scan_id: str,
        previous_scan_id: str,
        policy: PolicyConfig | None = None,
    ) -> PolicyEvaluation:
        """Load two scans, compare them, and evaluate against a policy."""
        current_scan = self.repo_svc.get_scan(current_scan_id)
        if not current_scan:
            raise ValueError(f"Current scan '{current_scan_id}' not found.")
        previous_scan = self.repo_svc.get_scan(previous_scan_id)
        if not previous_scan:
            raise ValueError(f"Previous scan '{previous_scan_id}' not found.")

        comparison = self.comp_svc.compare_scans(
            current_scan=current_scan, previous_scan=previous_scan
        )
        return self.evaluate_comparison_obj(comparison, policy=policy)

    def evaluate_pr_analysis(
        self,
        analysis_id: str,
        policy: PolicyConfig | None = None,
    ) -> PolicyEvaluation:
        """Evaluate a persisted PR analysis against a policy."""
        comparison = self.db.get_pr_comparison(analysis_id)
        if not comparison:
            raise ValueError(f"PR analysis comparison for '{analysis_id}' not found.")
        return self.evaluate_comparison_obj(comparison, policy=policy)


policy_service = PolicyService()
