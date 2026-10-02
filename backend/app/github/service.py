"""GitHub Pull Request workflow and analysis orchestration service.

Coordinates:
1. Webhook processing and idempotency checks.
2. Isolated source acquisition at base and head SHAs.
3. Deterministic Entropy ingestion and scanning (Base & Head).
4. Reuse of Phase 10 comparison engine for debt delta computation.
5. Persistent PR analysis state tracking and race-condition resolution.
6. GitHub Check Run and Pull Request comment reporting with safe failure handling.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from app.comparison.models import ScanComparisonResult
from app.core.errors import RepositoryNotFoundError
from app.github.client import GitHubClient
from app.github.formatter import build_check_run_output, build_pr_comment_markdown
from app.github.models import PRAnalysisRecord, PRAnalysisStatus
from app.github.source import temporary_checkout, validate_commit_sha
from app.policy.models import PolicyEvaluation, PolicyStatus

if TYPE_CHECKING:
    from app.comparison.service import ComparisonService
    from app.persistence.database import ScanDatabase
    from app.policy.service import PolicyService
    from app.scoring.service import ScoringService
    from app.services.analysis_service import AnalysisService
    from app.services.repository_service import RepositoryService

logger = logging.getLogger("entropy.github.service")


class GitHubWorkflowService:
    """Orchestrates deterministic Pull Request debt analysis and GitHub integration."""

    def __init__(
        self,
        db: ScanDatabase | None = None,
        client: GitHubClient | None = None,
        repo_svc: RepositoryService | None = None,
        analy_svc: AnalysisService | None = None,
        score_svc: ScoringService | None = None,
        comp_svc: ComparisonService | None = None,
        policy_svc: PolicyService | None = None,
    ) -> None:
        self._db = db
        self._client = client
        self._repo_svc = repo_svc
        self._analy_svc = analy_svc
        self._score_svc = score_svc
        self._comp_svc = comp_svc
        self._policy_svc = policy_svc

    @property
    def policy_svc(self) -> PolicyService:
        if self._policy_svc is None:
            from app.policy.service import policy_service

            self._policy_svc = policy_service
        return self._policy_svc

    @property
    def db(self) -> ScanDatabase:
        if self._db is None:
            from app.persistence.database import scan_db

            self._db = scan_db
        return self._db

    @property
    def client(self) -> GitHubClient:
        if self._client is None:
            self._client = GitHubClient()
        return self._client

    @property
    def repo_svc(self) -> RepositoryService:
        if self._repo_svc is None:
            from app.services.repository_service import repository_service

            self._repo_svc = repository_service
        return self._repo_svc

    @property
    def analy_svc(self) -> AnalysisService:
        if self._analy_svc is None:
            from app.services.analysis_service import analysis_service

            self._analy_svc = analysis_service
        return self._analy_svc

    @property
    def score_svc(self) -> ScoringService:
        if self._score_svc is None:
            from app.scoring.service import scoring_service

            self._score_svc = scoring_service
        return self._score_svc

    @property
    def comp_svc(self) -> ComparisonService:
        if self._comp_svc is None:
            from app.comparison.service import comparison_service

            self._comp_svc = comparison_service
        return self._comp_svc

    def handle_webhook_event(
        self,
        event_name: str,
        payload: dict,
        local_repo_source_path: str | None = None,
    ) -> PRAnalysisRecord | None:
        """Process incoming verified GitHub webhook event."""
        if event_name == "ping":
            logger.info("Received GitHub ping event")
            return None

        if event_name != "pull_request":
            logger.info("Ignoring unsupported GitHub event: %s", event_name)
            return None

        action = payload.get("action")
        if action not in ("opened", "synchronize", "reopened"):
            logger.info("Ignoring pull_request action: %s", action)
            return None

        pr_data = payload.get("pull_request", {})
        repo_data = payload.get("repository", {})

        pr_number = pr_data.get("number")
        owner = repo_data.get("owner", {}).get("login") or repo_data.get("owner", {}).get("name")
        repo = repo_data.get("name")

        base_sha = pr_data.get("base", {}).get("sha")
        head_sha = pr_data.get("head", {}).get("sha")
        base_branch = pr_data.get("base", {}).get("ref")
        head_branch = pr_data.get("head", {}).get("ref")

        if not all([pr_number, owner, repo, base_sha, head_sha]):
            logger.warning("Malformed pull_request payload missing essential fields: %s", payload)
            raise ValueError("Malformed pull_request payload: missing PR number, repo, or commit SHAs")

        return self.analyze_pull_request(
            owner=owner,
            repo=repo,
            pr_number=int(pr_number),
            base_sha=base_sha,
            head_sha=head_sha,
            base_branch=base_branch,
            head_branch=head_branch,
            source_repo_path=local_repo_source_path,
        )

    def analyze_pull_request(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        base_sha: str,
        head_sha: str,
        base_branch: str | None = None,
        head_branch: str | None = None,
        source_repo_path: str | None = None,
        force_reanalyze: bool = False,
    ) -> PRAnalysisRecord:
        """Execute complete, deterministic Base vs Head scan comparison for a Pull Request."""
        valid_base_sha = validate_commit_sha(base_sha)
        valid_head_sha = validate_commit_sha(head_sha)
        repository_id = f"{owner}/{repo}"

        # 1. Idempotency Check: (owner, repo, pr_number, base_sha, head_sha)
        existing = self.db.get_pr_analysis_by_target(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            base_sha=valid_base_sha,
            head_sha=valid_head_sha,
        )
        if existing and not force_reanalyze:
            if existing.status == PRAnalysisStatus.COMPLETED:
                logger.info(
                    "Idempotency hit: PR #%d (%s/%s) for Base %s -> Head %s already analyzed",
                    pr_number,
                    owner,
                    repo,
                    valid_base_sha[:8],
                    valid_head_sha[:8],
                )
                return existing

        analysis_id = existing.id if existing else str(uuid4())
        now = datetime.now(UTC)

        # 2. Record initial running state
        record = PRAnalysisRecord(
            id=analysis_id,
            repository_id=repository_id,
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            base_sha=valid_base_sha,
            head_sha=valid_head_sha,
            base_branch=base_branch,
            head_branch=head_branch,
            status=PRAnalysisStatus.RUNNING,
            created_at=existing.created_at if existing else now,
            updated_at=now,
            is_current_head=True,
        )
        self.db.save_pr_analysis(record)

        # 3. Create initial Check Run on GitHub (if credentials available)
        check_run_id = None
        try:
            check_run_id = self.client.create_check_run(
                owner=owner,
                repo=repo,
                name="Entropy Architectural & Security Debt",
                head_sha=valid_head_sha,
                status="in_progress",
            )
            record.check_run_id = check_run_id
        except Exception as exc:
            logger.warning("Could not create initial GitHub Check Run: %s", exc)

        # 4. Resolve source repository path
        resolved_repo_source = (
            Path(source_repo_path).resolve()
            if source_repo_path
            else Path.cwd()
        )
        if not resolved_repo_source.exists():
            error_msg = f"Source repository directory not found: {resolved_repo_source}"
            record.status = PRAnalysisStatus.FAILED
            record.error_message = error_msg
            record.updated_at = datetime.now(UTC)
            self.db.save_pr_analysis(record)
            if check_run_id:
                with contextlib.suppress(Exception):
                    self.client.update_check_run(
                        owner=owner,
                        repo=repo,
                        check_run_id=check_run_id,
                        status="completed",
                        conclusion="failure",
                        output={"title": "Entropy Analysis Failed", "summary": error_msg},
                    )
            raise RepositoryNotFoundError(error_msg)

        # 5. Execute Base & Head Scanning and Comparison
        try:
            # Step A: Checkout & Scan Base SHA
            with temporary_checkout(resolved_repo_source, valid_base_sha) as base_dir:
                base_scan = self.repo_svc.execute_scan(
                    repo_path=str(base_dir),
                    repo_name=f"{owner}/{repo}-base-{valid_base_sha[:8]}",
                )
                self.analy_svc.analyze_scan(base_scan.scan_id)
                self.score_svc.calculate_scan_score(base_scan.scan_id)
                # Reload refreshed base scan
                base_scan = self.repo_svc.get_scan(base_scan.scan_id) or base_scan

            # Step B: Checkout & Scan Head SHA
            with temporary_checkout(resolved_repo_source, valid_head_sha) as head_dir:
                head_scan = self.repo_svc.execute_scan(
                    repo_path=str(head_dir),
                    repo_name=f"{owner}/{repo}-head-{valid_head_sha[:8]}",
                )
                self.analy_svc.analyze_scan(head_scan.scan_id)
                self.score_svc.calculate_scan_score(head_scan.scan_id)
                # Reload refreshed head scan
                head_scan = self.repo_svc.get_scan(head_scan.scan_id) or head_scan

            # Step C: Deterministic Scan Comparison using Phase 10 Comparison Service
            comparison: ScanComparisonResult = self.comp_svc.compare_scans(
                current_scan=head_scan,
                previous_scan=base_scan,
            )

            # Step C2: Deterministic Policy Evaluation using Phase 13 Policy Service
            policy_eval: PolicyEvaluation | None = None
            try:
                policy_eval = self.policy_svc.evaluate_comparison_obj(comparison)
                record.policy_status = policy_eval.status.value
                record.policy_evaluation = policy_eval
            except Exception as exc:
                logger.warning("Policy evaluation error during PR workflow: %s", exc)

            # Step D: Update PR Record with Results
            record.base_scan_id = base_scan.scan_id
            record.head_scan_id = head_scan.scan_id
            record.base_score = comparison.summary.previous_score
            record.head_score = comparison.summary.current_score
            record.score_delta = comparison.summary.score_delta
            record.new_findings_count = comparison.summary.new_findings_count
            record.resolved_findings_count = comparison.summary.resolved_findings_count
            record.persistent_findings_count = comparison.summary.persistent_findings_count
            record.status = PRAnalysisStatus.COMPLETED
            record.updated_at = datetime.now(UTC)

            # Step E: Concurrency & Race-Condition Resolution
            # If another analysis for this PR completed later for a different head SHA,
            # this older record must not usurp is_current_head.
            latest_active = self.db.get_latest_pr_analysis(owner, repo, pr_number)
            if latest_active and latest_active.id != record.id:
                if latest_active.updated_at > record.created_at and latest_active.head_sha != record.head_sha:
                    logger.info(
                        "Newer analysis %s already active for PR #%d; marking %s as non-current head",
                        latest_active.id,
                        pr_number,
                        record.id,
                    )
                    record.is_current_head = False
                else:
                    self.db.update_pr_current_head(owner, repo, pr_number, record.id)
                    record.is_current_head = True
            else:
                self.db.update_pr_current_head(owner, repo, pr_number, record.id)
                record.is_current_head = True

            # Persist finalized analysis and comparison snapshot
            self.db.save_pr_analysis(record, comparison=comparison)

            # Step F: Report to GitHub (Check Run and PR Comment)
            # Safe failure handling: failure to communicate with GitHub does NOT fail the analysis!
            dashboard_url = f"http://localhost:3000?tab=pr&repo={owner}/{repo}&pr={pr_number}"
            if check_run_id:
                try:
                    if policy_eval:
                        if policy_eval.status == PolicyStatus.PASS:
                            conclusion = "success"
                        elif policy_eval.status == PolicyStatus.WARN:
                            conclusion = "neutral"
                        else:
                            conclusion = "failure"
                    else:
                        conclusion = "neutral"

                    check_run_output = build_check_run_output(
                        comparison=comparison,
                        pr_number=pr_number,
                        dashboard_url=dashboard_url,
                        policy_evaluation=policy_eval,
                    )
                    self.client.update_check_run(
                        owner=owner,
                        repo=repo,
                        check_run_id=check_run_id,
                        status="completed",
                        conclusion=conclusion,
                        output=check_run_output,
                    )
                except Exception as exc:
                    logger.warning("Failed to update GitHub Check Run: %s", exc)

            try:
                existing_comment_id = self.client.find_existing_comment(owner, repo, pr_number)
                comment_body = build_pr_comment_markdown(
                    comparison=comparison,
                    pr_number=pr_number,
                    dashboard_url=dashboard_url,
                    policy_evaluation=policy_eval,
                )
                comment_id = self.client.create_or_update_comment(
                    owner=owner,
                    repo=repo,
                    pr_number=pr_number,
                    body=comment_body,
                    comment_id=existing_comment_id,
                )
                if comment_id:
                    record.comment_id = comment_id
                    self.db.save_pr_analysis(record, comparison=comparison)
            except Exception as exc:
                logger.warning("Failed to post/update PR comment: %s", exc)

            logger.info(
                "PR #%d analysis completed: Base Score=%s, Head Score=%s, Delta=%s, New=%d, Resolved=%d",
                pr_number,
                record.base_score,
                record.head_score,
                record.score_delta,
                record.new_findings_count,
                record.resolved_findings_count,
            )
            return record

        except Exception as exc:
            logger.exception("PR analysis failed for PR #%d (%s/%s): %s", pr_number, owner, repo, exc)
            record.status = PRAnalysisStatus.FAILED
            record.error_message = str(exc)
            record.updated_at = datetime.now(UTC)
            self.db.save_pr_analysis(record)

            if check_run_id:
                with contextlib.suppress(Exception):
                    self.client.update_check_run(
                        owner=owner,
                        repo=repo,
                        check_run_id=check_run_id,
                        status="completed",
                        conclusion="failure",
                        output={
                            "title": "Entropy Analysis Failed",
                            "summary": f"Entropy encountered an unexpected error: {exc}",
                        },
                    )
            raise


# Default singleton instance
github_workflow_service = GitHubWorkflowService()
