"""SQLite-backed persistent scan snapshot database and query service."""

from __future__ import annotations

import contextlib
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from app.comparison.models import ScanComparisonResult
from app.core.config import settings
from app.github.models import PRAnalysisRecord, PRAnalysisStatus
from app.models.domain.enums import DebtScoreTier, ScanStatus
from app.models.domain.scan import RepositoryScanResult
from app.persistence.models import ScanSnapshot
from app.policy.models import PolicyEvaluation

logger = logging.getLogger("entropy.persistence")


class ScanDatabase:
    """Manages persistent SQLite storage of repository scan artifacts and snapshots."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path is not None:
            self.db_path = Path(db_path)
        else:
            storage_dir = settings.SCAN_STORAGE_DIR
            storage_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = storage_dir / "entropy_scans.db"

        self._init_db()

    @contextlib.contextmanager
    def _get_connection(self):
        """Context manager providing a configured SQLite connection."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=15.0,
            check_same_thread=False,
            isolation_level=None,  # Autocommit mode
        )
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create database tables and performance indexes if not present."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_snapshots (
                    scan_id TEXT PRIMARY KEY,
                    repository_id TEXT NOT NULL,
                    repo_name TEXT NOT NULL,
                    repo_path TEXT NOT NULL,
                    branch TEXT,
                    commit_hash TEXT,
                    status TEXT NOT NULL,
                    entropy_score INTEGER,
                    score_band TEXT,
                    total_files INTEGER DEFAULT 0,
                    analyzed_files INTEGER DEFAULT 0,
                    total_loc INTEGER DEFAULT 0,
                    finding_count INTEGER DEFAULT 0,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    duration_ms REAL,
                    analyzer_version TEXT DEFAULT '0.1.0',
                    scoring_version TEXT DEFAULT '1.0.0',
                    raw_json TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_snapshots_repo_started
                ON scan_snapshots (repository_id, started_at DESC);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_snapshots_status
                ON scan_snapshots (status);
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pr_analyses (
                    id TEXT PRIMARY KEY,
                    repository_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    repo TEXT NOT NULL,
                    pr_number INTEGER NOT NULL,
                    base_sha TEXT NOT NULL,
                    head_sha TEXT NOT NULL,
                    base_branch TEXT,
                    head_branch TEXT,
                    base_scan_id TEXT,
                    head_scan_id TEXT,
                    base_score INTEGER,
                    head_score INTEGER,
                    score_delta INTEGER,
                    new_findings_count INTEGER DEFAULT 0,
                    resolved_findings_count INTEGER DEFAULT 0,
                    persistent_findings_count INTEGER DEFAULT 0,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    check_run_id INTEGER,
                    comment_id INTEGER,
                    is_current_head INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    raw_comparison_json TEXT
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_pr_analyses_target
                ON pr_analyses (owner, repo, pr_number);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_pr_analyses_idempotency
                ON pr_analyses (owner, repo, pr_number, base_sha, head_sha);
                """
            )

            # Phase 13: Policy columns migration
            for col, col_type in [("policy_status", "TEXT"), ("policy_evaluation_json", "TEXT")]:
                try:
                    conn.execute(f"ALTER TABLE pr_analyses ADD COLUMN {col} {col_type};")
                except sqlite3.OperationalError:
                    pass

            logger.info("Initialized scan database at %s", self.db_path)

    def save_scan(self, scan: RepositoryScanResult) -> None:
        """Persist or update a complete scan result and its lightweight snapshot."""
        repo_id = scan.repository.repository_id or scan.repository.derive_repository_id(
            scan.repository.path, scan.repository.remote_url
        )
        score_val = scan.score.total_score if scan.score else None
        band_val = scan.score.tier.value if scan.score else None
        analyzed_files = scan.score.analyzed_files if scan.score else 0

        raw_json = scan.model_dump_json()

        query = """
            INSERT INTO scan_snapshots (
                scan_id, repository_id, repo_name, repo_path, branch, commit_hash,
                status, entropy_score, score_band, total_files, analyzed_files,
                total_loc, finding_count, started_at, completed_at, duration_ms,
                analyzer_version, scoring_version, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                status = excluded.status,
                entropy_score = excluded.entropy_score,
                score_band = excluded.score_band,
                total_files = excluded.total_files,
                analyzed_files = excluded.analyzed_files,
                total_loc = excluded.total_loc,
                finding_count = excluded.finding_count,
                completed_at = excluded.completed_at,
                duration_ms = excluded.duration_ms,
                raw_json = excluded.raw_json;
        """

        params = (
            scan.scan_id,
            repo_id,
            scan.repository.name,
            scan.repository.path,
            scan.repository.branch,
            scan.repository.commit_hash,
            scan.status.value,
            score_val,
            band_val,
            scan.repository.total_files,
            analyzed_files,
            scan.repository.total_loc,
            len(scan.findings),
            scan.started_at.isoformat(),
            scan.completed_at.isoformat() if scan.completed_at else None,
            scan.duration_ms,
            "0.1.0",
            "1.0.0",
            raw_json,
        )

        with self._get_connection() as conn:
            conn.execute(query, params)

        logger.debug("Persisted scan snapshot for '%s' (repo: %s)", scan.scan_id, repo_id)

    def get_scan(self, scan_id: str) -> RepositoryScanResult | None:
        """Fetch the full, verbatim RepositoryScanResult from database."""
        query = "SELECT raw_json FROM scan_snapshots WHERE scan_id = ?;"
        with self._get_connection() as conn:
            row = conn.execute(query, (scan_id,)).fetchone()
            if row:
                return RepositoryScanResult.model_validate_json(row["raw_json"])
        return None

    def get_snapshot(self, scan_id: str) -> ScanSnapshot | None:
        """Fetch a lightweight snapshot without loading full findings or raw_json."""
        query = """
            SELECT scan_id, repository_id, repo_name, repo_path, branch, commit_hash,
                   status, entropy_score, score_band, total_files, analyzed_files,
                   total_loc, finding_count, analyzer_version, scoring_version,
                   started_at, completed_at, duration_ms
            FROM scan_snapshots WHERE scan_id = ?;
        """
        with self._get_connection() as conn:
            row = conn.execute(query, (scan_id,)).fetchone()
            if row:
                return self._row_to_snapshot(row)
        return None

    def list_scans_for_repository(
        self,
        repository_id: str,
        limit: int = 20,
        offset: int = 0,
        status: str | None = None,
        branch: str | None = None,
    ) -> tuple[list[ScanSnapshot], int]:
        """List scan snapshots for a repository ordered newest first with pagination."""
        where_clauses = ["repository_id = ?"]
        params: list[Any] = [repository_id]

        if status:
            where_clauses.append("status = ?")
            params.append(status)
        if branch:
            where_clauses.append("branch = ?")
            params.append(branch)

        where_sql = " AND ".join(where_clauses)

        with self._get_connection() as conn:
            # 1. Total count
            count_query = f"SELECT COUNT(*) AS total FROM scan_snapshots WHERE {where_sql};"
            total = conn.execute(count_query, params).fetchone()["total"]

            # 2. Paginated rows
            data_query = f"""
                SELECT scan_id, repository_id, repo_name, repo_path, branch, commit_hash,
                       status, entropy_score, score_band, total_files, analyzed_files,
                       total_loc, finding_count, analyzer_version, scoring_version,
                       started_at, completed_at, duration_ms
                FROM scan_snapshots
                WHERE {where_sql}
                ORDER BY started_at DESC
                LIMIT ? OFFSET ?;
            """
            rows = conn.execute(data_query, params + [limit, offset]).fetchall()
            items = [self._row_to_snapshot(r) for r in rows]

        return items, total

    def list_all_scans(self, limit: int = 100) -> list[ScanSnapshot]:
        """List global recent scan snapshots ordered newest first."""
        query = """
            SELECT scan_id, repository_id, repo_name, repo_path, branch, commit_hash,
                   status, entropy_score, score_band, total_files, analyzed_files,
                   total_loc, finding_count, analyzer_version, scoring_version,
                   started_at, completed_at, duration_ms
            FROM scan_snapshots
            ORDER BY started_at DESC
            LIMIT ?;
        """
        with self._get_connection() as conn:
            rows = conn.execute(query, (limit,)).fetchall()
            return [self._row_to_snapshot(r) for r in rows]

    def get_trend(self, repository_id: str) -> list[ScanSnapshot]:
        """Fetch completed scan progression ordered chronologically (oldest to newest)."""
        query = """
            SELECT scan_id, repository_id, repo_name, repo_path, branch, commit_hash,
                   status, entropy_score, score_band, total_files, analyzed_files,
                   total_loc, finding_count, analyzer_version, scoring_version,
                   started_at, completed_at, duration_ms
            FROM scan_snapshots
            WHERE repository_id = ? AND status = 'completed'
            ORDER BY started_at ASC;
        """
        with self._get_connection() as conn:
            rows = conn.execute(query, (repository_id,)).fetchall()
            return [self._row_to_snapshot(r) for r in rows]

    def get_repository_scan_history(self, repository_id: str) -> list[RepositoryScanResult]:
        """Fetch all full completed scan results for a repository ordered chronologically."""
        query = """
            SELECT raw_json
            FROM scan_snapshots
            WHERE repository_id = ? AND status = 'completed'
            ORDER BY started_at ASC;
        """
        with self._get_connection() as conn:
            rows = conn.execute(query, (repository_id,)).fetchall()
            results = []
            for r in rows:
                with contextlib.suppress(Exception):
                    results.append(RepositoryScanResult.model_validate_json(r["raw_json"]))
            return results

    def _row_to_snapshot(self, row: sqlite3.Row) -> ScanSnapshot:
        """Convert a sqlite3.Row into a typed ScanSnapshot."""
        band = None
        if row["score_band"]:
            with contextlib.suppress(ValueError):
                band = DebtScoreTier(row["score_band"])

        return ScanSnapshot(
            scan_id=row["scan_id"],
            repository_id=row["repository_id"],
            repo_name=row["repo_name"],
            repo_path=row["repo_path"],
            branch=row["branch"],
            commit_sha=row["commit_hash"],
            status=ScanStatus(row["status"]),
            entropy_score=row["entropy_score"],
            score_band=band,
            total_files=row["total_files"],
            analyzed_files=row["analyzed_files"],
            total_loc=row["total_loc"],
            finding_count=row["finding_count"],
            analyzer_version=row["analyzer_version"] or "0.1.0",
            scoring_version=row["scoring_version"] or "1.0.0",
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=datetime.fromisoformat(row["completed_at"])
            if row["completed_at"]
            else None,
            duration_ms=row["duration_ms"],
        )

    def save_pr_analysis(
        self,
        record: PRAnalysisRecord,
        comparison: ScanComparisonResult | None = None,
    ) -> None:
        """Persist or update a Pull Request analysis record and comparison snapshot."""
        raw_comparison = comparison.model_dump_json() if comparison else None
        raw_policy = (
            record.policy_evaluation.model_dump_json()
            if record.policy_evaluation
            else None
        )

        query = """
            INSERT INTO pr_analyses (
                id, repository_id, owner, repo, pr_number, base_sha, head_sha,
                base_branch, head_branch, base_scan_id, head_scan_id,
                base_score, head_score, score_delta, new_findings_count,
                resolved_findings_count, persistent_findings_count,
                status, error_message, check_run_id, comment_id,
                is_current_head, created_at, updated_at, raw_comparison_json,
                policy_status, policy_evaluation_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                base_scan_id = excluded.base_scan_id,
                head_scan_id = excluded.head_scan_id,
                base_score = excluded.base_score,
                head_score = excluded.head_score,
                score_delta = excluded.score_delta,
                new_findings_count = excluded.new_findings_count,
                resolved_findings_count = excluded.resolved_findings_count,
                persistent_findings_count = excluded.persistent_findings_count,
                status = excluded.status,
                error_message = excluded.error_message,
                check_run_id = excluded.check_run_id,
                comment_id = excluded.comment_id,
                is_current_head = excluded.is_current_head,
                updated_at = excluded.updated_at,
                raw_comparison_json = COALESCE(excluded.raw_comparison_json, pr_analyses.raw_comparison_json),
                policy_status = excluded.policy_status,
                policy_evaluation_json = COALESCE(excluded.policy_evaluation_json, pr_analyses.policy_evaluation_json);
        """
        params = (
            record.id,
            record.repository_id,
            record.owner,
            record.repo,
            record.pr_number,
            record.base_sha,
            record.head_sha,
            record.base_branch,
            record.head_branch,
            record.base_scan_id,
            record.head_scan_id,
            record.base_score,
            record.head_score,
            record.score_delta,
            record.new_findings_count,
            record.resolved_findings_count,
            record.persistent_findings_count,
            record.status.value,
            record.error_message,
            record.check_run_id,
            record.comment_id,
            1 if record.is_current_head else 0,
            record.created_at.isoformat(),
            record.updated_at.isoformat(),
            raw_comparison,
            record.policy_status,
            raw_policy,
        )

        with self._get_connection() as conn:
            conn.execute(query, params)
        logger.debug(
            "Persisted PR analysis '%s' for PR #%d (%s/%s)",
            record.id,
            record.pr_number,
            record.owner,
            record.repo,
        )

    def get_pr_analysis(self, pr_analysis_id: str) -> PRAnalysisRecord | None:
        """Fetch a PR analysis record by its primary ID."""
        query = "SELECT * FROM pr_analyses WHERE id = ?;"
        with self._get_connection() as conn:
            row = conn.execute(query, (pr_analysis_id,)).fetchone()
            if row:
                return self._row_to_pr_record(row)
        return None

    def get_pr_analysis_by_target(
        self, owner: str, repo: str, pr_number: int, base_sha: str, head_sha: str
    ) -> PRAnalysisRecord | None:
        """Fetch exact analysis record for an idempotent (repo, pr, base_sha, head_sha) target."""
        query = """
            SELECT * FROM pr_analyses
            WHERE owner = ? AND repo = ? AND pr_number = ? AND base_sha = ? AND head_sha = ?
            ORDER BY updated_at DESC LIMIT 1;
        """
        with self._get_connection() as conn:
            row = conn.execute(query, (owner, repo, pr_number, base_sha, head_sha)).fetchone()
            if row:
                return self._row_to_pr_record(row)
        return None

    def get_latest_pr_analysis(
        self, owner: str, repo: str, pr_number: int
    ) -> PRAnalysisRecord | None:
        """Fetch the current active (is_current_head=1) or most recently updated PR analysis record."""
        query = """
            SELECT * FROM pr_analyses
            WHERE owner = ? AND repo = ? AND pr_number = ?
            ORDER BY is_current_head DESC, updated_at DESC LIMIT 1;
        """
        with self._get_connection() as conn:
            row = conn.execute(query, (owner, repo, pr_number)).fetchone()
            if row:
                return self._row_to_pr_record(row)
        return None

    def list_pr_analyses_for_repo(
        self, owner: str, repo: str, limit: int = 20
    ) -> list[PRAnalysisRecord]:
        """List recent PR analysis records for a repository."""
        query = """
            SELECT * FROM pr_analyses
            WHERE owner = ? AND repo = ?
            ORDER BY updated_at DESC LIMIT ?;
        """
        with self._get_connection() as conn:
            rows = conn.execute(query, (owner, repo, limit)).fetchall()
            return [self._row_to_pr_record(r) for r in rows]

    def get_pr_comparison(self, pr_analysis_id: str) -> ScanComparisonResult | None:
        """Retrieve the persisted verbatim ScanComparisonResult for a PR analysis."""
        query = "SELECT raw_comparison_json FROM pr_analyses WHERE id = ?;"
        with self._get_connection() as conn:
            row = conn.execute(query, (pr_analysis_id,)).fetchone()
            if row and row["raw_comparison_json"]:
                with contextlib.suppress(Exception):
                    return ScanComparisonResult.model_validate_json(row["raw_comparison_json"])
        return None

    def update_pr_current_head(
        self, owner: str, repo: str, pr_number: int, current_id: str
    ) -> None:
        """Ensure only current_id is marked as is_current_head=1 for this PR."""
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE pr_analyses SET is_current_head = 0 WHERE owner = ? AND repo = ? AND pr_number = ?;",
                (owner, repo, pr_number),
            )
            conn.execute(
                "UPDATE pr_analyses SET is_current_head = 1 WHERE id = ?;",
                (current_id,),
            )

    def get_pr_policy(self, pr_analysis_id: str) -> PolicyEvaluation | None:
        """Retrieve the persisted verbatim PolicyEvaluation for a PR analysis."""
        query = "SELECT policy_evaluation_json FROM pr_analyses WHERE id = ?;"
        with self._get_connection() as conn:
            row = conn.execute(query, (pr_analysis_id,)).fetchone()
            if row and "policy_evaluation_json" in row.keys() and row["policy_evaluation_json"]:
                with contextlib.suppress(Exception):
                    return PolicyEvaluation.model_validate_json(row["policy_evaluation_json"])
        return None

    def _row_to_pr_record(self, row: sqlite3.Row) -> PRAnalysisRecord:
        """Convert a sqlite3.Row into a typed PRAnalysisRecord."""
        policy_eval = None
        if "policy_evaluation_json" in row.keys() and row["policy_evaluation_json"]:
            with contextlib.suppress(Exception):
                policy_eval = PolicyEvaluation.model_validate_json(row["policy_evaluation_json"])

        return PRAnalysisRecord(
            id=row["id"],
            repository_id=row["repository_id"],
            owner=row["owner"],
            repo=row["repo"],
            pr_number=row["pr_number"],
            base_sha=row["base_sha"],
            head_sha=row["head_sha"],
            base_branch=row["base_branch"],
            head_branch=row["head_branch"],
            base_scan_id=row["base_scan_id"],
            head_scan_id=row["head_scan_id"],
            base_score=row["base_score"],
            head_score=row["head_score"],
            score_delta=row["score_delta"],
            new_findings_count=row["new_findings_count"] or 0,
            resolved_findings_count=row["resolved_findings_count"] or 0,
            persistent_findings_count=row["persistent_findings_count"] or 0,
            status=PRAnalysisStatus(row["status"]),
            error_message=row["error_message"],
            check_run_id=row["check_run_id"],
            comment_id=row["comment_id"],
            policy_status=row["policy_status"] if "policy_status" in row.keys() else None,
            policy_evaluation=policy_eval,
            is_current_head=bool(row["is_current_head"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )


scan_db = ScanDatabase()
