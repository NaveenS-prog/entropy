"""Integration test for Phase 12 PR Base vs Head Scan Comparison on a real Git repository."""

import os
import subprocess
from pathlib import Path

import pytest

from app.github.models import PRAnalysisStatus
from app.github.service import github_workflow_service
from app.persistence.database import scan_db


@pytest.fixture
def sample_git_repo(tmp_path: Path):
    """Create a temporary real Git repository with Base and Head commits."""
    repo_dir = tmp_path / "test_pr_repo"
    repo_dir.mkdir(parents=True)

    env = os.environ.copy()
    env["GIT_CONFIG_NOSYSTEM"] = "1"

    # 1. Initialize Git Repo
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True, env=env)
    subprocess.run(["git", "config", "user.name", "Test Engineer"], cwd=str(repo_dir), check=True, capture_output=True, env=env)
    subprocess.run(["git", "config", "user.email", "test@entropy.local"], cwd=str(repo_dir), check=True, capture_output=True, env=env)

    # 2. Base Commit: Contains Error Handling Debt (Empty catch block)
    service_file = repo_dir / "service.py"
    service_file.write_text(
        "def fetch():\n"
        "    try:\n"
        "        risky()\n"
        "    except Exception:\n"
        "        pass\n"
    )
    subprocess.run(["git", "add", "service.py"], cwd=str(repo_dir), check=True, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-m", "Base commit with empty catch"], cwd=str(repo_dir), check=True, capture_output=True, env=env)

    base_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo_dir), capture_output=True, text=True, check=True, env=env).stdout.strip()

    # 3. Head Commit: Resolves error handling debt, but introduces a hardcoded secret in auth.py
    service_file.write_text(
        "import logging\n\n"
        "logger = logging.getLogger(__name__)\n\n"
        "def fetch():\n"
        "    try:\n"
        "        risky()\n"
        "    except Exception as exc:\n"
        "        logger.error('Failed to fetch: %s', exc)\n"
        "        raise\n"
    )

    auth_file = repo_dir / "auth.py"
    auth_file.write_text(
        "# Static secret\n"
        "JWT_SECRET = 'super_secret_production_key_12345'\n"
    )

    subprocess.run(["git", "add", "service.py", "auth.py"], cwd=str(repo_dir), check=True, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-m", "Head commit resolving error but adding secret"], cwd=str(repo_dir), check=True, capture_output=True, env=env)

    head_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo_dir), capture_output=True, text=True, check=True, env=env).stdout.strip()

    return {
        "repo_dir": repo_dir,
        "base_sha": base_sha,
        "head_sha": head_sha,
    }


def test_real_pr_base_vs_head_comparison(sample_git_repo):
    """Test full end-to-end PR analysis on real Git repository commits."""
    repo_dir = sample_git_repo["repo_dir"]
    base_sha = sample_git_repo["base_sha"]
    head_sha = sample_git_repo["head_sha"]

    record = github_workflow_service.analyze_pull_request(
        owner="entropy-test",
        repo="ecommerce-app",
        pr_number=42,
        base_sha=base_sha,
        head_sha=head_sha,
        base_branch="main",
        head_branch="feature/auth-remediation",
        source_repo_path=str(repo_dir),
        force_reanalyze=True,
    )

    assert record.status == PRAnalysisStatus.COMPLETED
    assert record.pr_number == 42
    assert record.base_sha == base_sha
    assert record.head_sha == head_sha

    # Verify finding lifecycle
    assert record.resolved_findings_count >= 1, "Expected the empty catch block in service.py to be resolved"
    assert record.new_findings_count >= 1, "Expected the newly introduced secret in auth.py to be detected as new"

    # Verify score movement
    assert record.base_score is not None
    assert record.head_score is not None
    assert record.score_delta == record.head_score - record.base_score

    # Verify comparison persistence
    comparison = scan_db.get_pr_comparison(record.id)
    assert comparison is not None
    assert comparison.summary.resolved_findings_count == record.resolved_findings_count
    assert comparison.summary.new_findings_count == record.new_findings_count
    assert comparison.summary.score_delta == record.score_delta

    # Verify finding details in comparison
    resolved_rules = {f.rule_id for f in comparison.resolved_findings}
    assert any(r in resolved_rules for r in ("ENT-ERR-001", "ENT-ERR-002", "ENT-ERR-003"))

    new_rules = {f.rule_id for f in comparison.new_findings}
    assert "ENT-LOG-002" in new_rules
