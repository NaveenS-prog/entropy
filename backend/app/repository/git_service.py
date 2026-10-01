"""Git metadata extraction service using resilient subprocess calls."""

import subprocess
from pathlib import Path


class GitService:
    """Provides non-destructive metadata queries for local git repositories."""

    @staticmethod
    def get_head_commit(repo_path: Path | str) -> str | None:
        """Retrieve the current HEAD commit hash."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    @staticmethod
    def get_current_branch(repo_path: Path | str) -> str | None:
        """Retrieve the current active git branch name."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
