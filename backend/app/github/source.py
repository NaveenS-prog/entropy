"""Secure repository source acquisition at specific commit SHAs.

Guarantees:
- Zero shell interpolation (no shell=True).
- Strict SHA validation using regex.
- Isolated temporary directories with guaranteed cleanup.
- Prevents path traversal and symlink attacks.
- Neutralizes repository hooks by bypassing or exporting via git-archive.
"""

from __future__ import annotations

import contextlib
import io
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from collections.abc import Iterator
from pathlib import Path

from app.core.errors import RepositorySecurityError

logger = logging.getLogger("entropy.github.source")

# Strict SHA-1 and SHA-256 hexadecimal pattern (4 to 64 chars, typically 7 or 40)
COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{4,64}$")


def validate_commit_sha(sha: str) -> str:
    """Validate that a commit SHA is strictly hexadecimal without malicious characters."""
    clean_sha = sha.strip()
    if not COMMIT_SHA_PATTERN.match(clean_sha):
        raise ValueError(
            f"Invalid commit SHA '{sha}': must be a 4-64 character hexadecimal string"
        )
    return clean_sha


def _safe_extract_tar(tar: tarfile.TarFile, destination_path: Path) -> None:
    """Safely extract tar archive preventing path traversal and symlink exploits."""
    dest_resolved = destination_path.resolve()

    for member in tar.getmembers():
        member_path = (destination_path / member.name).resolve()
        # Verify member is strictly inside target directory
        if not str(member_path).startswith(str(dest_resolved)):
            raise RepositorySecurityError(
                f"Path traversal detected in archive member: '{member.name}'"
            )
        # Refuse to extract absolute symlinks pointing outside target directory
        if member.issym() or member.islnk():
            link_target = (destination_path / os.path.dirname(member.name) / member.linkname).resolve()
            if not str(link_target).startswith(str(dest_resolved)):
                logger.warning("Skipping unsafe symlink in archive: %s -> %s", member.name, member.linkname)
                continue

        tar.extract(member, path=str(destination_path), filter="data" if hasattr(tarfile, "data_filter") else None)


def export_commit_source(repo_dir: Path | str, commit_sha: str, target_dir: Path) -> Path:
    """Export source tree at exact commit SHA into target_dir without running any hooks."""
    repo_path = Path(repo_dir).resolve()
    target_path = Path(target_dir).resolve()
    valid_sha = validate_commit_sha(commit_sha)

    if not repo_path.exists():
        raise FileNotFoundError(f"Source repository path not found: {repo_path}")

    target_path.mkdir(parents=True, exist_ok=True)

    # 1. Primary method: git archive (bypasses all git hooks and exports tracked files only)
    archive_cmd = ["git", "archive", "--format=tar", valid_sha]
    env = os.environ.copy()
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"

    try:
        proc = subprocess.run(
            archive_cmd,
            cwd=str(repo_path),
            capture_output=True,
            check=False,
            timeout=30,
            env=env,
        )
        if proc.returncode == 0 and len(proc.stdout) > 0:
            with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:") as tar:
                _safe_extract_tar(tar, target_path)
            logger.info("Successfully exported SHA %s via git-archive to %s", valid_sha[:8], target_path)
            return target_path
    except Exception as exc:
        logger.debug("git archive failed or unsupported: %s; falling back to safe checkout", exc)

    # 2. Fallback method: safe detached clone/checkout with hooks disabled
    clone_cmd = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "clone",
        "--no-checkout",
        "--local",
        str(repo_path),
        str(target_path),
    ]
    clone_proc = subprocess.run(
        clone_cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env=env,
    )
    if clone_proc.returncode != 0:
        raise RuntimeError(
            f"Failed to clone repository at {repo_path} for SHA {valid_sha}: {clone_proc.stderr.strip()}"
        )

    checkout_cmd = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "checkout",
        valid_sha,
        "--force",
    ]
    checkout_proc = subprocess.run(
        checkout_cmd,
        cwd=str(target_path),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        env=env,
    )
    if checkout_proc.returncode != 0:
        raise RuntimeError(
            f"Failed to checkout SHA {valid_sha} in {target_path}: {checkout_proc.stderr.strip()}"
        )

    # Remove .git directory from checkout target to prevent metadata collisions
    git_dir = target_path / ".git"
    if git_dir.exists():
        shutil.rmtree(git_dir, ignore_errors=True)

    logger.info("Successfully exported SHA %s via safe detached checkout to %s", valid_sha[:8], target_path)
    return target_path


@contextlib.contextmanager
def temporary_checkout(repo_dir: Path | str, commit_sha: str) -> Iterator[Path]:
    """Context manager providing an isolated temporary checkout of a commit SHA with guaranteed cleanup."""
    temp_dir = tempfile.mkdtemp(prefix="entropy_gh_source_")
    temp_path = Path(temp_dir).resolve()
    try:
        export_commit_source(repo_dir=repo_dir, commit_sha=commit_sha, target_dir=temp_path)
        yield temp_path
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)
