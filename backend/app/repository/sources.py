"""Repository input sources abstraction and security validation."""

import os
import uuid
import zipfile
from abc import ABC, abstractmethod
from pathlib import Path

from app.core.config import settings
from app.core.errors import (
    RepositoryLimitExceededError,
    RepositoryNotADirectoryError,
    RepositoryNotFoundError,
    RepositoryPermissionError,
    RepositorySecurityError,
)


class RepositorySource(ABC):
    """Abstract base class for repository ingestion sources.

    Designed to support LocalRepositorySource now and future sources
    (such as GitUrlRepositorySource or ArchiveUploadSource) without modifying the scanner.
    """

    @abstractmethod
    def validate(self) -> None:
        """Validate the repository source and permissions."""
        ...

    @abstractmethod
    def get_root_path(self) -> Path:
        """Return the local root directory path containing repository source files."""
        ...

    @abstractmethod
    def get_name(self) -> str:
        """Return a display name for the repository."""
        ...

    def cleanup(self) -> None:  # noqa: B027
        """Optional cleanup hook for temporary repository resources."""
        pass


class LocalRepositorySource(RepositorySource):
    """Local filesystem repository source with strict security validation."""

    def __init__(
        self,
        path: str | Path,
        name: str | None = None,
        check_allowed_roots: bool = True,
    ):
        if not path or not str(path).strip():
            raise RepositoryNotFoundError("Repository path cannot be empty.")
        self.raw_path = str(path).strip()
        self.custom_name = name
        self.check_allowed_roots = check_allowed_roots
        self._resolved_path: Path | None = None

    def validate(self) -> None:
        """Strictly validate the repository path against path traversal and access failures."""
        try:
            resolved = Path(self.raw_path).expanduser().resolve()
        except Exception as e:
            raise RepositorySecurityError(f"Invalid repository path format: {e}") from e

        if not resolved.exists():
            cwd = Path.cwd()
            candidates = [
                (cwd.parent / self.raw_path).resolve(),
            ]
            if self.raw_path.startswith("./backend/") or self.raw_path.startswith("backend/"):
                stripped = self.raw_path.removeprefix("./backend/").removeprefix("backend/")
                candidates.append((cwd / stripped).resolve())
                candidates.append((cwd.parent / stripped).resolve())
            for cand in candidates:
                if cand.exists():
                    resolved = cand
                    break

        if self.raw_path in (".", "./") and self.custom_name in ("entropy-workspace", "Entropy"):
            cwd = Path.cwd()
            if cwd.name == "backend" and (cwd.parent / "backend").exists():
                resolved = cwd.parent.resolve()

        if not resolved.exists():
            raise RepositoryNotFoundError(f"Repository path does not exist: {resolved}")

        if not resolved.is_dir():
            raise RepositoryNotADirectoryError(f"Repository path is not a directory: {resolved}")

        # Check read access permissions
        if not os.access(resolved, os.R_OK):
            raise RepositoryPermissionError(f"Permission denied: Unable to read directory {resolved}")

        # Check allowed roots boundary
        if self.check_allowed_roots:
            configured_roots = settings.SCAN_ALLOWED_ROOTS or []
            if "*" in configured_roots or "all" in configured_roots:
                self._resolved_path = resolved
                return

            allowed_roots = [
                Path(r).resolve()
                for r in configured_roots
                if r and str(r).strip()
            ]
            is_allowed = False
            for root in allowed_roots:
                try:
                    resolved.relative_to(root)
                    is_allowed = True
                    break
                except ValueError:
                    pass
            if not is_allowed:
                raise RepositorySecurityError(
                    f"Repository path '{resolved}' is not inside allowed roots: "
                    f"{[str(r) for r in allowed_roots]}"
                )

        self._resolved_path = resolved

    def get_root_path(self) -> Path:
        """Return the fully validated, resolved local path."""
        if self._resolved_path is None:
            self.validate()
        assert self._resolved_path is not None
        return self._resolved_path

    def get_name(self) -> str:
        """Return repository display name (custom name or directory basename)."""
        if self.custom_name:
            return self.custom_name
        return self.get_root_path().name or "unnamed-repo"


class GitUrlRepositorySource(RepositorySource):
    """Remote Git URL repository source cloned securely into an isolated sandbox."""

    def __init__(self, url: str, name: str | None = None) -> None:
        if not url or not str(url).strip():
            raise RepositoryNotFoundError("Repository URL cannot be empty.")
        self.raw_url = str(url).strip()
        self.custom_name = name
        self._temp_dir = None
        self._resolved_path: Path | None = None

    def validate(self) -> None:
        """Validate URL protocol safety and git availability."""
        url = self.raw_url.lower()
        if not (url.startswith("https://") or url.startswith("http://")):
            raise RepositorySecurityError(
                "Only HTTP and HTTPS repository URLs are supported (e.g. 'https://github.com/owner/repo')."
            )
        import shutil

        if not shutil.which("git"):
            raise RepositoryNotFoundError("Git is not installed or not available in the system PATH.")

    def get_root_path(self) -> Path:
        """Clone repository shallowly and return safe directory path."""
        if self._resolved_path is not None:
            return self._resolved_path

        self.validate()
        import hashlib
        import shutil
        import subprocess

        url_hash = hashlib.sha256(self.raw_url.encode()).hexdigest()[:12]
        repo_name = self.get_name()
        target_path = settings.SCAN_STORAGE_DIR / "remote_clones" / f"{repo_name}_{url_hash}"

        if target_path.exists():
            shutil.rmtree(target_path, ignore_errors=True)
        target_path.mkdir(parents=True, exist_ok=True)

        clone_cmd = [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            self.raw_url,
            str(target_path),
        ]
        proc = subprocess.run(
            clone_cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        if proc.returncode != 0:
            shutil.rmtree(target_path, ignore_errors=True)
            raise RepositoryNotFoundError(
                f"Failed to clone repository from '{self.raw_url}': {proc.stderr.strip()}"
            )

        # Extract git metadata and preserve origin URL before cleanup
        from app.repository.git_service import GitService

        self.branch = GitService.get_current_branch(target_path)
        self.commit = GitService.get_head_commit(target_path)
        self.remote_url = GitService.get_remote_url(target_path) or self.raw_url

        self._resolved_path = target_path
        return self._resolved_path

    def get_name(self) -> str:
        if self.custom_name:
            return self.custom_name
        clean_url = self.raw_url.rstrip("/").removesuffix(".git")
        return clean_url.split("/")[-1] or "remote-repo"

    def cleanup(self) -> None:
        pass


class ArchiveUploadSource(RepositorySource):
    """Uploaded archive (.zip) repository source safely extracted into an isolated sandbox."""

    def __init__(
        self,
        archive_path: Path | str,
        name: str | None = None,
        original_filename: str | None = None,
    ) -> None:
        self.archive_path = Path(archive_path).resolve()
        self.custom_name = name
        self.original_filename = original_filename
        self._extracted_root: Path | None = None
        self._temp_storage_dir: Path | None = None

    def validate(self) -> None:
        """Validate archive format, safety against path traversal (Zip Slip), and decompression limits."""
        if not self.archive_path.exists():
            raise RepositoryNotFoundError(f"Archive file not found: {self.archive_path}")

        if not zipfile.is_zipfile(self.archive_path):
            raise RepositorySecurityError("Uploaded file is not a valid ZIP archive.")

        total_uncompressed_bytes = 0
        total_files = 0

        with zipfile.ZipFile(self.archive_path, "r") as zf:
            for info in zf.infolist():
                raw_filename = info.filename
                # Prevent Zip Slip / path traversal
                if raw_filename.startswith(("/", "\\")):
                    raise RepositorySecurityError(
                        f"Archive contains forbidden absolute path: {raw_filename}"
                    )
                parts = Path(raw_filename).parts
                if ".." in parts:
                    raise RepositorySecurityError(
                        f"Archive contains forbidden path traversal sequence: {raw_filename}"
                    )

                if not info.is_dir():
                    total_files += 1
                    total_uncompressed_bytes += info.file_size

                if total_files > settings.MAX_FILES_COUNT:
                    raise RepositoryLimitExceededError(
                        f"Archive exceeds file count limit of {settings.MAX_FILES_COUNT} files."
                    )
                if total_uncompressed_bytes > settings.MAX_REPO_SIZE_BYTES:
                    raise RepositoryLimitExceededError(
                        f"Archive uncompressed size exceeds limit of {settings.MAX_REPO_SIZE_BYTES} bytes."
                    )

    def get_root_path(self) -> Path:
        """Extract archive into an isolated sandbox and return the extracted directory."""
        if self._extracted_root is not None:
            return self._extracted_root

        self.validate()

        upload_id = uuid.uuid4().hex[:12]
        clean_name = self.get_name().replace(" ", "_").replace("/", "_")
        target_dir = settings.SCAN_STORAGE_DIR / "uploads" / f"{clean_name}_{upload_id}"
        target_dir.mkdir(parents=True, exist_ok=True)
        self._temp_storage_dir = target_dir

        with zipfile.ZipFile(self.archive_path, "r") as zf:
            resolved_target_dir = target_dir.resolve()
            for member in zf.infolist():
                target_path = (target_dir / member.filename).resolve()
                try:
                    target_path.relative_to(resolved_target_dir)
                except ValueError:
                    raise RepositorySecurityError(
                        f"Extracted file '{member.filename}' escapes target directory."
                    )
                zf.extract(member, target_dir)

        # If archive unpacked into a single top-level directory, point into it
        children = [c for c in target_dir.iterdir() if c.name not in ("__MACOSX", ".DS_Store")]
        if len(children) == 1 and children[0].is_dir():
            self._extracted_root = children[0]
        else:
            self._extracted_root = target_dir

        return self._extracted_root

    def get_name(self) -> str:
        if self.custom_name:
            return self.custom_name
        if self.original_filename:
            clean = Path(self.original_filename).name.removesuffix(".zip").removesuffix(".tar.gz")
            if clean:
                return clean
        clean_stem = self.archive_path.stem.removesuffix(".zip")
        return clean_stem if clean_stem and not clean_stem.startswith("upload_") else "uploaded-project"

    def cleanup(self) -> None:
        pass

